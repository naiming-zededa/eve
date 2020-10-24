// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/euank/go-kmsg-parser/kmsgparser"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/api/go/logs"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync" // XXX debug use for now
	"syscall"
	"time"
)

const (
	agentName              = "newlogd"
	errorTime              = 3 * time.Minute
	warningTime            = 40 * time.Second
	metricsPublishInterval = 300 * time.Second
	logfileDelay           = 300 // maxinum delay 5 minutes for log file collection
	stillRunningInerval    = 25 * time.Second

	collectDir   = types.NewlogCollectDir
	uploadDevDir = types.NewlogUploadDevDir
	uploadAppDir = types.NewlogUploadAppDir
	devPrefix    = types.DevPrefix
	appPrefix    = types.AppPrefix
	tmpPrefix    = "TempFile"

	maxLogFileSize   int32 = 400000 // maxinum collect file size in bytes
	maxGzipFileSize  int64 = 50000  // maxinum gzipped file size for upload in bytes
	defaultSyncCount       = 30     // default log events flush/sync to disk file

	startCleanupTime int = 14400 // 10 hours disconnect
	startRemoveTime  int = startCleanupTime / 2

	minSpaceCleanupMB uint64 = 100 // start to cleanup if space in /persist is less than 100M

	ansi = "[\u0009\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"
)

var (
	logger *logrus.Logger
	log    *base.LogObject

	savedPid             = 0
	msgIDCounter  uint64 = 1
	logmetrics    types.NewlogMetrics
	devMetaData   devMeta
	logmetaData   string
	syncToFileCnt int    // every 'N' log event count flush to log file
	spaceAvailMB  uint64 // '/persist' disk space available

	//subGlobalConfig  pubsub.Subscription

	schedResetTimer *time.Timer // after detect log has watchdog going down message, reset the file flush count

	// per app writelog stats
	appStatsMap map[string]statsLogFile

	// device source input bytes written to log file
	devSourceBytes map[string]uint64

	//domainUUID map[string]string = make(map[string]string) // App log, from domain-id to app-UUID and app-Name
	domainUUID map[string]appDomain // App log, from domain-id to app-UUID and app-Name
	// syslog/kmsg priority string definition
	priorityStr = [8]string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}
)

// for app Domain-ID mapping into UUID and DisplayName
type appDomain struct {
	appUUID string
	appName string
}

type inputEntry struct {
	severity  string
	source    string // basename of filename?
	content   string // One line
	pid       string
	filename  string // file name that generated the logmsg
	function  string // function name that generated the log msg
	timestamp string
	appUUID   string // App UUID
	acName    string // App Container Name
	acLogTime string // App Container log time
}

type statsLogFile struct {
	index     int
	file      *os.File
	size      int32
	starttime time.Time
}

type fileChanInfo struct {
	tmpfile   string
	header    string
	inputSize int32
	isApp     bool
}

type devMeta struct {
	uuid     string
	imageVer string
	curPart  string
}

var mylogfile *os.File
var mylock sync.Mutex
//var mydebugfile *os.File
//var mydebugfile2 *os.File

// newlogd program
func main() {
	restartPtr := flag.Bool("r", false, "Restart")
	flag.Parse()
	restarted := *restartPtr

	logger, log = logInit()

	if !restarted {
		if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
			log.Fatal(err)
		}
		syncToFileCnt = defaultSyncCount
	} else {
		// sync every log event in restart mode, going down in less than 5 min
		syncToFileCnt = 1
	}

	// XXX debug
	var err error
	if _, err = os.Stat("/persist/tmplog"); err != nil {
		if err := os.MkdirAll("/persist/tmplog", 0755); err != nil {
			log.Fatal(err)
		}
	}
	mylogfileName := "/persist/tmplog/my-newlog-tmp.txt"
	if _, err = os.Stat(mylogfileName); err == nil {
		timeNum := strconv.Itoa(int(time.Now().Unix()))
		os.Rename(mylogfileName, mylogfileName+"."+timeNum)
	}
	//mylogfile = startTmpfile("/persist/tmplog", mylogfileName)
	mylogfile, err = os.Create(mylogfileName)
	if err != nil {
		log.Fatal(err)
	}
	s1 := fmt.Sprintf("started newlogd...\n")
	tmplogWrite(s1, mylogfile)

	spaceAvailMB = getAvailableSpace()
	// XXX debug
	/* XXX
	mydebugfile, err = os.Create("/persist/newlog/my-newlogd-debug.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer mydebugfile.Close()
	mydebugfile2, err = os.Create("/persist/newlog/my-newlogd-debug-loginfo.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer mydebugfile2.Close()
	*/

	log.Infof("newlogd: starting... restarted %v", restarted)

	loggerChan := make(chan inputEntry, 10)
	movefileChan := make(chan fileChanInfo, 5)

	var forceUseNewlog bool
	if _, err = os.Stat(types.ForceNewlogFilename); err == nil {
		forceUseNewlog = true
	}

	s1 = fmt.Sprintf("newlogd: force newlog %v\n", forceUseNewlog)
	tmplogWrite(s1, mylogfile)
	log.Infof("newlogd: force newlog %v", forceUseNewlog)

	// XXX temp flag to force newlog infra
	if forceUseNewlog {
		// handle the write log messages to /persist/newlog/collect/ logfiles
		go writelogFile(loggerChan, movefileChan)

		// handle the kernal messages
		go getKmessages(loggerChan)

		// handle collect other container log messages
		go getMemlogMsg(loggerChan)
	}

	ps := *pubsub.New(&socketdriver.SocketDriver{Logger: logger, Log: log}, logger, log)

	stillRunning := time.NewTicker(stillRunningInerval)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Publish newlog metrics
	metricsPub, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.NewlogMetrics{},
		})
	if err != nil {
		log.Fatal(err)
	}
	metricsPub.ClearRestarted()

	// domain-name to UUID and App-name mapping
	domainUUID = make(map[string]appDomain)
	// Get DomainStatus from domainmgr
	subDomainStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "domainmgr",
		TopicImpl:     types.DomainStatus{},
		Activate:      true,
		CreateHandler: handleDomainStatusModify,
		ModifyHandler: handleDomainStatusModify,
		DeleteHandler: handleDomainStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	//subDomainStatus.Activate() XXX no need

	subOnboardStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedclient",
		CreateHandler: handleOnboardStatusModify,
		ModifyHandler: handleOnboardStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		TopicImpl:     types.OnboardingStatus{},
		Activate:      true,
		Persistent:    true,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Look for global config such as log levels
	// XXX going to change to 'zedagent' and 'persistent'
	/* XXX
	subGlobalConfig, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "",
		TopicImpl:     types.ConfigItemValueMap{},
		Activate:      true,
		CreateHandler: handleGlobalConfigModify,
		ModifyHandler: handleGlobalConfigModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		Persistent:    true,
	})
	if err != nil {
		log.Fatal(err)
	}
	*/

	subUploadMetrics, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "loguploader",
		CreateHandler: handleUploadMetricsModify,
		ModifyHandler: handleUploadMetricsModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		TopicImpl:     types.NewlogMetrics{},
		Activate:      true,
	})
	if err != nil {
		log.Fatal(err)
	}

	// newlog Metrics publish timer. Publish log metrics every 5 minutes.
	interval := time.Duration(metricsPublishInterval)
	max := float64(interval)
	min := max * 0.3
	metricsPublishTimer := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))

	schedResetTimer = time.NewTimer(1 * time.Second)
	schedResetTimer.Stop()

	for {
		select {
		case <-metricsPublishTimer.C:
			getDevTop10Inputs()
			metricsPub.Publish("global", logmetrics)
			log.Debugf("newlodg main: Published newlog metrics at %s", time.Now().String())

		case change := <-subDomainStatus.MsgChan():
			subDomainStatus.ProcessChange(change)

		case change := <-subUploadMetrics.MsgChan():
			subUploadMetrics.ProcessChange(change)

		//case change := <-subGlobalConfig.MsgChan():
		//	subGlobalConfig.ProcessChange(change)

		case change := <-subOnboardStatus.MsgChan():
			subOnboardStatus.ProcessChange(change)
			s1 := fmt.Sprintf("sub-onboard called at %v\n", time.Now())
			tmplogWrite(s1, mylogfile)

		case tmpLogfileInfo := <-movefileChan:
			doMoveCompressFile(tmpLogfileInfo)
			// XXX debug
			s1 := fmt.Sprintf("moveLogAndCompress: time %v, logfile %s\n", time.Now(), tmpLogfileInfo.tmpfile)
			tmplogWrite(s1, mylogfile)
			// do space management/clean
			mayDoSpaceCleanup(tmpLogfileInfo.isApp)

		case <-schedResetTimer.C:
			syncToFileCnt = defaultSyncCount

		case <-stillRunning.C:
			if _, err := os.Stat("/persist/tmplog/crash-newlogd"); err == nil { // XXX hack, to crash 'newlogd'
				os.Remove("/persist/tmplog/crash-newlogd")
				var bytetmp [10]byte
				i := 12
				log.Infof("newlogd crash on %s", string(bytetmp[:i]))
			}
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

// Handles upload side of Newlog metrics
func handleUploadMetricsModify(ctxArg interface{}, key string, statusArg interface{}) {
	status := statusArg.(types.NewlogMetrics)
	logmetrics.TotalBytesUpload = status.TotalBytesUpload
	logmetrics.Num4xxResponses = status.Num4xxResponses
	logmetrics.Latency.MinUploadMsec = status.Latency.MinUploadMsec
	logmetrics.Latency.MaxUploadMsec = status.Latency.MaxUploadMsec
	logmetrics.Latency.AvgUploadMsec = status.Latency.AvgUploadMsec
	logmetrics.Latency.CurrUploadMsec = status.Latency.CurrUploadMsec

	logmetrics.CurrUploadIntvSec = status.CurrUploadIntvSec

	logmetrics.ServerStats.CurrCPULoadPCT = status.ServerStats.CurrCPULoadPCT
	logmetrics.ServerStats.AvgCPULoadPCT = status.ServerStats.AvgCPULoadPCT
	logmetrics.ServerStats.CurrProcessMsec = status.ServerStats.CurrProcessMsec
	logmetrics.ServerStats.AvgProcessMsec = status.ServerStats.AvgProcessMsec

	// loguplader signal to newlogd on upload fail status
	logmetrics.FailedToSend = status.FailedToSend
	logmetrics.FailSentStartTime = status.FailSentStartTime

	logmetrics.DevMetrics.NumGZipFilesSent = status.DevMetrics.NumGZipFilesSent
	logmetrics.DevMetrics.NumGzipFileInDir = status.DevMetrics.NumGzipFileInDir
	logmetrics.DevMetrics.NumGZipFileRetry = status.DevMetrics.NumGZipFileRetry
	logmetrics.DevMetrics.RecentUploadTimestamp = status.DevMetrics.RecentUploadTimestamp
	logmetrics.DevMetrics.LastGZipFileSendTime = status.DevMetrics.LastGZipFileSendTime
	logmetrics.DevMetrics.NumGZipFileDrop = status.DevMetrics.NumGZipFileDrop

	logmetrics.AppMetrics.NumGZipFilesSent = status.AppMetrics.NumGZipFilesSent
	logmetrics.AppMetrics.NumGzipFileInDir = status.AppMetrics.NumGzipFileInDir
	logmetrics.AppMetrics.NumGZipFileRetry = status.AppMetrics.NumGZipFileRetry
	logmetrics.AppMetrics.RecentUploadTimestamp = status.AppMetrics.RecentUploadTimestamp
	logmetrics.AppMetrics.LastGZipFileSendTime = status.AppMetrics.LastGZipFileSendTime
	logmetrics.AppMetrics.NumGZipFileDrop = status.AppMetrics.NumGZipFileDrop

	log.Debugf("newlogd handleUploadMetricsModify changed to %+v", status)
}

// Handles UUID change from process client
func handleOnboardStatusModify(ctxArg interface{}, key string, statusArg interface{}) {
	status := statusArg.(types.OnboardingStatus)
	if cmp.Equal(devMetaData.uuid, status.DeviceUUID.String()) {
		log.Debugf("newlogd handleOnboardStatusModify no change to %s", devMetaData.uuid)
		return
	}
	devMetaData.uuid = status.DeviceUUID.String()
	logmetaData = formatAndGetMeta("")
	log.Infof("newlogd handleOnboardStatusModify changed to %+v", devMetaData)
}

func handleDomainStatusModify(ctxArg interface{}, key string, statusArg interface{}) {

	log.Debugf("handleDomainStatusModify: for %s", key)
	status := statusArg.(types.DomainStatus)
	// Record the domainName even if Pending* is set
	log.Debugf("handleDomainStatusModify: add %s to %s",
		status.DomainName, status.UUIDandVersion.UUID.String())
	appD := appDomain{
		appUUID: status.UUIDandVersion.UUID.String(),
		appName: status.DisplayName,
	}
	domainUUID[status.DomainName] = appD
	s1 := fmt.Sprintf("handleDomainStatusModify: add %s to %s, domainuuid %+v\n",
		status.DomainName, status.UUIDandVersion.UUID.String(), domainUUID)
	tmplogWrite(s1, mylogfile)
	log.Debugf("handleDomainStatusModify: done for %s", key)
}

func handleDomainStatusDelete(ctxArg interface{}, key string, statusArg interface{}) {

	log.Debugf("handleDomainStatusDelete: for %s", key)
	status := statusArg.(types.DomainStatus)
	if _, ok := domainUUID[status.DomainName]; !ok {
		return
	}
	log.Debugf("handleDomainStatusDelete: remove %s", status.DomainName)
	delete(domainUUID, status.DomainName)
	log.Debugf("handleDomainStatusDelete: done for %s", key)
}

/* XXX comment out for now
// Handles both create and modify events
func handleGlobalConfigModify(ctxArg interface{}, key string, statusArg interface{}) {
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s", key)
		return
	}
	debug, _ := agentlog.HandleGlobalConfig(log, subGlobalConfig, agentName, false, logger)
	log.Infof("handleGlobalConfigModify done for %s, debug set %v", key, debug)
	s1 := fmt.Sprintf("handleDomainStatusModify: newlogd debug %v\n", debug)
	tmplogWrite(s1, mylogfile)
}
*/

func logInit() (*logrus.Logger, *base.LogObject) {
	savedPid = os.Getpid()
	logger := logrus.New()
	hook := new(SourceHook)
	logger.AddHook(hook)
	formatter := logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	}
	logger.SetFormatter(&formatter)
	logger.SetReportCaller(true)
	eh := func() { agentlog.PrintStacks(log) }
	logrus.RegisterExitHandler(eh)

	log := base.NewSourceLogObject(logger, agentName, savedPid)
	return logger, log
}

// SourceHook is used to add source=agentName
type SourceHook struct {
}

// Fire adds source=agentName
func (hook *SourceHook) Fire(entry *logrus.Entry) error {
	entry.Data["source"] = agentName
	entry.Data["pid"] = savedPid
	return nil
}

// Levels installs the SourceHook for all levels
func (hook *SourceHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// getKmessages - goroutine to get from /dev/kmsg
func getKmessages(loggerChan chan inputEntry) {
	parser, err := kmsgparser.NewParser()
	if err != nil {
		log.Fatalf("unable to create kmsg parser: %v", err)
	}
	defer parser.Close()

	kmsg := parser.Parse()
	i := 0
	for msg := range kmsg {
		entry := inputEntry{
			source:    "kernel",
			severity:  "info",
			content:   msg.Message,
			timestamp: msg.Timestamp.Format(time.RFC3339Nano),
		}
		if msg.Priority >= 0 && msg.Priority < len(priorityStr) {
			entry.severity = priorityStr[msg.Priority]
		}

		// XXX debug for entry
		i++
		if i%20 == 0 {
			s1 := fmt.Sprintf("getKmessage: (%d), kmsg entry %+v\n", i, entry)
			tmplogWrite(s1, mylogfile)
		}

		logmetrics.NumKmessages++
		logmetrics.DevMetrics.NumInputEvent++
		log.Debugf("getKmessages (%d) entry msg %s", i, entry.content)

		loggerChan <- entry
	}
}

// getMemlogMsg - goroutine to get messages from memlogd queue
func getMemlogMsg(logChan chan inputEntry) {
	sockName := fmt.Sprintf("/run/%s.sock", "memlogdq")
	s, err := net.Dial("unix", sockName)
	if err != nil {
		log.Fatal("getMemlogMsg: Dial:", err)
	}
	defer s.Close()
	log.Infof("getMemlogMsg: got socket for memlogdq")

	var writeByte byte = 2
	readTimeout := 30 * time.Second

	// have to write byte value 2 to trigger memlogd queue streaming
	s.Write([]byte{writeByte})

	i := 0
	bufReader := bufio.NewReader(s)
	for {
		if err = s.SetDeadline(time.Now().Add(readTimeout)); err != nil {
			log.Fatal("getMemlogMsg: SetDeadline:", err)
		}

		bytes, err := bufReader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF && !strings.HasSuffix(err.Error(), "i/o timeout") {
				log.Fatal("getMemlogMsg: bufRead Read:", err)
			} else {
				// XXX debug
				s1 := fmt.Sprintf("getMemlogMsg: bufRead EOF or timeout, continue, read bytes %d\n", len(bytes))
				tmplogWrite(s1, mylogfile)
			}
		}
		if len(bytes) == 0 {
			s1 := fmt.Sprintf("getMemlogMsg: byte read zero. wait 5 sec\n")
			tmplogWrite(s1, mylogfile)
			time.Sleep(5 * time.Second)
			continue
		}
		i++
		sourceName, msgTime, origMsg := getSourceFromMsg(string(bytes))
		logInfo, ok := agentlog.ParseLoginfo(origMsg)
		// XXX debug, write one for every 50 memlogd msgs
		if i%50 == 0 {
			s1 := fmt.Sprintf("getMemlogMsg: (%d), time %v, loginfo %+v\n", i, time.Now(), logInfo)
			tmplogWrite(s1, mylogfile)
		}

		var pidStr string
		var isApp bool

		// XXX not sure if this is really debug or needed
		if strings.Contains(string(bytes), "guest_vm") { // XXX debug
			s1 := fmt.Sprintf("getMemlogMsg: guest_vm, source %s; origMsg %s; msg %s; loginfo %+v\n", sourceName, origMsg, string(bytes), logInfo)
			tmplogWrite(s1, mylogfile)

			logmetrics.AppMetrics.NumInputEvent++
			logInfo.Source = sourceName
			logInfo.Msg = origMsg
			isApp = true
		} else if logInfo.Containername != "" {
			logmetrics.AppMetrics.NumInputEvent++
			isApp = true
		} else { // XXX need to handle "guest_vm_err-", well above include the "err-" case
			logmetrics.DevMetrics.NumInputEvent++
		}
		if !ok {
			// not in json or right json format, try to reformat
			logInfo = repaireMsg(origMsg, msgTime, sourceName)
		}
		if logInfo.Msg == "" {
			logInfo.Msg = origMsg
		}
		if !isApp && logInfo.Source == "" {
			logInfo.Source = sourceName
		}
		if logInfo.Time == "" && strings.HasSuffix(msgTime, "Z") {
			logInfo.Time = msgTime
		}
		if logInfo.Pid != 0 {
			pidStr = strconv.Itoa(logInfo.Pid)
		}
		entry := inputEntry{
			source:    logInfo.Source,
			content:   logInfo.Msg,
			pid:       pidStr,
			timestamp: logInfo.Time,
			function:  logInfo.Function,
			filename:  logInfo.Filename,
			severity:  logInfo.Level,
			appUUID:   logInfo.Appuuid,
			acName:    logInfo.Containername,
			acLogTime: logInfo.Eventtime,
		}

		// if we are in watchdog going down. fsync often
		checkWatchdogRestart(&entry)

		/* XXX
		if entry.source == "pillar.err" {
			mydebugfile.Write(bytes)
			mydebugfile.Sync()

			if strings.Contains(logInfo.Function, "pillar/cmd/") {
				src1 := strings.Split(logInfo.Function, "pillar/cmd/")
				src2 := strings.SplitN(src1[1], ".", 2)
				entry.source = src2[0]
			}
			s2 := fmt.Sprintf("source %s, %+v\n", entry.source, logInfo)
			mydebugfile2.Write([]byte(s2))
		}
		*/

		// XXX debug for entry
		if i%50 == 0 {
			s1 := fmt.Sprintf("getMemlogMsg: (%d), memlog entry %+v\n", i, entry)
			tmplogWrite(s1, mylogfile)
		}

		logChan <- entry
	}
}

func repaireMsg(content, savedTimestamp, sourceName string) agentlog.Loginfo { // XXX bytes for debug
	// repair oversized json msg
	myStr := remNonPrintable(content)
	myStr1 := strings.Split(myStr, ",\"msg\":")
	var loginfo agentlog.Loginfo
	var ok bool
	if loginfo.Time == "" {
		loginfo.Time = savedTimestamp
	}
	if loginfo.Source == "" {
		loginfo.Source = sourceName
	}
	if len(myStr1) == 1 { // no msg:
		var nsev, nmsg string
		level := strings.SplitN(content, "level=", 2)
		if len(level) == 2 {
			level2 := strings.Split(level[1], " ")
			nsev = level2[0]
		}
		msg := strings.SplitN(content, "msg=", 2)
		if len(msg) == 2 {
			msg2 := strings.Split(msg[1], "\"")
			if len(msg2) == 3 {
				nmsg = msg2[1]
			}
		}
		if nsev != "" || nmsg != "" {
			loginfo.Level = nsev
			loginfo.Msg = nmsg
			ok = true
		}
	} else {
		msgStr := myStr1[0]
		if string(msgStr[len(msgStr)-1]) != "}" {
			msgStr += "}"
		}
		loginfo, ok = agentlog.ParseLoginfo(msgStr)
		if ok {
			loginfo.Msg = myStr1[1]
		}
	}
	if !ok {
		loginfo.Level = "info"
		loginfo.Msg = content
	}
	return loginfo
}

func tmplogWrite(msg string, mylogfile *os.File) {
	//mylock.Lock()
	mylogfile.WriteString(msg)
	mylogfile.Sync()
	//mylock.Unlock()
}

func getSourceFromMsg(msg string) (string, string, string) {
	var source, content string
	lines := strings.SplitN(msg, ";", 2)
	if len(lines) != 2 {
		return source, "", content
	}
	content = lines[1]
	lines2 := strings.Split(lines[0], ",")
	n := len(lines2)
	if n < 2 {
		return source, "", content
	}
	return lines2[n-1], lines2[n-2], content
}

func startTmpfile(dirname, filename string) *os.File {
	tmpFile, err := ioutil.TempFile(dirname, filename)
	if err != nil {
		log.Fatal(err)
	}
	tmpFile.Chmod(0600)
	return tmpFile
}

func remNonPrintable(str string) string {
	var re = regexp.MustCompile(ansi)
	myStr := re.ReplaceAllString(str, "")
	myStr = strings.Trim(myStr, "\r")
	return strings.Trim(myStr, "\n")
}

// writelogFile - a goroutine to format and write log entries into dev/app logfiles
func writelogFile(logChan <-chan inputEntry, moveChan chan fileChanInfo) {

	if _, err := os.Stat(collectDir); os.IsNotExist(err) {
		if err := os.MkdirAll(collectDir, 0755); err != nil {
			log.Fatal(err)
		}
	}

	// move and gzip the existing logfiles first
	logmetaData = findMovePrevLogFiles(moveChan)

	// new logfile
	devlogFile := startTmpfile(collectDir, devPrefix)
	defer devlogFile.Close()

	var fileinfo fileChanInfo
	var devStats statsLogFile

	devSourceBytes = make(map[string]uint64)
	appStatsMap = make(map[string]statsLogFile)
	checklogTimer := time.NewTimer(logfileDelay * time.Second)
	devStats.file = devlogFile

	// write the log metadata to the first line of the logfile, will be extracted when doing gzip conversion
	_, err := devStats.file.WriteString(logmetaData + "\n")
	if err != nil {
		log.Fatal(err)
	}

	timeIdx := 0
	for {
		select {
		case <-checklogTimer.C:
			timeIdx++
			checkLogTimeExpire(fileinfo, &devStats, moveChan)
			checklogTimer = time.NewTimer(15 * time.Second) // check the file time limit every 15 seconds
			if timeIdx%6 == 0 {                                       // every half an hour
				spaceAvailMB = getAvailableSpace()
				s1 := fmt.Sprintf("stats dir %s, bavail %d MBytes\n", types.PersistDir, spaceAvailMB)
				tmplogWrite(s1, mylogfile)
			}

		case entry := <-logChan:
			appuuid := checkAppEntry(&entry)
			timeS := getPtypeTimestamp(entry.timestamp)
			mapLog := logs.LogEntry{
				Severity:  entry.severity,
				Source:    entry.source,
				Content:   entry.content,
				Iid:       entry.pid,
				Filename:  entry.filename,
				Msgid:     msgIDCounter,
				Function:  entry.function,
				Timestamp: &timeS,
			}
			mapJentry, _ := json.Marshal(mapLog)
			logline := string(mapJentry) + "\n"
			msgIDCounter++
			if appuuid != "" {
				appM := getAppStatsMap(appuuid)
				len := writelogEntry(&appM, logline)

				logmetrics.AppMetrics.NumBytesWrite += uint64(len)
				appStatsMap[appuuid] = appM

				trigMoveToGzip(fileinfo, &appM, appuuid, moveChan, false)

			} else {
				len := writelogEntry(&devStats, logline)
				updateDevInputlogStats(entry.source, uint64(len))

				trigMoveToGzip(fileinfo, &devStats, "", moveChan, false)
			}
		}
	}
}

func checkAppEntry(entry *inputEntry) string {
	appuuid := ""
	var appVMlog bool
	var appSplitArr []string
	if entry.appUUID != "" {
		appuuid = entry.appUUID
		entry.content = "{\"container\":\"" + entry.acName + "\",\"time\":\"" + entry.acLogTime + "\",\"msg\":\"" + entry.content + "\"}"
	} else if strings.HasPrefix(entry.source, "guest_vm-") {
		appSplitArr = strings.SplitN(entry.source, "guest_vm-", 2)
		appVMlog = true
	} else if strings.HasPrefix(entry.source, "guest_vm_err-") {
		appSplitArr = strings.SplitN(entry.source, "guest_vm_err-", 2)
		appVMlog = true
	}
	if appVMlog {
		if len(appSplitArr) == 2 {
			if appSplitArr[0] == "" && appSplitArr[1] != "" {
				entry.source = appSplitArr[1]
				if du, ok := domainUUID[entry.source]; ok {
					appuuid = du.appUUID
				} else {
					s1 := fmt.Sprintf("checkAppEntry: app domain name lookup failed\n")
					tmplogWrite(s1, mylogfile)
				}
				s1 := fmt.Sprintf("checkAppEntry: app domain name %s, appuuid %s\n", entry.source, appuuid)
				tmplogWrite(s1, mylogfile)
			} else {
				s1 := fmt.Sprintf("checkAppEntry: app domain name can't find\n")
				tmplogWrite(s1, mylogfile)
			}
		} else {
			s1 := fmt.Sprintf("checkAppEntry: app domain name slpitArr not 2\n")
			tmplogWrite(s1, mylogfile)
		}
	}
	return appuuid
}

func getAppStatsMap(appuuid string) statsLogFile {
	if _, ok := appStatsMap[appuuid]; !ok {
		applogname := appPrefix + appuuid + ".log"
		applogfile := startTmpfile(collectDir, applogname)

		appM := statsLogFile{
			file:      applogfile,
			starttime: time.Now(),
		}
		appStatsMap[appuuid] = appM
		s1 := fmt.Sprintf("getAppStatsMap: appStatsMap created for uuid %s, filename %s\n", appuuid, applogfile)
		tmplogWrite(s1, mylogfile)

		// write the metadata to the first line of app logfile, for App, just the appName info
		_, err := appM.file.WriteString(formatAndGetMeta(appuuid) + "\n")
		if err != nil {
			log.Fatal("getAppStatsMap: write appName ", err)
		}
	}
	return appStatsMap[appuuid]
}

// update device log source map for metrics64
func updateDevInputlogStats(source string, size uint64) {
	b, ok := devSourceBytes[source]
	if !ok {
		b = 0
	}
	b += size
	devSourceBytes[source] = b

	logmetrics.DevMetrics.NumBytesWrite += size
}

// write log entry, update size and index, sync file if needed
func writelogEntry(stats *statsLogFile, logline string) int {
	len, err := stats.file.WriteString(logline)
	if err != nil {
		s1 := fmt.Sprintf("writelogEntry: fatal, write failed on %s, err %v\n", stats.file.Name(), err)
		tmplogWrite(s1, mylogfile)
		log.Fatal("writelogEntry: write logline ", err)
	}
	stats.size += int32(len)

	if stats.index%syncToFileCnt == 0 {
		stats.file.Sync()
	}
	stats.index++
	return len
}

func mayDoSpaceCleanup(isApp bool) {
	// check the space first

	var initialCleanTime int64
	outOfSpace := spaceAvailMB < minSpaceCleanupMB
	// check the cleanup if we fail to send to cloud or disk space is low
	if !logmetrics.FailedToSend && !outOfSpace {
		return
	}
	nowSec := int(time.Since(logmetrics.FailSentStartTime).Seconds())
	s1 := fmt.Sprintf("mayDoSpaceCleanup: failed to send sec %d\n", nowSec)
	tmplogWrite(s1, mylogfile)
	if nowSec > startCleanupTime || outOfSpace {
		s1 = fmt.Sprintf("mayDoSpaceCleanup: over the cleanup time\n")
		tmplogWrite(s1, mylogfile)
		//initialCleanTime := failSentTime.Add(keepInitTime * time.Second).Unix()
		fileTime := 0
		var gzipDir, gotFileName string
		if isApp {
			gzipDir = uploadAppDir
		} else {
			gzipDir = uploadDevDir
		}
		files, err := ioutil.ReadDir(gzipDir)
		if err != nil {
			log.Fatal("mayDoSpaceCleanup: read dir error", err)
		}

		// recycle the gzip files
		// (1) If it's fail to connect to cloud, find the file to remove is: FailSentStartTime + startRemoveTime
		//     in other words 5 hours after the disconnect to server, middle of keep 10 hours of gzip data
		// (2) If it's /persist out of space case, find the middle of the earliest file to now
		if outOfSpace {
			oldestFileSec := nowSec
			for _, f := range files {
				if f.IsDir() {
					continue
				}
				isgzip, fTime := getTimeNumber(isApp, f.Name())
				if !isgzip {
					continue
				}
				if fTime < oldestFileSec {
					oldestFileSec = fTime
				}
			}
			if oldestFileSec == nowSec { // not found
				return
			}
			initialCleanTime = int64((nowSec - oldestFileSec) / 2)
		} else {
			initialCleanTime = logmetrics.FailSentStartTime.Add(time.Duration(startRemoveTime) * time.Second).Unix()
		}

		// find the gzip first gzip file which is after 5 hours of failure and remove it
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			isgzip, fTime := getTimeNumber(isApp, f.Name())
			if !isgzip {
				continue
			}
			if fTime > int(initialCleanTime) {
				if fileTime == 0 || fileTime > fTime {
					fileTime = fTime
					gotFileName = f.Name()
				}
			}
		}

		if fileTime > 0 && gotFileName != "" {
			theFile := gzipDir + "/" + gotFileName
			s1 = fmt.Sprintf("mayDoSpaceCleanup: find and remove the file %s\n", theFile)
			tmplogWrite(s1, mylogfile)
			err := os.Remove(theFile)
			if err != nil {
				log.Fatal("mayDoSpaceCleanup: remove file error", err)
			}
		}
	}
}

func doMoveCompressFile(tmplogfileInfo fileChanInfo) {
	s1 := fmt.Sprintf("doMoveCompressFile: %+v\n", tmplogfileInfo)
	tmplogWrite(s1, mylogfile)
	var isApp bool
	var dirName, appuuid string
	if tmplogfileInfo.isApp {
		isApp = true
		dirName = uploadAppDir
		appuuid = getAppuuidFromLogfile(tmplogfileInfo)
	} else {
		if _, err := os.Stat(uploadDevDir); os.IsNotExist(err) {
			if err := os.Mkdir(uploadDevDir, 0755); err != nil {
				log.Fatal(err)
			}
		}
		dirName = uploadDevDir
	}

	now := time.Now()
	timenowNum := int(now.Unix()) // in secends
	outfile := gzipFileNameGet(isApp, timenowNum, dirName, appuuid)

	// read input file
	ifile, err := os.Open(tmplogfileInfo.tmpfile)
	if err != nil {
		log.Fatal(err)
	}
	reader := bufio.NewReader(ifile)
	content, _ := ioutil.ReadAll(reader)

	c2 := bytes.SplitN(content, []byte("\n"), 2)
	if len(c2) != 2 { // most likely the file is created before any write on it
		err = fmt.Errorf("doMoveCompressFile: can't get metadata on first line, remove %s", tmplogfileInfo.tmpfile)
		log.Error(err)
		ifile.Close()
		err = os.Remove(tmplogfileInfo.tmpfile)
		if err != nil {
			log.Fatal("doMoveCompressFile: remove file failed", err)
		}
		return
	}

	// assign the metadata in the first line of the logfile
	tmplogfileInfo.header = string(c2[0])
	content = c2[1]
	newSize := gzipToOutFile(content, outfile, tmplogfileInfo, now)
	ifile.Close()

	// if the newSize exceeding the limit, split it and redo the gzip on them
	if newSize > maxGzipFileSize && newSize/2 < maxGzipFileSize { // XXX temp size
		// remove this new oversied gzip file
		os.Remove(outfile)

		content1, content2 := breakGzipfiles(content)
		newSize1 := gzipToOutFile(content1, outfile, tmplogfileInfo, now)
		outfile2 := gzipFileNameGet(isApp, timenowNum+1, dirName, appuuid) // add one second for filename
		newSize2 := gzipToOutFile(content2, outfile2, tmplogfileInfo, now.Add(1*time.Second))
		s1 = fmt.Sprintf("doMoveCompressFile: break size %d into tow gzip files with sizes %d/%d, input-size %d\n",
			newSize, newSize1, newSize2, tmplogfileInfo.inputSize)
		tmplogWrite(s1, mylogfile)
		logmetrics.NumBreakGZipFile++
		newSize = newSize1 + newSize2
	}

	if isApp {
		logmetrics.AppMetrics.NumGZipBytesWrite += uint64(newSize)
	} else {
		logmetrics.DevMetrics.NumGZipBytesWrite += uint64(newSize)
	}

	// get rid of the temp log file
	s1 = fmt.Sprintf("doMoveCompressFile: done. metaD %s, remove orig log file %s, to gzip file %s\n", string(c2[0]), tmplogfileInfo.tmpfile, outfile)
	tmplogWrite(s1, mylogfile)
	err = os.Remove(tmplogfileInfo.tmpfile)
	if err != nil {
		log.Fatal("doMoveCompressFile: remove file failed", err)
	}
}

func gzipToOutFile(content []byte, fName string, fHdr fileChanInfo, now time.Time) int64 {
	// open output file
	files := strings.Split(fName, "/")
	gzipfileName := files[len(files)-1]
	gzipDirName := strings.TrimSuffix(fName, "/"+gzipfileName)
	oTmpFile, err := ioutil.TempFile(gzipDirName, tmpPrefix)
	if err != nil {
		log.Fatal("gzipToOutFile: create tmp file failed ", err)
	}

	gw, _ := gzip.NewWriterLevel(oTmpFile, gzip.BestCompression)

	// for app upload, use gzip header 'Name' for appName string to simplify cloud side implementation
	// for now, the gw.Comment has the metadata for device log, and gw.Name for appName for app log
	if fHdr.isApp {
		gw.Name = fHdr.header
	} else {
		gw.Comment = fHdr.header
	}
	gw.ModTime = now

	gw.Write(content)
	gw.Close()

	tmpFileName := oTmpFile.Name()
	oTmpFile.Sync()
	oTmpFile.Close()
	f2, err := os.Stat(tmpFileName)
	if err != nil {
		log.Fatal("gzipToOutFile: ofile stat error", err)
	}
	newSize := f2.Size()
	err = os.Rename(tmpFileName, fName)
	if err != nil {
		log.Fatal("gzipToOutFile: os.Rename error: ", err)
	}
	return newSize
}

func breakGzipfiles(content []byte) ([]byte, []byte) {
	var c1, c2 []byte
	fsize := len(content)
	hsize := fsize / 2
	i := 0
	for {
		size := hsize + i
		i++
		if size > fsize {
			err := fmt.Errorf("can't break the log file")
			log.Fatal(err)
		}
		if content[size] == '\n' {
			size++
			c1 = content[0:size]
			c2 = content[size:fsize]
			break
		}
	}
	return c1, c2
}

func gzipFileNameGet(isApp bool, timeNum int, dirName, appUUID string) string {
	var outfileName string
	if isApp {
		outfileName = appPrefix + appUUID + types.AppSuffix + strconv.Itoa(timeNum) + ".gz"
	} else {
		outfileName = devPrefix + strconv.Itoa(timeNum) + ".gz"
	}
	return dirName + "/" + outfileName
}

func getTimeNumber(isApp bool, fName string) (bool, int) {
	if isApp {
		if strings.HasPrefix(fName, appPrefix) && strings.HasSuffix(fName, ".gz") {
			fStr1 := strings.TrimPrefix(fName, appPrefix)
			fStr := strings.Split(fStr1, types.AppSuffix)
			if len(fStr) != 2 {
				err := fmt.Errorf("app split is not 2")
				log.Fatal(err)
			}
			fStr2 := strings.TrimSuffix(fStr[1], ".gz")
			fTime, err := strconv.Atoi(fStr2)
			if err != nil {
				log.Fatal(err)
			}
			return true, fTime
		}
	} else {
		if strings.HasPrefix(fName, devPrefix) && strings.HasSuffix(fName, ".gz") {
			fStr1 := strings.TrimPrefix(fName, devPrefix)
			fStr2 := strings.TrimSuffix(fStr1, ".gz")
			fTime, err := strconv.Atoi(fStr2)
			if err != nil {
				log.Fatal(err)
			}
			return true, fTime
		}
	}
	return false, 0
}

func getAppuuidFromLogfile(tmplogfileInfo fileChanInfo) string {
	if _, err := os.Stat(uploadAppDir); os.IsNotExist(err) {
		if err := os.Mkdir(uploadAppDir, 0755); err != nil {
			log.Fatal(err)
		}
		s1 := fmt.Sprintf("getAppuuidFromLogfile: created Apps dir\n")
		tmplogWrite(s1, mylogfile)
	}
	prefix := collectDir + "/" + appPrefix
	tmpStr1 := strings.TrimPrefix(tmplogfileInfo.tmpfile, prefix)
	tmpStr2 := strings.SplitN(tmpStr1, ".log", 2)
	return tmpStr2[0]
}

func findMovePrevLogFiles(movefile chan fileChanInfo) string {
	files, err := ioutil.ReadDir(collectDir)
	if err != nil {
		log.Fatal("findMovePrevLogFiles: read dir ", err)
	}

	// get EVE version and partition, UUID may not be avilable yet
	getEveInfo()

	// remove any gzip file the name starts them 'Tempfile', it crashed before finished rename in dev/app dir
	cleanGzipTempfiles(uploadDevDir)
	cleanGzipTempfiles(uploadAppDir)

	// on prev life's dev-log and app-log
	for _, f := range files {
		isDev := strings.HasPrefix(f.Name(), devPrefix)
		isApp := strings.HasPrefix(f.Name(), appPrefix)
		if !f.IsDir() && (isDev && len(f.Name()) > len(devPrefix) || isApp && len(f.Name()) > len(appPrefix)) {
			var fileinfo fileChanInfo
			s1 := fmt.Sprintf("findMovePrevLogFiles: find prev logfile %s\n", f.Name())
			tmplogWrite(s1, mylogfile)
			prevLogFile := collectDir + "/" + f.Name()
			fileinfo.tmpfile = prevLogFile
			fileinfo.isApp = isApp
			fileinfo.inputSize = int32(f.Size())

			movefile <- fileinfo
		}
	}

	return formatAndGetMeta("")
}

func trigMoveToGzip(fileinfo fileChanInfo, stats *statsLogFile, appUUID string, moveChan chan fileChanInfo, timerTrig bool) {
	// check filesize over limit if not triggered by timeout
	if !timerTrig && stats.size < maxLogFileSize {
		return
	}

	if err := stats.file.Close(); err != nil {
		log.Fatal(err)
	}

	isApp := appUUID != ""
	fileinfo.isApp = isApp
	fileinfo.inputSize = stats.size
	fileinfo.tmpfile = stats.file.Name()

	// XXX debug
	s1 := fmt.Sprintf("trigMoveToGzip: (%d), time %v, app-%v logfile meta %v, trig done\n", stats.index, time.Now(), isApp, fileinfo.header)
	tmplogWrite(s1, mylogfile)

	moveChan <- fileinfo

	if isApp { // appM stats and logfile is created when needed
		delete(appStatsMap, appUUID)
		return
	}

	// reset stats data and create new logfile for device
	stats.size = 0
	stats.file = startTmpfile(collectDir, devPrefix)
	stats.starttime = time.Now()

	_, err := stats.file.WriteString(logmetaData + "\n") // write the metadata in the first line of logfile
	if err != nil {
		log.Fatal("trigMoveToGzip: write metadata line ", err)
	}
	s1 = fmt.Sprintf("trigMoveToGzip: new devfile %s\n", stats.file.Name())
	tmplogWrite(s1, mylogfile)
	return
}

func checkLogTimeExpire(fileinfo fileChanInfo, devStats *statsLogFile, moveChan chan fileChanInfo) {
	// check device log file
	if devStats.file != nil && int(time.Since(devStats.starttime).Seconds()) > logfileDelay {
		trigMoveToGzip(fileinfo, devStats, "", moveChan, true)
		s1 := fmt.Sprintf("checkLogTimeExpire: time now %v, trig Move to Gzip for Main file %s\n", time.Now(), devStats.file.Name())
		tmplogWrite(s1, mylogfile)
	}

	// check app log files
	for appuuid, appM := range appStatsMap {
		if appM.file != nil && int(time.Since(appM.starttime).Seconds()) > logfileDelay {
			trigMoveToGzip(fileinfo, &appM, appuuid, moveChan, true)
			s1 := fmt.Sprintf("checkLogTimeExpire: trig Move to Gzip for App file %s, appuuid %s\n", appM.file.Name(), appuuid)
			tmplogWrite(s1, mylogfile)
		}
	}
}

// for dev, returns the meta data, and for app, return the appName
func formatAndGetMeta(appuuid string) string {
	var appName string
	if appuuid != "" {
		for _, appD := range domainUUID { // cycle through the domainUUID map and find the UUID and appName
			if appD.appUUID == appuuid {
				appName = appD.appName
				return appName
			}
		}
	}
	metaStr := logs.LogBundle{
		DevID:      devMetaData.uuid,
		Image:      devMetaData.curPart,
		EveVersion: devMetaData.imageVer,
	}
	mapJmeta, _ := json.Marshal(metaStr)
	return string(mapJmeta)
}

func getEveInfo() {
	for {
		devMetaData.curPart = agentlog.EveCurrentPartition()
		if devMetaData.curPart == "Unknown" {
			log.Errorln("currPart unknown")
			time.Sleep(time.Second)
			continue
		} else {
			break
		}
	}
	for {
		devMetaData.imageVer = agentlog.EveVersion()
		if devMetaData.imageVer == "Unknown" {
			log.Errorln("imageVer unknown")
			time.Sleep(time.Second)
			continue
		} else {
			break
		}
	}
}

func cleanGzipTempfiles(dir string) {
	gfiles, err := ioutil.ReadDir(dir)
	s1 := fmt.Sprintf("cleanGzipTempfiles: len %d, err %v\n", len(gfiles), err)
	tmplogWrite(s1, mylogfile)
	if err == nil {
		for _, f := range gfiles {
			if !f.IsDir() && strings.HasPrefix(f.Name(), tmpPrefix) && len(f.Name()) > len(tmpPrefix) {
				err = os.Remove(dir + "/" + f.Name())
				s1 := fmt.Sprintf("cleanGzipTempfiles: found and remove %s, err %v\n", f.Name(), err)
				tmplogWrite(s1, mylogfile)
			}
		}
	}
}

// flush more often when we are going down by reading from watchdog log message itself
func checkWatchdogRestart(entry *inputEntry) {
	// source can be watchdog or watchdog.err
	if strings.HasPrefix(entry.source, "watchdog") {
		if strings.Contains(entry.content, "Retry timed-out at") {
			entry.severity = "emerg"
			syncToFileCnt = 1

			// in case if the system does not go down, fire a timer to reset it to normal sync count
			schedResetTimer = time.NewTimer(300 * time.Second)
		}
	}
}

func rankByInputCount(Frequencies map[string]uint64) PairList {
	pl := make(PairList, len(Frequencies))
	i := 0
	for k, v := range Frequencies {
		pl[i] = Pair{k, v}
		i++
	}
	sort.Sort(sort.Reverse(pl))
	return pl
}

type Pair struct {
	Key   string
	Value uint64
}

type PairList []Pair

func (p PairList) Len() int           { return len(p) }
func (p PairList) Less(i, j int) bool { return p[i].Value < p[j].Value }
func (p PairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

func getDevTop10Inputs() {
	if logmetrics.DevMetrics.NumBytesWrite == 0 {
		return
	}

	top10 := make(map[string]uint32)
	pl := rankByInputCount(devSourceBytes)
	for i, p := range pl {
		if i >= 10 {
			break
		}
		top10[p.Key] = uint32(p.Value * 100 / logmetrics.DevMetrics.NumBytesWrite)
	}
	s1 := fmt.Sprintf("getDevSourceInput: len %d, top 10 %+v, all src-bytes %+v\n", len(top10), top10, pl)
	tmplogWrite(s1, mylogfile)
	logmetrics.DevTop10InputBytesPCT = top10
}

func getPtypeTimestamp(timeStr string) timestamp.Timestamp {
	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		log.Fatal(err)
	}
	tt := timestamp.Timestamp{Seconds: t.Unix(), Nanos: int32(t.Nanosecond())}
	return tt
}

func getAvailableSpace() uint64 {
	var stat syscall.Statfs_t
	syscall.Statfs(types.PersistDir, &stat)
	return stat.Bavail * uint64(stat.Bsize) / uint64(1000000)
}