// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package loguploader

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/api/go/logs"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	"github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	agentName = "loguploader"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second

	failSendDir = types.NewlogDir + "/failedUpload"

	defaultUploadIntv      = 90
	metricsPublishInterval = 300 * time.Second
	cloudMetricInterval    = 10 * time.Second
	stillRunningInerval    = 25 * time.Second
	max4xxdropFiles        = 1000 // leave maximum of 1000 gzip failed to upload files on device, 50M max disk space
	max4xxRetries          = 10   // move on if the same gzip file failed for 4xx
)

var (
	devUUID             uuid.UUID
	deviceNetworkStatus = &types.DeviceNetworkStatus{}
	debug               bool
	debugOverride       bool
	logger              *logrus.Logger
	log                 *base.LogObject
	newlogsDevURL       string
	contSentSuccess     int64
	contSentFailure     int64
	dev4xxfile          resp4xxlogfile
	app4xxfile          resp4xxlogfile
)

type resp4xxlogfile struct {
	logfileName string
	failureCnt  int
}

type loguploaderContext struct {
	globalConfig           *types.ConfigItemValueMap
	zedcloudCtx            *zedcloud.ZedCloudContext
	subDeviceNetworkStatus pubsub.Subscription
	subGlobalConfig        pubsub.Subscription
	usableAddrCount        int
	GCInitialized          bool
	metrics                types.NewlogMetrics
	serverNameAndPort      string
	metricsPub             pubsub.Publication
}

// Run - an loguploader run
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject) int {
	logger = loggerArg
	log = logArg
	debugPtr := flag.Bool("d", false, "Debug flag")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	agentlog.Init(agentName)

	if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
		log.Fatal(err)
	}

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(stillRunningInerval)
	ps.StillRunning(agentName, warningTime, errorTime)

	loguploaderCtx := loguploaderContext{
		globalConfig: types.DefaultConfigItemValueMap(),
	}

	subDeviceNetworkStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "nim",
		TopicImpl:     types.DeviceNetworkStatus{},
		Activate:      false,
		Ctx:           &loguploaderCtx,
		CreateHandler: handleDNSModify,
		ModifyHandler: handleDNSModify,
		DeleteHandler: handleDNSDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	loguploaderCtx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "",
		TopicImpl:     types.ConfigItemValueMap{},
		Activate:      false,
		Ctx:           &loguploaderCtx,
		CreateHandler: handleGlobalConfigModify,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	loguploaderCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	sendCtxInit(&loguploaderCtx)

	for loguploaderCtx.usableAddrCount == 0 {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		// This wait can take an unbounded time since we wait for IP
		// addresses. Punch StillRunning
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Infof("Have %d management ports with usable addresses", loguploaderCtx.usableAddrCount)

	// Publish cloud metrics
	cms := zedcloud.GetCloudMetrics(log) // Need type of data
	pubCloud, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: cms,
		})
	if err != nil {
		log.Fatal(err)
	}

	interval := time.Duration(cloudMetricInterval) // every 10 sec
	max := float64(interval)
	min := max * 0.3
	publishCloudTimer := flextimer.NewRangeTicker(time.Duration(min), time.Duration(max))

	// Publish newlog metrics
	metricsPub, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.NewlogMetrics{},
		})
	if err != nil {
		log.Fatal(err)
	}
	loguploaderCtx.metricsPub = metricsPub

	// assume we can not send to cloud first, fail-to-send status to 'newlogd'
	loguploaderCtx.metrics.FailedToSend = true
	loguploaderCtx.metrics.FailSentStartTime = time.Now()

	// newlog Metrics publish timer. Publish log metrics every 5 minutes.
	interval = time.Duration(metricsPublishInterval)
	max = float64(interval)
	min = max * 0.3
	metricsPublishTimer := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))

	// a go routine to fetch gzip log file and upload to cloud
	//go fetchAndSendlogs(loguploaderCtx)

	var numLeftFiles, iteration, prevIntv int
	scheduletimer := time.NewTimer(1800 * time.Second)

	// init the upload interface to 2 min
	loguploaderCtx.metrics.CurrUploadIntvSec = defaultUploadIntv
	uploadTimer := time.NewTimer(time.Duration(loguploaderCtx.metrics.CurrUploadIntvSec) * time.Second)

	for {
		select {
		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case <-publishCloudTimer.C:
			start := time.Now()
			log.Debugf("publishCloudTimer cloud metrics at at %s", time.Now().String())
			err := pubCloud.Publish("global", zedcloud.GetCloudMetrics(log))
			if err != nil {
				log.Errorln(err)
			}
			ps.CheckMaxTimeTopic(agentName, "publishCloudTimer", start, warningTime, errorTime)

		case <-metricsPublishTimer.C:
			metricsPub.Publish("global", loguploaderCtx.metrics)
			log.Debugf("Published newlog upload metrics at %s", time.Now().String())

		case <-scheduletimer.C:

			// upload interval stays for 30 min once it calculates
			// - if the device is disconnected from cloud for over 20 min, then when use random
			//   interval between 3-15 min to retry, avoid overwhelming the cloud server once it is up
			// - in normal uploading case, set interval depends on the number of gzip files left in
			//   both dev/app directories, from 15 seconds upto to 2 minutes
			//
			// at device starts, more logging activities, and slower timer. will see longer delays,
			// as the device moves on, the log upload should catchup quickly
			var interval int
			if loguploaderCtx.metrics.FailedToSend &&
				time.Since(loguploaderCtx.metrics.FailSentStartTime).Nanoseconds()/int64(time.Second) > 1200 {
				loguploaderCtx.metrics.CurrUploadIntvSec = uint32(rand.Intn(720) + 180)
			} else {
				if numLeftFiles < 5 {
					interval = defaultUploadIntv
				} else if numLeftFiles >= 5 && numLeftFiles < 25 {
					interval = 45
				} else if numLeftFiles >= 25 && numLeftFiles < 50 {
					interval = 30
				} else if numLeftFiles >= 50 && numLeftFiles < 200 {
					interval = 15
				} else {
					interval = 8
				}

				// if there is more than 4 files left, and new interval calculated is longer than previous
				// interval, keep the previous one instead
				if numLeftFiles >= 5 && prevIntv != 0 && prevIntv < interval {
					interval = prevIntv
				}
				prevIntv = interval
				// give 20% of randomness
				intvBase := (interval * 80) / 100
				intvRan := (interval - intvBase) * 2
				if intvRan > 0 {
					loguploaderCtx.metrics.CurrUploadIntvSec = uint32(rand.Intn(intvRan) + intvBase)
				}
			}
			scheduletimer = time.NewTimer(1800 * time.Second)

		case <-uploadTimer.C:
			// Main upload
			origIter := iteration
			numDevFile := doFetchSend(&loguploaderCtx, types.NewlogUploadDevDir, &iteration)
			loguploaderCtx.metrics.DevMetrics.NumGzipFileInDir = uint32(numDevFile)

			// App upload
			numAppFile := doFetchSend(&loguploaderCtx, types.NewlogUploadAppDir, &iteration)
			loguploaderCtx.metrics.AppMetrics.NumGzipFileInDir = uint32(numAppFile)

			numLeftFiles = numDevFile + numAppFile
			uploadTimer = time.NewTimer(time.Duration(loguploaderCtx.metrics.CurrUploadIntvSec) * time.Second)
			log.Debugf("loguploader Run: time %v, timer fired, Dev/App files left in directories %d/%d",
				time.Now(), numDevFile, numAppFile)
			if iteration > origIter {
				metricsPub.Publish("global", loguploaderCtx.metrics)
			}

		case <-stillRunning.C:
			if _, err := os.Stat("/persist/tmplog/crash-loguploader"); err == nil { // XXX hack, to crash 'newlogd'
				os.Remove("/persist/tmplog/crash-loguploader")
				var bytetmp [10]byte
				i := 12
				log.Infof("uploader crash on %s", string(bytetmp[:i]))
			}
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

func sendCtxInit(ctx *loguploaderContext) {
	//get server name
	bytes, err := ioutil.ReadFile(types.ServerFileName)
	if err != nil {
		log.Fatalf("sendCtxInit: Failed to read ServerFileName(%s). Err: %s",
			types.ServerFileName, err)
	}
	// Preserve port
	ctx.serverNameAndPort = strings.TrimSpace(string(bytes))
	serverName := strings.Split(ctx.serverNameAndPort, ":")[0]

	//set newlog url
	zedcloudCtx := zedcloud.NewContext(log, zedcloud.ContextOptions{
		DevNetworkStatus: deviceNetworkStatus,
		Timeout:          ctx.globalConfig.GlobalValueInt(types.NetworkSendTimeout),
		NeedStatsFunc:    true,
		Serial:           hardware.GetProductSerial(log),
		SoftSerial:       hardware.GetSoftSerial(log),
		AgentName:        agentName,
	})

	ctx.zedcloudCtx = &zedcloudCtx
	log.Infof("sendCtxInit: Get Device Serial %s, Soft Serial %s", zedcloudCtx.DevSerial,
		zedcloudCtx.DevSoftSerial)

	// XXX need to redo this since the root certificates can change when DeviceNetworkStatus changes
	err = zedcloud.UpdateTLSConfig(&zedcloudCtx, serverName, nil)
	if err != nil {
		log.Fatal(err)
	}

	// In case we run early, wait for UUID file to appear
	for {
		b, err := ioutil.ReadFile(types.UUIDFileName)
		if err != nil {
			log.Errorln("ReadFile", err, types.UUIDFileName)
			time.Sleep(time.Second)
			continue
		}
		uuidStr := strings.TrimSpace(string(b))
		devUUID, err = uuid.FromString(uuidStr)
		if err != nil {
			log.Errorln("uuid.FromString", err, string(b))
			time.Sleep(time.Second)
			continue
		}
		zedcloudCtx.DevUUID = devUUID
		break
	}
	// wait for uuid of logs V2 URL string
	newlogsDevURL = zedcloud.URLPathString(ctx.serverNameAndPort, zedcloudCtx.V2API, devUUID, "newlogs")
	log.Infof("sendCtxInit: Read UUID %s", devUUID)
}

func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {
	status := statusArg.(types.DeviceNetworkStatus)
	ctx := ctxArg.(*loguploaderContext)
	if key != "global" {
		log.Debugf("handleDNSModify: ignoring %s", key)
		return
	}
	log.Debugf("handleDNSModify for %s", key)
	if cmp.Equal(*deviceNetworkStatus, status) {
		log.Debugf("handleDNSModify no change")
		return
	}
	*deviceNetworkStatus = status
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*deviceNetworkStatus)
	ctx.usableAddrCount = newAddrCount // inc both ipv4 and ipv6 of mgmt intfs

	// update proxy certs if configured
	if ctx.zedcloudCtx != nil && ctx.zedcloudCtx.V2API {
		zedcloud.UpdateTLSProxyCerts(ctx.zedcloudCtx)
	}
	log.Debugf("handleDNSModify done for %s; %d usable",
		key, newAddrCount)
}

func handleDNSDelete(ctxArg interface{}, key string, statusArg interface{}) {
	log.Debugf("handleDNSDelete for %s", key)
	ctx := ctxArg.(*loguploaderContext)

	if key != "global" {
		log.Debugf("handleDNSDelete: ignoring %s", key)
		return
	}
	*deviceNetworkStatus = types.DeviceNetworkStatus{}
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*deviceNetworkStatus)
	ctx.usableAddrCount = newAddrCount
	log.Debugf("handleDNSDelete done for %s", key)
}

// Handles both create and modify events
func handleGlobalConfigModify(ctxArg interface{}, key string, statusArg interface{}) {
	ctx := ctxArg.(*loguploaderContext)
	if key != "global" {
		log.Debugf("handleGlobalConfigModify: ignoring %s", key)
		return
	}
	log.Debugf("handleGlobalConfigModify for %s", key)
	var gcp *types.ConfigItemValueMap
	debug, gcp = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		debugOverride, logger)
	if gcp != nil && !ctx.GCInitialized {
		ctx.globalConfig = gcp
		ctx.GCInitialized = true
	}
	log.Debugf("handleGlobalConfigModify done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string, statusArg interface{}) {
	ctx := ctxArg.(*loguploaderContext)
	if key != "global" {
		log.Debugf("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Debugf("handleGlobalConfigDelete for %s", key)
	debug, _ = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		debugOverride, logger)
	ctx.globalConfig = types.DefaultConfigItemValueMap()
	log.Debugf("handleGlobalConfigDelete done for %s", key)
}

func doFetchSend(ctx *loguploaderContext, zipDir string, iter *int) int {
	if _, err := os.Stat(zipDir); err != nil {
		log.Debugf("doFetchSend: can't stats %s", zipDir)
		return 0
	}
	files, err := ioutil.ReadDir(zipDir)
	if err != nil {
		log.Fatal("doFetchSend: read dir failed", err)
	}

	numFiles := len(files)
	if numFiles == 0 {
		log.Debugf("doFetchSend: no gzip file found in %s", zipDir)
		return 0
	}

	var fileTime int
	var gotFileName string
	var numGzipfiles int
	var isApp bool
	if zipDir == types.NewlogUploadAppDir {
		isApp = true
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		isgzip, fTime := getTimeNumber(isApp, f.Name())
		if !isgzip {
			continue
		}
		numGzipfiles++
		if fileTime == 0 || fileTime > fTime {
			fileTime = fTime
			gotFileName = f.Name()
		}
	}

	if fileTime > 0 && gotFileName != "" {
		gziplogfile := zipDir + "/" + gotFileName
		file, err := os.Open(gziplogfile)
		if err != nil {
			log.Fatal("doFetchSend: can not open gziplogfile", err)
		}
		reader := bufio.NewReader(file)
		content, _ := ioutil.ReadAll(reader)

		unavailable, err := sendToCloud(ctx, content, *iter, gotFileName, fileTime, isApp)
		if err != nil {
			if unavailable {
				contSentFailure++
				contSentSuccess = 0
			}
			// if resp code is 503, or continously 3 times unavilable failed, start to set the 'FailedToSend' status
			// 'newlogd' gzip directory space management and random spaced out uploading schedule is
			// based on the 'FailedToSend' status
			if (contSentFailure >= 3) && !ctx.metrics.FailedToSend {
				ctx.metrics.FailSentStartTime = time.Now()
				ctx.metrics.FailedToSend = true
				log.Infof("doFetchSend: fail. set fail to send time %v", ctx.metrics.FailSentStartTime.String())
				ctx.metricsPub.Publish("global", ctx.metrics)
			}
			log.Errorf("doFetchSend: %v got error sending http: %v", ctx.metrics.FailSentStartTime.String(), err)
		} else {
			if err := os.Remove(gziplogfile); err != nil {
				log.Fatal("doFetchSend: can not remove gziplogfile", err)
			}

			contSentSuccess++
			contSentFailure = 0
			if contSentSuccess >= 3 && ctx.metrics.FailedToSend {
				log.Infof("doFetchSend: Reset failedToSend, at %v, gzip file %s is sent out ok",
					time.Now().String(), gotFileName)
				ctx.metrics.FailedToSend = false
				ctx.metricsPub.Publish("global", ctx.metrics)
			}
			log.Debugf("doFetchSend: gzip file %s is sent out ok", gotFileName)
		}
		*iter++
		return numGzipfiles - 1
	}
	log.Debugf("doFetchSend: does not find gz log file")
	return 0
}

func getTimeNumber(isApp bool, fName string) (bool, int) {
	if isApp {
		if strings.HasPrefix(fName, types.AppPrefix) && strings.HasSuffix(fName, ".gz") {
			fStr1 := strings.TrimPrefix(fName, types.AppPrefix)
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
		if strings.HasPrefix(fName, types.DevPrefix) && strings.HasSuffix(fName, ".gz") {
			fStr1 := strings.TrimPrefix(fName, types.DevPrefix)
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

func sendToCloud(ctx *loguploaderContext, data []byte, iter int, fName string, fTime int, isApp bool) (bool, error) {
	size := int64(len(data))
	log.Debugf("sendToCloud: size %d, isApp %v, iter %d", size, isApp, iter)

	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("sendToCloud malloc error:")
	}

	var logsURL string
	var sentFailed, serviceUnavailable bool
	if isApp {
		fStr1 := strings.TrimPrefix(fName, types.AppPrefix)
		fStr := strings.Split(fStr1, types.AppSuffix)
		if len(fStr) != 2 {
			err := fmt.Errorf("app split is not 2")
			log.Fatal(err)
		}
		appUUID := fStr[0]
		appLogURL := fmt.Sprintf("apps/instanceid/%s/newlogs", appUUID)
		logsURL = zedcloud.URLPathString(ctx.serverNameAndPort, true, devUUID, appLogURL)
	} else {
		logsURL = newlogsDevURL
	}
	startTime := time.Now()

	// if resp statusOK, then sent success
	// otherwise have to retry the same file later:
	//  - if resp is nil, or it's 'StatusServiceUnavailable', mark as serviceUnavailabe
	//  - if resp is 4xx, the file maybe moved to 'failtosend' directory later
	resp, contents, _, err := zedcloud.SendOnAllIntf(ctx.zedcloudCtx, logsURL, size, buf, iter, true)
	if resp != nil {
		if resp.StatusCode == http.StatusOK {
			latency := time.Since(startTime).Nanoseconds() / int64(time.Millisecond)
			if ctx.metrics.Latency.MinUploadMsec == 0 || ctx.metrics.Latency.MinUploadMsec > uint32(latency) {
				ctx.metrics.Latency.MinUploadMsec = uint32(latency)
			}
			if uint32(latency) > ctx.metrics.Latency.MaxUploadMsec {
				ctx.metrics.Latency.MaxUploadMsec = uint32(latency)
			}
			totalLatency := int64(ctx.metrics.Latency.AvgUploadMsec) *
				int64(ctx.metrics.AppMetrics.NumGZipFilesSent+ctx.metrics.DevMetrics.NumGZipFilesSent)
			filetime := time.Unix(int64(fTime), 0)
			if isApp {
				ctx.metrics.AppMetrics.RecentUploadTimestamp = filetime
				ctx.metrics.AppMetrics.NumGZipFilesSent++
				ctx.metrics.AppMetrics.LastGZipFileSendTime = startTime
			} else {
				updateserverload(ctx, contents)
				ctx.metrics.DevMetrics.RecentUploadTimestamp = filetime
				ctx.metrics.DevMetrics.NumGZipFilesSent++
				ctx.metrics.DevMetrics.LastGZipFileSendTime = startTime
			}
			ctx.metrics.Latency.AvgUploadMsec = uint32((totalLatency + latency) /
				int64(ctx.metrics.AppMetrics.NumGZipFilesSent+ctx.metrics.DevMetrics.NumGZipFilesSent))
			ctx.metrics.Latency.CurrUploadMsec = uint32(latency)

			ctx.metrics.TotalBytesUpload += uint64(size)
			log.Debugf("sendToCloud: sent ok, file time %v, latency %d, content %s",
				filetime, latency, string(contents))
		} else {
			if resp.StatusCode == http.StatusServiceUnavailable {
				serviceUnavailable = true
			} else if isResp4xx(resp.StatusCode) {
				handle4xxlogfile(ctx, fName, isApp)
			}
			sentFailed = true
			log.Debugf("sendToCloud: sent failed, content %s", string(contents))
		}
	} else {
		serviceUnavailable = true
		sentFailed = true
		log.Debugf("sendToCloud: sent failed no resp, content %s", string(contents))
	}
	if sentFailed {
		if isApp {
			ctx.metrics.AppMetrics.NumGZipFileRetry++
		} else {
			ctx.metrics.DevMetrics.NumGZipFileRetry++
		}
	}
	if err != nil {
		log.Errorf("sendToCloud: %d bytes, file %s failed: %v", size, fName, err)
		return serviceUnavailable, fmt.Errorf("sendToCloud: failed to send")
	}
	log.Infof("sendToCloud: Sent %d bytes, file %s to %s", size, fName, logsURL)
	return serviceUnavailable, nil
}

func updateserverload(ctx *loguploaderContext, contents []byte) {
	size := len(contents)
	if size == 0 {
		log.Infof("updateserverload: size zero")
		return
	}
	var serverM logs.ServerMetrics
	contents = bytes.TrimRight(contents, "\n")
	err := json.Unmarshal(contents, &serverM)
	if err == nil {
		ctx.metrics.ServerStats.CurrCPULoadPCT = serverM.CpuPercentage
		ctx.metrics.ServerStats.CurrProcessMsec = serverM.LogProcessDelayMsec

		totalAvg := ctx.metrics.ServerStats.AvgProcessMsec * uint32(ctx.metrics.DevMetrics.NumGZipFilesSent)
		ctx.metrics.ServerStats.AvgProcessMsec = (totalAvg + ctx.metrics.ServerStats.CurrProcessMsec) /
			uint32(ctx.metrics.DevMetrics.NumGZipFilesSent+1)
		totalLoad := ctx.metrics.ServerStats.AvgCPULoadPCT * float32(ctx.metrics.DevMetrics.NumGZipFilesSent)
		ctx.metrics.ServerStats.AvgCPULoadPCT = (totalLoad + ctx.metrics.ServerStats.CurrCPULoadPCT) /
			float32(ctx.metrics.DevMetrics.NumGZipFilesSent+1)
	} else {
		log.Errorf("updateserverload: size %d, contents %s, data unmarshal error %v", size, string(contents), err)
	}
	log.Errorf("updateserverload: size %d, content %s", len(contents), string(contents))
	log.Debugf("updateserverload: size %d, contents %s, pct %f, avg-pct %f, duration-msec %d",
		size, contents, ctx.metrics.ServerStats.CurrCPULoadPCT, ctx.metrics.ServerStats.AvgCPULoadPCT, ctx.metrics.ServerStats.CurrProcessMsec)
}

func isResp4xx(code int) bool {
	remainder := code - 400
	if remainder >= 0 && remainder <= 99 {
		return true
	}
	return false
}

// if we failed to send the same gzip file and get 4xx too many times, move it
// to the 'failedtosend' dir, so we don't get blocked forever, keep maximum of 100 there
func handle4xxlogfile(ctx *loguploaderContext, fName string, isApp bool) {
	var relocate bool
	ctx.metrics.Num4xxResponses++
	if isApp {
		if app4xxfile.logfileName == "" || app4xxfile.logfileName != fName {
			app4xxfile.logfileName = fName
			app4xxfile.failureCnt = 1
		} else if app4xxfile.failureCnt < max4xxRetries {
			app4xxfile.failureCnt++
		} else {
			app4xxfile.logfileName = ""
			app4xxfile.failureCnt = 0
			ctx.metrics.AppMetrics.NumGZipFileDrop++
			relocate = true
		}
	} else {
		if dev4xxfile.logfileName == "" || dev4xxfile.logfileName != fName {
			dev4xxfile.logfileName = fName
			dev4xxfile.failureCnt = 1
		} else if dev4xxfile.failureCnt < max4xxRetries {
			dev4xxfile.failureCnt++
		} else {
			dev4xxfile.logfileName = ""
			dev4xxfile.failureCnt = 0
			ctx.metrics.DevMetrics.NumGZipFileDrop++
			relocate = true
		}
	}

	if relocate {
		var srcFile, dstFile string
		if _, err := os.Stat(failSendDir); err != nil {
			if err := os.MkdirAll(failSendDir, 0755); err != nil {
				log.Fatal(err)
			}
		}

		if isApp {
			srcFile = types.NewlogUploadAppDir + "/" + fName
		} else {
			srcFile = types.NewlogUploadDevDir + "/" + fName
		}
		dstFile = failSendDir + "/" + fName

		files, err := ioutil.ReadDir(failSendDir)
		if err != nil {
			log.Fatal("handle4xxlogfile: read dir ", err)
		}
		if len(files) >= max4xxdropFiles {
			for _, f := range files { // ordered by filename
				log.Infof("handle4xxlogfile: remove 4xx gzip file %s", f.Name())
				os.Remove(failSendDir + "/" + f.Name())
				break
			}
		}

		log.Infof("handle4xxlogfile: relocate src %s to dst %s", srcFile, dstFile)
		os.Rename(srcFile, dstFile)
	}
}
