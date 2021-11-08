package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	timestamp "github.com/golang/protobuf/ptypes/timestamp"
	"github.com/gorilla/websocket"
	"github.com/grandcat/zeroconf"
	"github.com/lf-edge/eve/pkg/pillar/types"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/crypto/ssh"
)

var (
	netopts       []string
	pubsubopts    []string
	pubsubpersist []string
	pubsublarge   []string
	sysopts       []string
	logdirectory  []string
	device        string
	isLocal       bool
	directQuery   bool
	querytype     string
	stoken        string
	timeout       string
	logjson       bool
	extralog      int
	sshprivkey    []byte
	readP         *os.File
	writeP        *os.File
	oldStdout     *os.File
	socketOpen    bool
	wsMsgCount    int
	wsSentBytes   int
	websocketConn *websocket.Conn
	hostKey       ssh.PublicKey
	intSignal     chan os.Signal
	isTCPClient   bool
	tcpRetryWait  bool
	tcpClientRun  bool
	isTCPProxy    bool
	isCopy        bool           // client side
	isSvrCopy     bool           // server side
	copyMsgChn    chan []byte
	tcpMsgChn     chan wsMessage
	tcpDataChn    []chan tcpData
	tcpServerDone chan struct{}
)

var helpStr string=`edge-view [ -ws <ip:port> -token <session-token> | -device <ip-addr> ] <query string>
 options:
  log/search-pattern [ -time <start_time>-<end_time> -json -type <app|dev> -extra num ]
`
const (
	CloseMessage      = "+++Done+++"
	StartCopyMessage  = "+++Start-Copy+++"
	TCPDONEMessage    = "+++tcpDone+++"
	TCPSetupOKMessage = "+++tcpSetupOK+++"
	FileCopyDir       = "/download/"
	clientCertFile    = "/client.pem"
	clientKeyFile     = "/client.key"
)

const (
	RED     = "\033[1;31m%s\033[0m"
	BLUE    = "\033[1;34m%s\033[0m"
	CYAN    = "\033[1;36m%s\033[0m"
	GREEN   = "\033[0;32m%s\033[0m"
	YELLOW  = "\033[0;93m%s\033[0m"
	PURPLE  = "\033[0;35m%s\033[0m"
	BOLD    = "\033[;1m%s\033[0m"
	REVERSE = "\033[;7m%s\033[0m"
	RESET   = "\033[0m"
)

type wsMessage struct {
	mtype      int
	origSize   int // XXX for debug on client side
	msg        []byte
}

type tcpconn struct {
	conn       net.Conn
	msgChan    chan wsMessage
	pending    bool
	closed     bool
	closeTime  time.Time
	recvLocal  int
	recvWss    int
	done       chan struct{}
}

type tcpData struct {
	Version    uint16      `json:"version"`
	MappingID  uint16      `json:"mappingId"`
	ChanNum    uint16      `json:"chanNum"`
	Data       []byte      `json:"data"`
}

type logfiletime struct {
	filepath    string
	filesec     int64
}

type LogEntry struct {
	Severity  string               `json:"severity,omitempty"`  // e.g., INFO, DEBUG, ERROR etc.
	Source    string               `json:"source,omitempty"`    // Source of the msg, zedmanager etc.
	Iid       string               `json:"iid,omitempty"`       // instance ID of the source (e.g., PID)
	Content   string               `json:"content,omitempty"`   // actual log message
	Msgid     uint64               `json:"msgid,omitempty"`     // monotonically increasing number (detect drops)
	Tags      map[string]string    `json:"tags,omitempty"`      // additional meta info <key,value>
	Timestamp *timestamp.Timestamp `json:"timestamp,omitempty"` // timestamp of the msg
	Filename  string               `json:"filename,omitempty"`
	Function  string               `json:"function,omitempty"`
}

type LogContent struct {
	File     string    `json:"file,omitempty"`
	Func     string    `json:"func,omitempty"`
	IfName   string    `ifname:"func,omitempty"`
	Level    string    `json:"level,omitempty"`
	Msg      string    `json:"msg,omitempty"`
	Objtype  string    `json:"obj_type,omitempty"`
	PID      int       `json:"pid,omitempty"`
	Source   string    `json:"source,omitempty"`
	Time     string    `json:"time,omitempty"`
}

type copyFile struct {
	Name      string   `json:"name"`
	Size      int64    `json:"size"`
	Sha256    string   `json:sha256"`
	ModTsec   int64    `json"modtsec"`
}

type fileCopyStatus struct {
	gotFileInfo   bool
	filename      string
	fileSize      int64
	fileHash      string
	currSize      int64
	modTime       time.Time
	buf           []byte
	f             *os.File
}

type urlStats struct {
	recvBytes      int64
	sentBytes      int64
	sentNumber     int64
}

func initOpts() {
	netopts = []string{
		"acl",
		"app",
		"arp",
		"connectivity",
		"flow",
		"if",
		"mdns",
		"nslookup",
		"ping",
		"proxy",
		"route",
		"socket",
		"speed",
		"tcp",
		"tcpdump",
		"trace",
		"url",
		"wireless"}

	pubsubopts = []string{
		"baseosmgr",
		"domainmgr",
		"downloader",
		"global",
		"loguploader",
		"newlogd",
		"nim",
		"nodeagent",
		"tpmmgr",
		"vaultmgr",
		"volumemgr",
		"watcher",
		"zedagent",
		"zedclient",
		"zedmanager",
		"zedrouter"}

	pubsubpersist = []string{
		"nim",
		"tpmmgr",
		"volumemgr",
		"zedagent",
		"zedclient",
		"zedmanager",
		"zedrouter"}

	pubsublarge = []string{
		"zedagent",
		"zedmanager"}

	sysopts = []string{
		"app",
		"configitem",
		"cp",
		"datastore",
		"download",
		"hw",
		"model",
		"newlog",
		"pci",
		"ps",
		"cipher",
		"usb",
		"shell",
		"volume",
	}

	logdirectory = []string{
		"/persist/newlog/keepSentQueue/",
		"/persist/newlog/devUpload/",
		"/persist/newlog/appUpload/",
		"/persist/newlog/failedUpload/",
	}
}

func main() {
	wsAddr := flag.String("ws", "", "http service address")
	phelpopt := flag.Bool("help", false, "command-line help")
	phopt := flag.Bool("h", false, "command-line help")
	pdevip := flag.String("device", "", "device ip option")
	pServer := flag.Bool("server", false, "service edge-view queries")
	ptoken := flag.String("token", "", "session token")
	flag.Parse()
	log.SetFlags(0)

	if *pdevip != "" && !*pServer {
		directQuery = true
	}

	if directQuery {
		var err error
		sshprivkey, err = ioutil.ReadFile("/ssh-private-key")
		if err != nil {
			fmt.Printf("ssh key file error: %v\n", err)
			return
		}
	} else {
		if *wsAddr == "" {
			fmt.Printf("wss address:port needs to be specified when '-token' is used\n")
			return
		}
	}

	if *ptoken != "" && *pServer {
		stoken = *ptoken
	}
	initOpts()

	var fstatus fileCopyStatus
	remotePorts := make(map[int]int)
	var pqueryopt, pnetopt, psysopt, ppubsubopt, logopt, timeopt string
	var jsonopt bool
	typeopt := "all"
	extraopt := 0
	tcpclientCnt := 1
	values := flag.Args()
	var skiptype string
	for _, word := range values {
		if skiptype != "" {
			switch skiptype  {
			case "dev":
				*pdevip = word
			case "time":
				timeopt = word
			case "type":
				typeopt = word
			case "extra":
				numline, _ := strconv.Atoi(word)
				extraopt = numline
			case "token":
				*ptoken = word
			default:
			}
			skiptype = ""
			continue
		}
		if strings.HasSuffix(word, "-help") || strings.HasSuffix(word, "-h") {
			*phelpopt = true
		} else if strings.HasSuffix(word, "-server") {
			*pServer = true
		} else if strings.HasSuffix(word, "-json") {
			jsonopt = true
		} else if strings.HasSuffix(word, "-device") {
			skiptype = "dev"
		} else if strings.HasSuffix(word, "-time") {
			skiptype = "time"
		} else if strings.HasSuffix(word, "-type") {
			skiptype = "type"
		} else if strings.HasSuffix(word, "-extra") {
			skiptype = "extra"
		} else if strings.HasSuffix(word, "-token") {
			skiptype = "token"
		} else {
			pqueryopt = word
		}
	}

	if *phopt || *phelpopt {
		printHelp(pqueryopt)
		return
	}

	if pqueryopt != "" {
		if strings.HasPrefix(pqueryopt, "log/") {
			logs := strings.SplitN(pqueryopt, "log/", 2)
			logopt = logs[1]
			if logopt == "" {
				log.Println("log/ needs search string")
				printHelp("")
				return
			}
		} else if strings.HasPrefix(pqueryopt, "pub/") {
			pubs := strings.SplitN(pqueryopt, "pub/", 2)
			ppubsubopt = pubs[1]
			_, err := checkOpts(ppubsubopt, pubsubopts)
			if err != nil {
				log.Println("pub/ option error")
				printHelp("")
				return
			}
		} else if strings.HasPrefix(pqueryopt, "app/") {
			pnetopt = pqueryopt
		} else if strings.HasPrefix(pqueryopt, "app") {
			psysopt = pqueryopt
		} else if strings.HasPrefix(pqueryopt, "tcp/") {
			tcpopts := strings.SplitN(pqueryopt, "tcp/", 2)
			tcpparam := tcpopts[1]

			var params []string
			if strings.Contains(tcpparam, "/") {
				params = strings.Split(tcpparam, "/")
				if tcpclientCnt > 5 {
					log.Println("tcp maximum mapping is 5")
					return
				}
			} else {
				params = append(params, tcpparam)
			}
			tcpclientCnt = len(params)

			for i, pStr := range params {
				if strings.Contains(pStr, ":") {
					pPort := strings.Split(pStr, ":")
					if len(pPort) == 2 {
						portStr := pPort[1]
						portNum, _ := strconv.Atoi(portStr)
						remotePorts[i] = portNum
					}
				}
			}
			if len(remotePorts) != tcpclientCnt {
				fmt.Printf("tcp port mapping not matching %d, %v", tcpclientCnt, remotePorts)
				return
			}

			isTCPClient = true
			fmt.Printf("tcp mapping locally listening %d ports to remote: %s\n", len(remotePorts), "\033[0;32m")
			for i, p := range params {
				fmt.Printf("  0.0.0.0:%d -> %s\n", 9001 + i, p)
			}
			fmt.Printf("%s\n", RESET)
			pnetopt = pqueryopt
		} else if strings.HasPrefix(pqueryopt, "proxy") {
			isTCPClient = true
			log.Println("proxy server locally listening on: 0.0.0.0:9001\n")
			pnetopt = pqueryopt
		} else if strings.HasPrefix(pqueryopt, "cp/") {
			psysopt = pqueryopt
			isCopy = true
		} else {
			_, err := checkOpts(pqueryopt, netopts)
			if err != nil {
				_, err = checkOpts(pqueryopt, sysopts)
				if err == nil {
					psysopt = pqueryopt
				}
			} else {
				pnetopt = pqueryopt
			}
			if err != nil {
				fmt.Printf("info: %s, not supported\n", pqueryopt)
				printHelp("")
				return
			}
		}
	}

	if logopt != "" && timeopt == "" { // default to now to half an hour before
		timeopt = "0-0.5"
	}

	intSigStart()

	urlSt := url.URL{Scheme: "wss", Host: *wsAddr, Path: "/echo"}

	var err error
	var done chan struct{}
	hostname := ""
	if !directQuery {
		log.Printf("connecting to %s", urlSt.String())
		hostname = getHostname(true)
		ok := setupWebC(hostname, *ptoken, urlSt, *pServer)
		if !ok {
			return
		}
		defer websocketConn.Close()
		done = make(chan struct{})
	}

	var cmdStr string
	var cmdSlice []string
	if *pdevip != "" {
		cmdStr = cmdStr + "-device=" + *pdevip + "+++"
		cmdSlice = append(cmdSlice, "-device=" + *pdevip)
	}
	if pnetopt != "" {
		cmdStr = cmdStr + "-network=" + pnetopt + "+++"
		cmdSlice = append(cmdSlice, "-network=" + pnetopt)
	}
	if psysopt != "" {
		cmdStr = cmdStr + "-system=" + psysopt + "+++"
		cmdSlice = append(cmdSlice, "-system=" + psysopt)
	}
	if ppubsubopt != "" {
		cmdStr = cmdStr + "-pubsub=" + ppubsubopt + "+++"
		cmdSlice = append(cmdSlice, "-pubsub=" + ppubsubopt)
	}
	if logopt != "" {
		cmdStr = cmdStr + "-log=" + logopt + "+++"
		cmdSlice = append(cmdSlice, "-log=" + logopt)
	}
	if timeopt != "" {
		cmdStr = cmdStr + "-time=" + timeopt + "+++"
		cmdSlice = append(cmdSlice, "-time=" + timeopt)
	}
	if jsonopt {
		cmdStr = cmdStr + "-json" + "+++"
		cmdSlice = append(cmdSlice, "-json")
	}
	if extraopt != 0 {
		cmdStr = cmdStr + "-extra=" + strconv.Itoa(extraopt) + "+++"
		cmdSlice = append(cmdSlice, "-extra=" + strconv.Itoa(extraopt))
	}
	if typeopt != "all" {
		cmdStr = cmdStr + "-type=" + typeopt + "+++"
		cmdSlice = append(cmdSlice, "-type=" + typeopt)
	}
	fmt.Printf("cmd: %v\n", cmdSlice) // not printing token

	if *ptoken != "" && !*pServer && !directQuery {
		cmdStr = cmdStr + "-token=" + *ptoken + "+++"
		cmdSlice = append(cmdSlice, "-token=" + *ptoken)
	}
	cmdSlice = append(cmdSlice, "")

	if directQuery {
		parserAndRun(cmdSlice)
		return
	} else if *pServer {
		go func() {
			defer close(done)
			for {
				mtype, message, err := websocketConn.ReadMessage()
				if err != nil {
					log.Println("read:", err)
					if errors.Is(err, syscall.ECONNRESET) ||
						strings.Contains(err.Error(), "i/o timeout") {
						log.Println("read: timeout or reset, close and resetup websocket")
						websocketConn.Close()
						tcpRetryWait = true
						time.Sleep(100 * time.Millisecond)
						ok := setupWebC(hostname, *ptoken, urlSt, true)
						tcpRetryWait = false
						if ok {
							continue
						}
					}
					return
				}
				// remove the token to be printed
				var argv0 []string
				if mtype == websocket.TextMessage {
					lmsg := strings.Split(string(message), "-token=")
					if len(lmsg) == 2 {
						lmsg2 := strings.Split(lmsg[1], "+++")
						msg := lmsg[0] + lmsg2[1]
						log.Printf("recv: %s", msg)
					} else {
						log.Printf("recv: %s", message)
					}
					if strings.Contains(string(message), "no device online") ||
						strings.Contains(string(message), CloseMessage) {
						log.Println("read: no device, continue")
						continue
					}
					cmds := strings.Split(string(message), "+++")
					for _, c := range cmds {
						argv0 = append(argv0, c)
					}
					if len(argv0) == 0 {
						log.Println("read: no argv")
						continue
					}
				}
				//fmt.Printf("got message, type %d, isTCPProxy %v\n", mtype, isTCPProxy) // XXX
				if isSvrCopy {
					copyMsgChn <- message
					continue
				} else if isTCPProxy {
					if mtype == websocket.TextMessage {
						close(tcpServerDone)
						continue
					}
					var jmsg tcpData
					err := json.Unmarshal(message, &jmsg)
					if err != nil {
						fmt.Printf("json unmarshal err %v\n", err)
						continue
					}
					mid := jmsg.MappingID - 1
					myChan, ok := tcpConnM[mid].Get(int(jmsg.ChanNum))
					if !ok || myChan.closed {
						fmt.Printf("tcpConnMap(%d) has no chan %d on server, launch\n", mid, jmsg.ChanNum)
						tcpDataChn[mid] <- jmsg
						continue
					}
					msg := wsMessage{
						mtype: mtype,
						msg:   jmsg.Data,
					}
					myChan.msgChan <- msg
					continue
				}
				go goRunQuery(argv0)
			}
		}()
	} else {
		// send the query command to websocket server
		err = websocketConn.WriteMessage(websocket.TextMessage, []byte(cmdStr))
		if err != nil {
			log.Println("write:", err)
			return
		}
		go func() {
			defer close(done)
			for {
				mtype, message, err := websocketConn.ReadMessage()
				if err != nil {
					log.Println("client read wss:", err)
					if errors.Is(err, syscall.ECONNRESET) {
						if isTCPClient {
							log.Println("reset by peer, try reconnect %v", time.Now())
							websocketConn.Close()
							tcpRetryWait = true
							time.Sleep(100 * time.Millisecond)
							ok := setupWebC(hostname, *ptoken, urlSt, false)
							tcpRetryWait = false
							if ok {
								continue
							} else {
								log.Println("retry failed. exit")
							}
						}
					}
					return
				}
				if strings.Contains(string(message), CloseMessage) {
					log.Printf("%s\n", string(message))
					log.Printf("receive message done\n")
					done <- struct{}{}
					break
				} else if isTCPClient {
					if mtype == websocket.TextMessage {
						log.Printf("setup tcp client: %s\n", message)
						if !tcpClientRun {
							if bytes.Contains(message, []byte(TCPSetupOKMessage)) {
								tcpClientsLaunch(tcpclientCnt, remotePorts)
							}
						} else {
							fmt.Printf(" tcp client running, receiving close probably due to server timed out: %v\n", string(message))
							done <- struct{}{}
							break
						}
					} else {
						var jmsg tcpData
						err := json.Unmarshal(message, &jmsg)
						if err != nil {
							fmt.Printf("json unmarshal err %v\n", err)
							continue
						}
						mid := jmsg.MappingID - 1
						if len(tcpConnM) < int(mid) {
							fmt.Printf("tcpConnMap size %d, can not have index %d\n", len(tcpConnM), mid)
							continue
						}
						myChan, ok := tcpConnM[mid].Get(int(jmsg.ChanNum))
						if !ok {
							fmt.Printf("tcpConnMap has no chan %d on client\n", jmsg.ChanNum)
							continue
						}
						if myChan.closed {
							fmt.Printf("tcpConnMap chan %d on client is closed\n", jmsg.ChanNum)
							continue
						}
						msg := wsMessage{
							mtype:    mtype,
							msg:      jmsg.Data,
							origSize: len(message),
						}
						//fmt.Printf("in TCP Client, send msg to chan %d\n", jmsg.ChanNum)
						myChan.msgChan <- msg
					}
				} else if isCopy {
					getCopyFile(message, &fstatus, mtype)
					if mtype == websocket.TextMessage && isCopy && fstatus.f != nil {
						defer fstatus.f.Close()
					}
				} else {
					log.Printf("%s\n", message)
				}
			}
		}()
	}

	for {
		select {
		case <-done:
			tcpClientSendDone()
			return
		case <-intSignal:
			log.Println("interrupt")
			tcpClientSendDone()
			return
		}
	}
}

func setupWebC(hostname, token string, u url.URL, isServer bool) bool {
	//var err error
	//var c *websocket.Conn
	var pport int
	var pIP string
	retry := 0
	if isServer {
		proxyIP, proxyPort, proxyPEM := getProxy(false)
		if len(proxyPEM) > 0 {
			err := addPackage("update-ca-certificates", "ca-certificates")
			if err == nil {
				dir := "/usr/local/share/ca-certificates"
				os.MkdirAll(dir, 0644)
				for i, pem := range proxyPEM {
					ff, err := os.Create(dir + "/proxy-cert" + strconv.Itoa(i) + ".pem")
					if err != nil {
						fmt.Printf("file create error %v\n", err)
						continue
					}
					ff.WriteString(string(pem))
					ff.Close()
				}
				runCmd("/usr/sbin/update-ca-certificates", false, false)
			}
		}
		if proxyIP != "" {
			fmt.Printf("proxyIP %s, port %d\n", proxyIP, proxyPort)
		}
		pport = proxyPort
		pIP = proxyIP
	}
	for {
		tlsDialer := tlsDial(isServer, pIP, pport)
		c, resp, err := tlsDialer.Dial(u.String(),
			http.Header{
				"X-Session-Token": []string{token},
				"X-Hostname": []string{hostname}},
			)
		if err != nil {
			if resp == nil {
				fmt.Printf("dial: %v, wait for 10 sec\n", err)
			} else {
				fmt.Printf("dial: %v, status code %d, wait for 10 sec\n", err, resp.StatusCode)
			}
			time.Sleep(10 * time.Second)
		} else {
			websocketConn = c
			fmt.Printf("connect success to websocket server\n")
			break
		}
		retry++
		if !isServer && retry > 2 {
			return false
		}
	}
	return true
}

func intSigStart() {
	intSignal = make(chan os.Signal, 1)
	signal.Notify(intSignal, os.Interrupt)
}

func intSigStop() {
	signal.Stop(intSignal)
}

// TLS Dialer
func tlsDial(isServer bool, pIP string, pport int) *websocket.Dialer {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	_, err1 := os.Stat(clientCertFile)
	_, err2 := os.Stat(clientKeyFile)
	if err1 == nil && err2 == nil {
		cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
		if err == nil {
			tlsConfig.Certificates = []tls.Certificate{cert}
			fmt.Printf("client cert set in tlsConfig\n")
		} else {
			fmt.Printf("cert error %v\n", err)
		}
	}

	dialer := &websocket.Dialer{
		TLSClientConfig: tlsConfig,
	}
	if pIP != "" && pport != 0 {
		proxyURL, _ := url.Parse("http://"+pIP+":"+strconv.Itoa(pport))
		dialer.Proxy = http.ProxyURL(proxyURL)
	}

	return dialer
}

func getHostname(isServer bool) string {
	var hostname string
	if !isServer {
		return hostname
	}
	isLocal = true
	retStr, err := runCmd("hostname", false, false)
	if err != nil {
		return hostname
	}
	hostname = strings.TrimSuffix(retStr, "\n")
	return hostname
}

func goRunQuery(argv0 []string) {
	var err error
	wsMsgCount = 0
	wsSentBytes = 0
	readP, writeP, err = openPipe()
	if err == nil {
		parserAndRun(argv0)
		if isTCPProxy {
			return
		}
		closePipe(false)
		err = websocketConn.WriteMessage(websocket.TextMessage, []byte(CloseMessage))
		if err != nil {
			fmt.Printf("sent done msg error: %v\n", err)
		}
		fmt.Printf("Sent %d messages, total %d bytes to websocket\n", wsMsgCount, wsSentBytes)
	}
}

func parserAndRun(argv []string) {
	if len(argv) < 1 {
		return
	}
	inargv0 := argv[:len(argv)-1]
	var netw, sysopt, pubsub, logopt, queryToken string
	logjson = false
	querytype = "all"
	extralog = 0
	timeout = ""
	var tokenSet bool
	for _, a := range inargv0 {
		if strings.Contains(a, "query") {
			continue
		}

		if strings.Contains(a, "device=") {
			devs := strings.Split(a, "=")
			device = devs[1]
			if device == "" || device == "localhost" || device == "0.0.0.0" || device == "127.0.0.1" {
				isLocal = true
			}
		} else if strings.Contains(a, "network=") {
			nets := strings.Split(a, "network=")
			netw = nets[1]
		} else if strings.Contains(a, "system=") {
			syss := strings.Split(a, "system=")
			sysopt = syss[1]
		} else if strings.Contains(a, "pubsub=") {
			pubs := strings.Split(a, "pubsub=")
			pubsub = pubs[1]
		} else if strings.Contains(a, "log=") {
			logs := strings.Split(a, "log=")
			logopt = logs[1]
		} else if strings.Contains(a, "time=") {
			times := strings.Split(a, "time=")
			timeout = times[1]
		} else if strings.Contains(a, "extra=") {
			extraopt := strings.Split(a, "extra=")
			extralog, _ = strconv.Atoi(extraopt[1])
		} else if strings.Contains(a, "json") {
			logjson = true
		} else if strings.Contains(a, "type=") {
			topt := strings.Split(a, "type=")
			querytype = topt[1]
		} else if strings.Contains(a, "token=") {
			tok := strings.Split(a, "token=")
			queryToken = tok[1]
			tokenSet = true
		}
	}

	if stoken != "" {
		if !tokenSet || queryToken != stoken {
			fmt.Printf("session authentication failed\n")
			return
		}
	}

	if device == "" { // if device not specified, it's local
		isLocal = true
	}

	getBasics()
	if netw != "" {
		runNetwork(netw)
	} else if pubsub != "" {
		runPubsub(pubsub)
	} else if sysopt != "" {
		runSystem(sysopt)
	} else if logopt != "" {
		runLogSearch(logopt)
	} else {
		fmt.Printf("no supported options\n")
		return
	}
}

func remoteRun(user string, addr string, privateKey []byte, cmd string) (string, error) {
	key, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		fmt.Printf("ssh parse key error: %v\n", err)
		return "", err
	}
	// Authentication
	config := &ssh.ClientConfig{
		User: user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
	}
	// Connect
	client, err := ssh.Dial("tcp", net.JoinHostPort(addr, "22"), config)
	if err != nil {
		fmt.Printf("ssh dial error: %v\n", err)
		return "", err
	}
	// Create a session. It is one session per command.
	session, err := client.NewSession()
	if err != nil {
		fmt.Printf("ssh session error: %v\n", err)
		return "", err
	}
	defer session.Close()
	var b bytes.Buffer
	session.Stdout = &b // get output

	// Finally, run the command
	err = session.Run(cmd)
	return b.String(), err
}

func checkOpts(opt string, optslice []string) ([]string, error) {
	opts := strings.Split(opt, ",")
	for _, o := range opts {
		ok := false
		if strings.Contains(o, "/") {
			opt1 := strings.Split(o, "/")
			ok = isValidOpt(opt1[0], optslice)
		} else {
			ok = isValidOpt(o, optslice)
		}
		if !ok {
			return []string{}, fmt.Errorf("options available: %v", optslice)
		}
	}
	return opts, nil
}

func isValidOpt(value string, optslice []string) bool {
	for _, opt := range optslice {
		if opt == value {
			return true
		}
	}
	return false
}

func getBasics() {
	if isLocal {
		if _, err := os.Stat("/config"); err != nil {
			return
		}
	}

	retStr, err := runCmd("ip -4 -br a | grep UP", false, false)
	if err == nil {
		lines := splitLines(retStr)
		ips := []string{}
		for _, l := range lines {
			if strings.HasPrefix(l, "bn") {
				continue
			}
			//fmt.Printf("l: %s\n", l)
			words := strings.Fields(l)
			n := len(words)
			ipaddrs := strings.Split(words[n-1], "/")
			ips = append(ips, ipaddrs[0])
		}
		fmt.Printf("Device IPs: %v\n", ips)
	}
	retStr, err = runCmd("cat /config/uuid", false, false)
	if err == nil {
		fmt.Printf("  UUID: %s", retStr)
	}
	retStr, err = runCmd("cat /config/server", false, false)
	if err == nil {
		var printed bool
		conts := strings.Split(retStr, "zedcloud.")
		if len(conts) == 2 {
			cont2s := strings.Split(conts[1], ".zededa.net")
			if len(cont2s) == 2 {
				cluster := cont2s[0]
				controller := strings.Replace(retStr, cluster, "\033[0;93m"+cluster+"\033[0m", 1)
				fmt.Printf("  Controller: %s", controller)
				printed = true
			}
		}
		if !printed {
			fmt.Printf("  Controller: %s", retStr)
		}
	}
	retStr, err = runCmd("cat /run/eve-release && echo -n ', ' && cat /run/eve.id", false, false)
	if err == nil {
		fmt.Printf("  EVE-OS release %s", retStr)
	}
	retStr, err = runCmd("uptime", false, false)
	if err == nil {
		ret1 := strings.Split(retStr, " load")
		uptime := ret1[0]
		loc, _ := time.LoadLocation("UTC")
		fmt.Printf("  %v(%v), uptime %s", time.Now().In(loc).Format(time.RFC3339), loc, uptime)
	}
	fmt.Println()
	fmt.Println()
	closePipe(true)
}

// - network service

func runNetwork(netw string) {
	opts, err := checkOpts(netw, netopts)
	if err != nil {
		fmt.Println("runNetwork:", err)
	}

	for _, opt := range opts {
		//fmt.Printf("\n network option: %s\n", opt)
		var substring string
		if strings.Contains(opt, "/") {
			items := strings.SplitN(opt, "/", 2)
			opt = items[0]
			substring = items[1]
		}

		var intfStr, server string
		if opt == "if" || opt == "ping" || opt == "trace" {
			intfStr, _ = runIntfCmd()
		}
		if opt == "ping" || opt == "trace" {
			server, err = runCmd("cat /config/server", false, false)
			server = strings.TrimSuffix(server, "\n")
		}
		if opt == "url" {
			getURL()
		} else if opt == "route" {
			runRoute()
		} else if opt == "socket" {
			printColor(" listening socket ports: ", BLUE)
			runCmd("ss -tunlp4", true, true)
			printColor(" socket established: ", BLUE)
			runCmd("ss -t state established", true, true)
		} else if opt == "nslookup" {
			getDNS(substring)
		} else if opt == "arp" {
			getARP(substring)
		} else if opt == "acl" {
			runACLs(false, substring)
			runACLs(true, substring)
		} else if opt == "connectivity" {
			printColor(" - Connectivity: ", BLUE)
			getConnectivity()
		} else if opt == "if" {
			fmt.Printf("%s\n", intfStr)
			printTitle(" ip -br link:", CYAN, false)
			retStr, err := runCmd("ip -br link", false, false)
			if err != nil {
				continue
			}
			r := strings.Split(retStr, "\n")
			n := len(r)
			for _, intf := range r[:n-1] {
				if !strings.Contains(intf, substring) {
					continue
				}
				fmt.Printf("%s\n", intf)
			}
			getPortCfg(substring, true)
			printTitle(" proxy:", CYAN, false)
			getProxy(true)
		} else if opt == "app" {
			retStr, err := runCmd("ls /run/zedrouter/AppNetworkStatus/*.json", false, false)
			if err != nil {
				continue
			}
			r := strings.Split(retStr, "\n")
			n := len(r)
			for _, s := range r[:n-1] {
				retStr1, err := runCmd("cat "+s, false, false)
				if err != nil {
					continue
				}
				status := strings.TrimSuffix(retStr1, "\n")
				doAppNet(status, substring, false)
			}
		} else if opt == "trace" {
			if substring != "" {
				cmd := "traceroute -4 -m 10 -q 2 " + substring
				if timeout != "" {
					cmd = "timeout " + timeout + " " + cmd
				}
				printTitle(" traceroute to "+substring, CYAN, true)
				retStr, _ := runCmd(cmd, false, false) // timeout will generate error
				fmt.Printf("%s\n", retStr)
			} else {
				printTitle(" traceroute to google", CYAN, true)
				runCmd("traceroute -4 -m 10 -q 2 www.google.com", false, true)
				if server != "" {
					printTitle(" traceroute to "+server, CYAN, true)
					runCmd("traceroute -4 -m 10 -q 2 "+server, false, true)
				}
			}
		} else if opt == "proxy" {
			setAndStartProxyTCP(substring, true)
		} else if opt == "ping" {
			runPing(intfStr, server, substring)
		} else if opt == "tcpdump" {
			runTcpDump(substring)
		} else if opt == "wireless" {
			runWireless()
		} else if opt == "speed" {
			runSpeedTest(substring)
		} else if opt == "flow" {
			getFlow(substring)
		} else if opt == "mdns" {
			runmDNS(substring)
		} else if opt == "tcp" {
			setAndStartProxyTCP(substring, false)
		} else {
			fmt.Printf("\n not supported yet\n")
		}
	}
}

// doAppNet
func doAppNet(status, appstr string, isSummary bool) string {
	var appStatus types.AppNetworkStatus
	json.Unmarshal([]byte(status), &appStatus)
	niType := map[types.NetworkInstanceType]string{
		types.NetworkInstanceTypeSwitch:      "switch",
		types.NetworkInstanceTypeLocal:       "local",
		types.NetworkInstanceTypeCloud:       "cloud",
		types.NetworkInstanceTypeHoneyPot:    "honeypot",
		types.NetworkInstanceTypeTransparent: "transparent",
	}

	name := appStatus.DisplayName
	nameLower := strings.ToLower(name)
	appStrLower := strings.ToLower(appstr)
	if appstr != "" && !strings.Contains(nameLower, appStrLower) {
		return ""
	}
	printColor("\n - app: "+name+", appNum: "+strconv.Itoa(appStatus.AppNum)+"\n", BLUE)
	fmt.Printf("   app uuid %s\n", appStatus.UUIDandVersion.UUID.String())

	if appStatus.GetStatsIPAddr != nil {
		fmt.Printf("\n - App Container Stats Collect IP %v\n", appStatus.GetStatsIPAddr)
	}

	for _, item := range appStatus.UnderlayNetworkList {
		niUUID := item.Network.String()
		retStr, err := runCmd("cat /run/zedrouter/NetworkInstanceStatus/"+niUUID+".json", false, false)
		if err != nil {
			continue
		}
		var niStatus types.NetworkInstanceStatus
		json.Unmarshal([]byte(retStr), &niStatus)
		//fmt.Printf("ni: %+v\n", niStatus)
		var ifname string
		var ipaddr net.IP
		for _, p := range item.ACLDependList {
			if ifname != p.Ifname || !ipaddr.Equal(p.IPAddr) {
				fmt.Printf("\n  - uplink port: %s, %v\n", p.Ifname, p.IPAddr)
				ifname = p.Ifname
				ipaddr = p.IPAddr
			}
		}
		fmt.Printf("\n == bridge: %s, %s, %v, %s\n", item.Bridge, item.Vif, item.AllocatedIPv4Addr, item.Mac)

		if isSummary {
			continue
		}

		// XXX ip flow

		ipStr := item.AllocatedIPv4Addr
		printColor("\n - ping app ip address: "+ipStr, RED)
		runCmd("ping -c 3 "+ipStr, false, true)

		if niStatus.Type != types.NetworkInstanceTypeSwitch {
			printColor("\n - check open ports for "+ipStr, RED)
			// nmap package

			retStr, err := runCmd("cat /run/zedrouter/dhcp-hosts."+item.Bridge+"/*.inet", false, false)
			if err == nil {
				printColor("\n - dhcp host file:\n", GREEN)
				lines := strings.Split(retStr, "\n")
				for _, l := range lines {
					if strings.Contains(l, item.Mac) {
						fmt.Printf("%s\n", l)
						break
					}
				}
			}

			retStr, err = runCmd("cat /run/zedrouter/dnsmasq.leases/"+item.Bridge, false, false)
			if err == nil {
				printColor("\n - dnsmasq lease files\n", GREEN)
				lines := strings.Split(retStr, "\n")
				for _, l := range lines {
					if strings.Contains(l, item.Mac) {
						fmt.Printf("%ss\n", l)
						items := strings.Split(l, " ")
						unixtime, _ := strconv.Atoi(items[0])
						fmt.Printf(" lease up to: %v\n", time.Unix(int64(unixtime), 0))
						break
					}
				}
			}

			runAppACLs(item.AllocatedIPv4Addr)

			getVifStats(item.Vif)

			getAppNetTable(item.AllocatedIPv4Addr, &niStatus)

			// NI
			printColor("\n - network instance: ", GREEN)
			fmt.Printf(" %s, type %s, logical lable: %s\n\n", niStatus.DisplayName,
				niType[niStatus.Type], niStatus.Logicallabel)
			fmt.Printf(" DHCP range start: %v, end: %v\n", niStatus.DhcpRange.Start, niStatus.DhcpRange.End)
			fmt.Printf(" Current Uplink: %s\n", niStatus.CurrentUplinkIntf)
			fmt.Printf(" Probe Status:\n")
			for k, p := range niStatus.PInfo {
				fmt.Printf(" Uplink Intfname: %s\n", k)
				upStatus := "Down"
				if p.SuccessCnt != 0 || p.SuccessProbeCnt != 0 {
					upStatus = "UP"
				}
				fmt.Printf("   Probe status: %s, Cost: %d, local sucess: %d, remote success: %d\n",
					upStatus, p.Cost, p.SuccessCnt, p.SuccessProbeCnt)
			}
			fmt.Printf("\n")
		}
		closePipe(true)
	}

	appUUIDStr := appStatus.UUIDandVersion.UUID.String()
	retStr, err := runCmd("cat /run/domainmgr/DomainStatus/"+appUUIDStr+".json", false, false)
	if err == nil {
		printColor("\n  - domain status:", GREEN)
		var domainS types.DomainStatus
		json.Unmarshal([]byte(retStr), &domainS)
		fmt.Printf("    state: %d, boot time: %v, tried count %d\n",
			domainS.State, domainS.BootTime, domainS.TriedCount)
		if domainS.Error != "" {
			fmt.Printf("    error: %s, error time: %v, boot failed: %v",
				domainS.Error, domainS.ErrorTime, domainS.BootFailed)
		}
	}
	return appUUIDStr
}

// getAppNetTable - in 'doAppNet'
func getAppNetTable(ipaddr string, niStatus *types.NetworkInstanceStatus) {
	dhcpStart := niStatus.DhcpRange.Start
	dhcpEnd := niStatus.DhcpRange.End
	_, ipnet, err := net.ParseCIDR(dhcpStart.String() + "/16")
	_, ipnet2, err2 := net.ParseCIDR(dhcpEnd.String() + "/16")
	if err != nil || err2 != nil {
		return
	}
	mask := "/24" // assume there is only /24 or /16 here
	if ipnet.Contains(ipnet2.IP) && ipnet2.Contains(ipnet.IP) {
		mask = "/16"
	}

	ips := strings.Split(ipaddr, ".")
	cmd := "ip rule | grep 'from " + ips[0] + "." + ips[1] + ".'" + " | grep " + mask
	retStr, err := runCmd(cmd, false, false)
	if err != nil {
		return
	}
	printColor("\n - ip route tables related to: "+ipaddr, GREEN)
	lines := strings.Split(retStr, "\n")
	n := len(lines)
	for _, l := range lines[:n-1] {
		l2 := strings.Split(l, " lookup ")
		table := strings.TrimSpace(l2[1])
		fmt.Printf(" ip rule: \n" + l + "\n")
		fmt.Printf("\n for table: " + table + "\n")
		runCmd("ip route show table "+table, false, true)
	}
}

// getVifStats - in 'doAppNet'
func getVifStats(vifStr string) {
	retStr, err := runCmd("cat /run/zedrouter/NetworkMetrics/global.json", false, false)
	if err != nil {
		return
	}
	printColor("\n - bridge Tx/Rx packets on: "+vifStr, GREEN)
	var ntMetric types.NetworkMetrics
	json.Unmarshal([]byte(retStr), &ntMetric)
	for _, m := range ntMetric.MetricList {
		if vifStr == m.IfName {
			fmt.Printf(" TxBytes: %d, RxBytes: %d, TxPkts: %d, RxPkts: %d\n",
				m.TxBytes, m.RxBytes, m.TxPkts, m.RxPkts)
			break
		}
	}
}

// runAppACLs - in 'doAppNet'
func runAppACLs(ipStr string) {
	printColor("\n - check for ACLs on: "+ipStr+"\n", GREEN)
	runAppACLTblAddr("-S", "filter", ipStr)
	runAppACLTblAddr("-nvL", "filter", ipStr)
	runAppACLTblAddr("-S", "nat", ipStr)
	runAppACLTblAddr("-nvL", "nat", ipStr)
}

func runAppACLTblAddr(op, tbl, ipaddr string) {
	retStr, err := runCmd("iptables "+op+" -t "+tbl+" | grep "+ipaddr, true, false)
	if err == nil {
		if len(retStr) > 0 {
			act := ""
			if strings.Contains(op, "S") {
				act = " configured"
			}
			fmt.Printf(" iptable " + tbl + act + " rules: \n")
			fmt.Printf("%s\n", retStr)
		}
	}
}

func getURL() {
	var totalStats urlStats
	getMetricsMap("/run/zedclient/MetricsMap/", &totalStats, true)
	getMetricsMap("/run/zedagent/MetricsMap/", &totalStats, true)
	getMetricsMap("/run/downloader/MetricsMap/", &totalStats, true)
	getMetricsMap("/run/loguploader/MetricsMap/", &totalStats, true)
	getMetricsMap("/run/zedrouter/MetricsMap/", &totalStats, true)
	getMetricsMap("/run/nim/MetricsMap/", &totalStats, true)
	getMetricsMap("/run/diag/MetricsMap/", &totalStats, true)

	printTitle(" - Total Send/Receive stats:\n", CYAN, false)
	fmt.Printf("  send bytes %d, recv bytes %d, send messages %d\n",
		totalStats.sentBytes, totalStats.recvBytes, totalStats.sentNumber)

	mgmtports := getPortCfg("", false)

	var intfRx, intfTx int
	for _, mgmt := range mgmtports {
		tx, rx := getTxRx(mgmt)
		intfTx += tx
		intfRx += rx
	}
	printTitle(" - Total Mgmt intf Send/Receive stats:\n", CYAN, false)
	fmt.Printf("  %v\n", mgmtports)
	fmt.Printf("  send bytes %d, recv bytes %d\n", intfTx, intfRx)

	retStr, err := runCmd("ip -4 -br a | grep UP", false, false)
	if err != nil {
		return
	}
	var bridgeports []string
	ports := strings.Split(retStr, "\n")
	for _, port := range ports {
		if strings.HasPrefix(port, "bn") {
			fields := strings.Fields(port)
			bridgeports = append(bridgeports, fields[0])
		}
	}
	if len(bridgeports) > 0 {
		printTitle(" - Total Bridge intf Send/Receive stats:\n", CYAN, false)
	}
	intfRx = 0
	intfTx = 0
	for _, bridge := range bridgeports {
		tx, rx := getTxRx(bridge)
		intfTx += tx
		intfRx += rx
	}
	fmt.Printf("  %v\n", bridgeports)
	fmt.Printf("  send bytes %d, recv bytes %d\n", intfTx, intfRx)
}

func getTxRx(intf string) (int, int) {
	var intfTx, intfRx int
	retStr, err := runCmd("ip -s -s link show "+intf, false, false)
	if err != nil {
		return intfTx, intfRx
	}
	data1 := strings.Split(retStr, "\n")
	var foundTx, foundRx bool
	for _, line := range data1 {
		if strings.Contains(line, "  RX: bytes") {
			foundRx = true
			continue
		} else if strings.Contains(line, "  TX: bytes") {
			foundTx = true
			continue
		}
		if foundRx {
			foundRx = false
			data2 := strings.Fields(line)
			count, _ := strconv.Atoi(data2[0])
			intfRx += count
		} else if foundTx {
			foundTx = false
			data2 := strings.Fields(line)
			count, _ := strconv.Atoi(data2[0])
			intfTx += count
		}
	}
	return intfTx, intfRx
}

// getPortCfg
func getPortCfg(opt string, isPrint bool) []string {
	var mgmtIntf []string
	if isPrint {
		fmt.Printf("\n - device port configure:\n")
	}
	outStr, err := runCmd("cat /run/zedagent/DevicePortConfig/zedagent.json", false, false)
	if err != nil {
		return mgmtIntf
	}
	if isPrint {
		fmt.Printf("%s\n", outStr)
	}

	var portcfg types.DevicePortConfig
	json.Unmarshal([]byte(outStr), &portcfg)

	dhcpStr := map[types.DhcpType]string{1: "Static", 2: "None", 4: "Client"}
	for _, p := range portcfg.Ports {
		if opt != "" && !strings.Contains(p.IfName, opt) {
			continue
		}
		if isPrint {
			fmt.Printf(" Intf Name: %s\n", p.IfName)
			fmt.Printf("   Is Mgmt %v, Cost %d, dhcp type %v\n", p.IsMgmt, p.Cost, dhcpStr[p.Dhcp])
		}
		if p.IsMgmt {
			mgmtIntf = append(mgmtIntf, p.IfName)
		}
	}
	return mgmtIntf
}

// runIntfCmd
func runIntfCmd() (string, error) {
	return runCmd("ip -br -4 a", false, false)
}

// getConnectivity
func getConnectivity() {
	fmt.Printf("  run diag: \n")
	runCmd("/opt/zededa/bin/diag -o /dev/stdout", true, true)

	retStr, err := runCmd("ls /run/global/DevicePortConfig", false, false)
	if err == nil {
		if strings.HasSuffix(retStr, ".json") {
			fmt.Printf("  override.json:\n")
			retStr1, err := runCmd("cat /run/global/DevicePortConfig/*.json", false, false)
			if err != nil {
				fmt.Printf("error: %v\n", err)
			} else {
				fmt.Println(retStr1)
			}
		} else {
			fmt.Printf("  No override.json\n\n")
		}
	}

	retStr, err = runCmd("cat /persist/status/nim/DevicePortConfigList/global.json", false, false)
	if err != nil {
		return
	}

	printColor(" - port config list", BLUE)
	var portlist types.DevicePortConfigList
	json.Unmarshal([]byte(retStr), &portlist)
	printColor(" Current Index "+strconv.Itoa(portlist.CurrentIndex), GREEN)

	i := 0
	for _, pls := range portlist.PortConfigList {
		str1 := fmt.Sprintf("Key: %s, Last Succeeded: %v, Last Failed: %v\n",
			pls.Key, pls.LastSucceeded, pls.LastFailed)
		if i == portlist.CurrentIndex {
			printColor(str1, RED)
		} else {
			fmt.Printf(str1)
		}
		for _, p := range pls.Ports {
			str2 := fmt.Sprintf("   Ifname: %s, Lable: %s, Mgmt: %v\n",
				p.IfName, p.Logicallabel, p.IsMgmt)
			if i == portlist.CurrentIndex {
				printColor(str2, RED)
			} else {
				fmt.Printf(str2)
			}
		}
		i++
	}
}

// getARP
func getARP(opt string) {
	printColor(" - arp entries: \n", BLUE)
	if opt == "" {
		runCmd("ip -4 n", false, true)
	} else {
		retStr, _ := runCmd("ip -4 n", false, false)
		lines := strings.Split(retStr, "\n")
		n := len(lines)
		for _, l := range lines[:n-1] {
			if !strings.Contains(l, opt) {
				continue
			}
			fmt.Printf("%s\n", l)
		}
	}
}

// runACLs
func runACLs(isRunningACL bool, filter string) {
	acltables := []string{"raw", "filter", "nat", "mangle"}
	for _, tbl := range acltables {
		if filter != "" && filter != tbl {
			continue
		}
		var op string
		if isRunningACL {
			printColor(" Configured iptables: "+tbl, CYAN)
			op = "-S"
		} else {
			printColor(" Installed iptables: "+tbl, CYAN)
			op = "-nvL"
		}
		runCmd("iptables "+op+" -t "+tbl, true, true)
	}
}

// runRoute
func runRoute() {
	rules, err := runCmd("ip rule", false, false)
	if err != nil {
		fmt.Printf("runRoute: %v", err)
		return
	}
	printColor(" - ip rule:", RED)
	fmt.Printf("%s\n", rules)
	tables := getTables(rules)
	for _, table := range tables {
		printColor("show route in table: "+table, CYAN)
		runCmd("ip route show table "+table, false, true)
	}
}

func getTables(rules string) []string {
	rulelines := strings.Split(rules, "\n")
	var t []string
	n := len(rulelines)
	for _, rule := range rulelines[:n-1] {
		table := strings.Split(rule, "lookup ")
		if len(table) > 0 {
			if !strings.Contains(table[1], "default") {
				t = append(t, table[1])
			}
		}
	}
	return t
}

func getMetricsMap(path string, stats *urlStats, isPrint bool) {
	retStr, err := runCmd("ls "+path, false, false)
	if err != nil {
		return
	}

	retStr, err = runCmd("cat "+path+"global.json", false, false)
	if err != nil {
		return
	}
	pathname := ""
	paths := strings.Split(path, "/")
	if len(paths) > 3 {
		pathname = paths[2] + " stats"
	}
	printColor(" - "+pathname, CYAN)
	var mmap types.MetricsMap
	json.Unmarshal([]byte(retStr), &mmap)
	//fmt.Printf("%v", mmap)
	for k, m := range mmap {
		fmt.Printf(" interface: %s\n", k)
		fmt.Printf(" Success: %d  Last Success: %v\n", m.SuccessCount, m.LastSuccess)
		if m.FailureCount > 0 {
			fmt.Printf(" Failure: %d  Last Failure: %v\n", m.FailureCount, m.LastFailure)
		}
		urlm := m.URLCounters
		for k1, m1 := range urlm {
			fmt.Printf("   %s\n", k1)
			fmt.Printf("     Recv (KBytes): %d, Sent %d, SentMsg: %d, TLS resume: %d, Total Time(sec): %d\n\n",
				m1.RecvByteCount/1000, m1.SentByteCount, m1.SentMsgCount, m1.SessionResume, m1.TotalTimeSpent/1000)
			if stats != nil {
				stats.recvBytes += m1.RecvByteCount
				stats.sentBytes += m1.SentByteCount
				stats.sentNumber += m1.SentMsgCount
			}
		}
	}
}

func getDNS(domain string) {
	if domain == "" {
		domain = "zedcloud.zededa.net"
	}
	printColor(" - nslookup: "+domain, CYAN)
	runCmd("nslookup "+domain, false, true)
}

func runPing(intfStr, server string, opt string) {
	if opt != "" {
		if strings.Contains(opt, "/") {
			opts := strings.Split(opt, "/")
			intf := opts[0]
			ipaddr := opts[1]
			printColor("\n - ping "+ipaddr+" through intf: "+intf, CYAN)
			runCmd("ping -c 3 -I "+intf+" "+ipaddr, false, true)
		} else {
			printColor("\n - ping "+opt, CYAN)
			runCmd("ping -c 3 "+opt, false, true)
		}
		return
	}
	if intfStr == "" {
		fmt.Printf(" can not find intf to ping\n")
		return
	}

	intfs := splitLines(intfStr)
	for _, intfline := range intfs {
		if !strings.Contains(intfline, "UP") || intfline == "" {
			continue
		}
		intf := strings.Fields(intfline)
		if strings.HasPrefix(intf[0], "bn") {
			continue
		}
		intfip := intf[len(intf)-1]
		fmt.Printf("intf %v, intfip %s, n %d\n", intf, intfip, len(intf))
		ipa, _, err := net.ParseCIDR(intfip)
		if err != nil {
			fmt.Printf("ip cidr parse error: %v\n", err)
		}
		ipaddr := "8.8.8.8"
		printColor("\n - ping "+ipaddr+" through intf: "+intf[0], CYAN)
		retStr, err := runCmd("ping -c 3 -I "+intf[0]+" "+ipaddr, false, false)
		if err != nil {
			fmt.Printf("ping: %v\n", err)
			continue
		}
		fmt.Printf("%s\n", retStr)
		// to zedcloud
		if server == "" {
			server = "zedcloud.canary.zededa.net"
		}
		printColor("\n - ping to "+server+", source "+ipa.String(), CYAN)
		if isLocal {
			httpsclient(server, ipa)
		} else {
			runCmd("curl https://"+server+":/api/v1/edgeDevice/ping", true, true)
		}
		closePipe(true)
	}
}

func getProxy(needPrint bool) (string, int, [][]byte) {
	proxyIP := ""
	proxyPort := 0
	proxyPEM := [][]byte{}
	retStr, err := runCmd("cat /run/zedagent/DevicePortConfig/zedagent.json", false, false)
	if err != nil {
		return proxyIP, proxyPort, proxyPEM
	}
	var portcfg types.DevicePortConfig
	json.Unmarshal([]byte(retStr), &portcfg)

	for _, p := range portcfg.Ports {
		if !p.IsMgmt {
			continue
		}
		if len(p.Proxies) > 0 && needPrint {
			fmt.Printf("  ifname %s:\n", p.IfName)
		}
		for _, pp := range p.Proxies {
			if pp.Type == 1 { // https
				proxyIP = pp.Server
				proxyPort = int(pp.Port)

			}
			if needPrint {
				fmt.Printf("    type %d, server %s, port %d\n", pp.Type, pp.Server, pp.Port)
			}
		}
		for _, pem := range p.ProxyCertPEM {
			proxyPEM = append(proxyPEM, pem)
			if needPrint {
				fmt.Printf("    has proxy cert\n")
			}
		}
	}
	return proxyIP, proxyPort, proxyPEM
}

func httpsclient(server string, ipaddr net.IP) {

	localTCPAddr, _ := net.ResolveTCPAddr("tcp", ipaddr.String())
	transport := &http.Transport{
		Dial: (&net.Dialer{ Timeout: 30 * time.Second,
			KeepAlive: 30 * time.Second,
			LocalAddr: localTCPAddr}).Dial, TLSHandshakeTimeout: 10 * time.Second}
	client := &http.Client{
		Transport: transport,
	}

	resp, err := client.Get("https://"+server+":/api/v1/edgeDevice/ping")
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}

	htmlData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("%v\n", resp.Status)
	fmt.Printf(string(htmlData))
}

func getAppUUID(appStr string) (string, string) {
	var connPath, name string
	retData, err := runCmd("ls /run/zedrouter/AppNetworkStatus/*.json", false, false)
	if err != nil {
		fmt.Printf("no appnetworkstatus or error: %v\n", err)
		return connPath, name
	}
	r := strings.Split(retData, "\n")
	n := len(r)
	var appuuid string
	for _, s := range r[:n-1] {
		retData, err = runCmd("cat "+s, false, false)
		status := strings.TrimSuffix(retData, "\n")
		var appStatus types.AppNetworkStatus
		json.Unmarshal([]byte(status), &appStatus)
		name = appStatus.DisplayName
		nameLower := strings.ToLower(name)
		appStrLower := strings.ToLower(appStr)
		if !strings.Contains(nameLower, appStrLower) {
			continue
		}
		appuuid = appStatus.UUIDandVersion.UUID.String()
		break
	}

	if appuuid == "" {
		fmt.Printf("app for %s not found\n", appStr)
		return connPath, name
	}
	return appuuid, name
}

func findAppCons(appuuid string) string {
	var connPath string
	cmd := "cd /run/hypervisor/kvm/ && find . -name 'cons' -print"
	retData, err := runCmd(cmd, false, false)
	if err != nil {
		return connPath
	}

	r := strings.Split(retData, "\n")
	n := len(r)
	var appItem string
	for _, k := range r[:n-1] {
		item := strings.Split(k, "/")
		if len(item) != 3 {
			continue
		}
		if !strings.Contains(item[1], appuuid) {
			continue
		}
		appItem = item[1]
		break
	}

	if appItem == "" {
		fmt.Printf("app for kvm not found\n")
		return connPath
	}
	connPath = "/run/hypervisor/kvm/" + appItem + "/cons"
	return connPath
}

func getFlow(subStr string) {
	err := addPackage("conntrack", "conntrack-tools")
	if err != nil {
		return
	}
	printTitle("\n ip flow:", CYAN, true)

	cmd := "/usr/sbin/conntrack -L 2>&1 "
	if subStr != "" {
		cmd = cmd + "| grep -E " + subStr
	}
	retStr, err := runCmd(cmd, false, false)
	if err != nil {
		fmt.Printf("ip flow error: %v\n", err)
		return
	}

	var olines string
	lines := strings.Split(retStr, "\n")
	for i, l := range lines {
		if len(l) == 0 {
			continue
		}
		if strings.Contains(l, "conntrack v1.") {
			l2 := strings.Split(l, "conntrack v1.")
			l = l2[0]
		}
		var isApp bool
		var appStr string
		if strings.Contains(l, " mark=") { // add appNum and drop string at the end of line
			l2 := strings.Split(l, " mark=")
			if len(l2) != 2 {
				continue
			}
			l3 := strings.SplitN(l2[1], " ", 2)
			if len(l3) != 2 {
				continue
			}
			appNum, _ := strconv.Atoi(l3[0])
			if appNum > 1000 {
				if appNum == 0xffffff {
					appStr = " (drop)"
				} else {
					appN := appNum >> 24
					if appN > 0 && appN < 255 {
						isApp = true
						appStr = " (appNum " + strconv.Itoa(appN) + ")"
					}
				}
			}
			if !isApp && querytype == "app" {
				continue
			}
		}
		olines = l + appStr
		if subStr != "" {
			olines = strings.ReplaceAll(olines, subStr, "\033[0;93m"+subStr+"\033[0m")
		}
		fmt.Printf("%s", olines)
		if i%20 == 0 {
			closePipe(true)
		} else {
			fmt.Println()
		}
	}
}

func runmDNS(subStr string) {
	if directQuery {
		fmt.Printf("mdns is not supported in edge-view ssh mode\n")
		return
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("get interface error: %v\n", err)
		return
	}

	var intfname, serv, serviceStr string
	if strings.Contains(subStr, "/") {
		substrings := strings.Split(subStr, "/")
		if len(substrings) != 2 {
			fmt.Printf("mdns parameter is in the form interface/service\n")
			return
		}
		intfname = substrings[0]
		serv = substrings[1]
	} else {
		intfname = subStr
	}
	var ifs []net.Interface
	for _, intf := range ifaces {
		//fmt.Printf("interface %+v\n", intf)
		if intfname == "" {
			if strings.HasPrefix(intf.Flags.String(), "up|") {
				ifs = append(ifs, intf)
			}
		} else if intf.Name == intfname {
			ifs = append(ifs, intf)
			break
		}
	}

	if serv == "" {
		serviceStr = "_workstation._tcp"
	} else {
		serviceStr = "_" + serv + "._tcp"
	}

	var port []string
	for _, p := range ifs {
		port = append(port, p.Name)
	}
	printTitle(fmt.Sprintf("query mDNS service %s, on intfs %v\n", serviceStr, port), CYAN, true)

	ifOption := zeroconf.SelectIfaces(ifs)
	ipOption := zeroconf.SelectIPTraffic(zeroconf.IPv4)
	resolver, err := zeroconf.NewResolver(ipOption, ifOption)
	if err != nil {
		fmt.Printf("queryService: Failed to initialize resolver: %v", err)
		return
	}

	mctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(10))
	defer cancel()

	entries := make(chan *zeroconf.ServiceEntry)
	go func(results <-chan *zeroconf.ServiceEntry) {
		for entry := range results {
			fmt.Printf("  - %+v\n", entry)
		}
	}(entries)


	err = resolver.Browse(mctx, serviceStr, "local", entries)
	if err != nil {
		fmt.Printf("mdns resolver error %v", err)
		return
	}
	<-mctx.Done()
}

func runTcpDump(subStr string) {
	if !strings.Contains(subStr, "/") {
		fmt.Printf("need to have intf name separated by slash\n")
		return
	}
	err := addPackage("tcpdump", "tcpdump")
	if err != nil {
		return
	}

	subs := strings.SplitN(subStr, "/", 2)
	intf := subs[0]
	var timeValue string
	if timeout != "" {
		timeSec, err := strconv.Atoi(timeout)
		if err != nil {
			fmt.Printf("time option has to be seconds: %v\n", err)
			return
		}
		if timeSec > 120 {
			timeValue = "120"
			fmt.Printf("time value for tcpdump maximum is 120 seconds\n\n")
		} else {
			timeValue = timeout
		}
	} else {
		timeValue = "60"
	}
	cmd := "timeout " + timeValue + " tcpdump -i " + intf + " " + subs[1] + " -c 100"
	printTitle(" tcpdump with: "+cmd, GREEN, true)
	retStr, err := runCmd(cmd, false, false)
	if err != nil {
		fmt.Printf("err %v\n", err)
	} else {
		fmt.Printf("%s\n", retStr)
	}
}

func runWireless() {
	err := addPackage("iwconfig", "wireless-tools")
	if err != nil {
		return
	}

	printTitle("\n iwconfig wlan0", CYAN, false)
	runCmd("iwconfig wlan0", false, true)

	retStr, err := runCmd("cat /run/wlan/wpa_supplicant.conf", false, false)
	if err == nil {
		printTitle(" wpa_supplicant.conf:", CYAN, false)
		lines := strings.Split(retStr, "\n")
		for _, l := range lines[:len(lines)-1] {
			if strings.Contains(l, "psk=") {
				pos := strings.Split(l, "psk=")
				n := len(pos[1])
				pos2 := pos[0] + "psk=" + pos[1][:3] + "..." + pos[1][n-3:]
				fmt.Printf("%s\n", pos2)
			} else {
				fmt.Printf("%s\n", l)
			}
		}
	}
}

func runSpeedTest(intf string) {
	err := addPackage("speedtest", "speedtest-cli")
	if err != nil {
		return
	}
	var opt string
	if intf != "" {
		retStr, err := runCmd("ip -4 -br a | grep UP", false, false)
		if err == nil {
			lines := splitLines(retStr)
			for _, l := range lines {
				if strings.Contains(l, intf) {
					words := strings.Fields(l)
					n := len(words)
					ipaddr := strings.Split(words[n-1], "/")
					opt = " --source " + ipaddr[0]
				}
			}
		}
	}
	printTitle("\n speed test: on "+intf+", "+opt, CYAN, true)
	runCmd("/usr/bin/speedtest"+opt, false, true)
}

// - end of network

// - pubsub

func runPubsub(pubStr string) {
	opts, err := checkOpts(pubStr, pubsubopts)
	if err != nil {
		fmt.Println("runPubsub:", err)
	}

	startdir := []string{"/run/", "/persist/status/", "/persist/pubsub-large/"}
	for _, p := range opts {
		var pubsubdir, subdir string
		if strings.Contains(p, "/") {
			items := strings.Split(p, "/")
			pubsubdir = items[0]
			subdir = items[1]
		} else {
			pubsubdir = p
			subdir = ""
		}

		for _, sdir := range startdir {
			if sdir == "/persist/status/" {
				opts1, _ := checkOpts(pubStr, pubsubpersist)
				if len(opts1) == 0 {
					break
				}
			} else if sdir == "/persist/pubsub-large/" {
				opts1, _ := checkOpts(pubStr, pubsublarge)
				if len(opts1) == 0 {
					break
				}
			}

			printColor("\n pubsub in: "+sdir, BLUE)

			if subdir != "" {
				retData, err := runCmd("cd "+sdir+pubsubdir+" && ls | grep -i "+subdir, false, false)
				if err != nil {
					continue
				}
				lines := strings.Split(retData, "\n")
				n := len(lines)
				for _, sub := range lines[:n-1] {
					if strings.Contains(sub, ".sock") || strings.Contains(sub, ".conf") || sub == "" {
						continue
					}
					subdir = sub
					pubsubSvs(sdir, pubsubdir, subdir)
				}
			} else {
				pubsubSvs(sdir, pubsubdir, subdir)
			}
			closePipe(true)
		}
	}
}

// - end of pubsub

// - system

func runSystem(sysOpt string) {
	opts, err := checkOpts(sysOpt, sysopts)
	if err != nil {
		fmt.Println("runSystem:", err)
	}

	for _, opt := range opts {
		if opt == "newlog" {
			getLogStats()
		} else if opt == "volume" {
			getVolume()
		} else if opt == "app" {
			getSysApp()
		} else if opt == "datastore" {
			getDataStore()
		} else if opt == "cipher" {
			getCipher()
		} else if opt == "configitem" {
			runConfigItems()
		} else if opt == "download" {
			getDownload()
		} else if strings.HasPrefix(opt, "ps/") {
			runPS(opt)
		} else if strings.HasPrefix(opt, "shell/") {
			runShell(opt)
		} else if strings.HasPrefix(opt, "cp/") {
			runCopy(opt)
		} else if strings.HasPrefix(opt, "usb") {
			runUSB()
		} else if strings.HasPrefix(opt, "pci") {
			runPCI()
		} else if strings.HasPrefix(opt, "model") {
			runCmd("/usr/bin/spec.sh", false, true)
		} else if strings.HasPrefix(opt, "hw") {
			getHW()
		} else {
			fmt.Printf("opt %s: not supported yet\n", opt)
		}
	}
}

// getLogStats - in 'runSystem'
func getLogStats() {
	retData, err := runCmd("cat /run/newlogd/NewlogMetrics/global.json", false, false)
	if err == nil {
		prettyJSON, err := formatJSON([]byte(retData))
		if err == nil {
			printColor(" - log stats:\n", CYAN)
			fmt.Printf("%s\n", prettyJSON)
		}
	}

	retData, err = runCmd("cd /persist/newlog && du -h |tail -1|awk '{print $1}'", false, false)
	if err == nil {
		printColor("\n newlog files total size: "+retData+"\n", GREEN)
	}

	printColor(" log file directorys:\n", CYAN)
	for _, d := range logdirectory {
		retData, err := runCmd("ls "+d, false, false)
		if err != nil {
			continue
		}
		lines := strings.Split(retData, "\n")
		fmt.Printf(" %s: number of gzip files: %d\n", d, len(lines)-1)
		app := 0
		dev := 0
		var tmin, tmax, appmin, appmax int64
		n := len(lines)
		for _, l := range lines[:n-1] {
			var isApp, isDev bool
			if strings.HasPrefix(l, "app.") {
				app++
				isApp = true
			} else if strings.HasPrefix(l, "dev.") {
				dev++
				isDev = true
			}

			time1 := getFileTime(l)
			if time1 == 0 {
				continue
			}
			if isDev && (tmin == 0 || tmin > time1) {
				tmin = time1
			}
			if isDev && (tmax == 0 || tmax < time1) {
				tmax = time1
			}
			if isApp && (appmin == 0 || appmin > time1) {
				appmin = time1
			}
			if isApp && (appmax == 0 || appmax < time1) {
				appmax = time1
			}
		}
		if app == 0 && dev == 0 {
			fmt.Printf("  directory empty\n")
		} else {
			fmt.Printf("  dev files: %d, app files: %d \n", dev, app)
			if tmin > 0 || tmax > 0 {
				fmt.Printf("   dev-earliest: %v, dev-latest: %v\n", time.Unix(tmin, 0).Format(time.RFC3339), time.Unix(tmax, 0).Format(time.RFC3339))
			}
			if appmin > 0 || appmax > 0 {
				fmt.Printf("   app-earlist: %v, app-latest: %v\n", time.Unix(appmin, 0).Format(time.RFC3339), time.Unix(appmax, 0).Format(time.RFC3339))
			}
		}
	}
	fmt.Println()
}

func getFileTime(filename string) int64 {
	var fn []string
	if strings.Contains(filename, ".gz") && strings.Contains(filename, ".log.") {
		fn = strings.Split(filename, ".gz")
	}
	if len(fn) < 2 {
		return 0
	}
	fn = strings.Split(fn[0], ".log.")
	if len(fn) < 2 {
		return 0
	}
	filetime, _ := strconv.Atoi(fn[1])
	return int64(filetime / 1000)
}

func getVolume() {
	retStr, err := runCmd("ls /run/zedagent/AppInstanceConfig/*.json", false, false)
	if err != nil {
		return
	}

	jlines := strings.Split(retStr, "\n")
	n := len(jlines)
	for _, line := range jlines[:n-1] {
		retStr, err = runCmd("cat "+line, false, false)
		if err != nil {
			continue
		}
		var appinst types.AppInstanceConfig
		json.Unmarshal([]byte(retStr), &appinst)
		for _, vol := range appinst.VolumeRefConfigList {
			printColor("\n - App "+appinst.DisplayName, CYAN)
			fmt.Printf("  volume config, ID: %s\n", vol.VolumeID.String())

			retStr, err = runCmd("cat /run/zedagent/VolumeConfig/"+vol.VolumeID.String()+"*.json", false, false)
			if err != nil {
				continue
			}
			var vol1 types.VolumeConfig
			json.Unmarshal([]byte(retStr), &vol1)
			fmt.Printf("   name: %s, ID %s, RefCount: %d \n", vol1.DisplayName, vol1.VolumeID.String(), vol1.RefCount)
			retStr2, err := runCmd("ls -l "+vol1.VolumeDir+"/"+vol1.VolumeID.String()+"*", false, false)
			if err != nil {
				continue
			}
			if strings.Contains(retStr2, "qcow") {
				fmt.Println(retStr2)
			} else {
				retStr1, err := runCmd("cat "+vol1.VolumeDir+"/"+vol1.VolumeID.String()+"*.container/image-config.json", false, false)
				if err != nil {
					continue
				}
				var img v1.Image
				json.Unmarshal([]byte(retStr1), &img)
				fmt.Printf("    container:\n")
				fmt.Printf("    os: %s, cmd: %s\n", img.OS, img.Config.Cmd)
				fmt.Printf("    labels: %v\n", img.Config.Labels)
			}

			printColor("\n content tree config: "+vol1.ContentID.String(), BLUE)
			retStr, err = runCmd("cat /run/zedagent/ContentTreeConfig/"+vol1.ContentID.String()+".json", false, false)
			var cont types.ContentTreeConfig
			json.Unmarshal([]byte(retStr), &cont)
			fmt.Printf("   url: %s, format: %s, sha: %s\n", cont.RelativeURL, cont.Format, cont.ContentSha256)
			fmt.Printf("   size: %d, name: %s\n", cont.MaxDownloadSize, cont.DisplayName)
		}
	}
}

func getSysApp() {
	memfile := "/proc/meminfo"
	if isLocal {
		memfile = "/host" + memfile
	}
	retData, err := runCmd("cat "+memfile+" | grep 'Mem'", false, false)
	if err == nil {
		printColor(" - device memory", CYAN)
		fmt.Println(retData)
	}
	retData, err = runCmd("ls /run/zedrouter/AppNetworkStatus/*.json", false, false)
	if err != nil {
		return
	}
	r := strings.Split(retData, "\n")
	n := len(r)
	for _, s := range r[:n-1] {
		retData, err = runCmd("cat "+s, false, false)
		status := strings.TrimSuffix(retData, "\n")
		appuuid := doAppNet(status, "", true)
		retData, err = runCmd("cat /run/domainmgr/DomainMetric/"+appuuid+".json", false, false)
		if err == nil {
			var metric types.DomainMetric
			json.Unmarshal([]byte(retData), &metric)
			fmt.Printf("    CPU: %d, Used Mem(MB): %d, Avail Mem(BM): %d\n",
				metric.CPUTotalNs, metric.UsedMemory, metric.AvailableMemory)
		}

		retData, err = runCmd("cat /run/zedmanager/DomainConfig/"+appuuid+".json", false, false)
		if err != nil {
			continue
		}
		printColor("\n  - vnc/log info:", GREEN)
		var config types.DomainConfig
		json.Unmarshal([]byte(retData), &config)
		fmt.Printf("    VNC enabled: %v, VNC display id: %d, Applog disabled: %v\n",
			config.EnableVnc, config.VncDisplay, config.DisableLogs)
	}
}

func getDataStore() {
	retStr, err := runCmd("ls /run/zedagent/DatastoreConfig/*.json", false, false)
	if err != nil {
		return
	}

	printColor(" - DataStore:", CYAN)
	lines := splitLines(retStr)
	for _, l := range lines {
		retStr1, err := runCmd("cat "+l, false, false)
		if err != nil {
			continue
		}
		var data types.DatastoreConfig
		json.Unmarshal([]byte(retStr1), &data)
		if data.IsCipher {
			fmt.Printf("   Cipher Context ID: %s, Cipher Hash: %s\n",
				data.CipherContextID, base64.StdEncoding.EncodeToString(data.ClearTextHash))
		}
		fmt.Printf("\n   FQDN: %s, Path: %s, DS Type: %s, Is Cipher: %v\n", data.Fqdn, data.Dpath, data.DsType, data.IsCipher)
		if len(data.DsCertPEM) > 0 {
			for _, c := range data.DsCertPEM {
				printCert(c)
			}
		}
	}
}

func getHW() {
	printTitle("HW:", CYAN, false)
	addPackage("lshw", "lshw")
	runCmd("lshw -json", false, true)
}

func runUSB() {

	printTitle("USB:", CYAN, false)
	runCmd("apk add usbutils", false, false)
	retStr, err := runCmd("lsusb -v", false, false)
	if err != nil {
		fmt.Printf("%v\n", err)
	} else {
		fmt.Printf("%s\n", retStr)
	}
}

func runPCI() {

	printTitle("PCI:", CYAN, false)
	addPackage("lspci", "pciutils")
	retStr, err := runCmd("lspci -v", false, false)
	if err != nil {
		fmt.Printf("%v\n", err)
	} else {
		fmt.Printf("%s\n", retStr)
	}
}

func getCipher() {
	retStr, err := runCmd("ls -lt /persist/certs", false, false)
	if err == nil {
		printColor(" - /persist/certs:\n", CYAN)
		fmt.Println(retStr)
	}

	certType := map[types.CertType]string{
		types.CertTypeOnboarding:      "onboarding",
		types.CertTypeRestrictSigning: "signing",
		types.CertTypeEk:              "Ek",
		types.CertTypeEcdhXchange:     "EdchXchange",
	}

	printColor(" - Additional CA-Certificates:\n", CYAN)
	runCmd("ls -l /etc/ssl/certs/ | grep '/usr/local/share'", true, true)

	retStr, err = runCmd("ls /run/zedagent/DatastoreConfig/", false, false)
	if err == nil {
		printColor("\n - DataStore Config:", CYAN)
		lines := splitLines(retStr)
		for _, l := range lines {
			if !strings.HasSuffix(l, ".json") {
				continue
			}
			retStr1, err := runCmd("cat /run/zedagent/DatastoreConfig/"+l, false, false)
			if err != nil {
				continue
			}
			var data types.DatastoreConfig
			json.Unmarshal([]byte(retStr1), &data)
			fmt.Printf(" %s:\n", getJsonFileID(l))
			fmt.Printf("  type: %s, FQDN: %s, ApiKey: %s, path: %s, Is Cipher: %v\n",
				data.DsType, data.Fqdn, data.ApiKey, data.Dpath, data.IsCipher)
			if len(data.DsCertPEM) > 0 {
				for _, c := range data.DsCertPEM {
					printCert(c)
				}
			}
		}
	}

	retStr, err = runCmd("ls /run/domainmgr/CipherBlockStatus/", false, false)
	if err == nil {
		printColor("\n - Domainmgr CipherBlock:", CYAN)
		lines := splitLines(retStr)
		for _, l := range lines {
			if !strings.HasSuffix(l, ".json") {
				continue
			}
			retStr1, err := runCmd("cat /run/domainmgr/CipherBlockStatus/"+l, false, false)
			if err != nil {
				continue
			}
			var data types.CipherBlockStatus
			json.Unmarshal([]byte(retStr1), &data)
			fmt.Printf(" %s:\n", getJsonFileID(l))
			fmt.Printf("  ID: %s, Is Cipher: %v\n", data.CipherBlockID, data.IsCipher)
			retStr2, err := runCmd("ls /run/domainmgr/cloudinit/"+data.CipherBlockID+".cidata", false, false)
			if err == nil {
				if len(retStr2) > 0 {
					fmt.Printf("   cloudinit file: %s\n", retStr2)
				}
			}
		}
	}

	retStr, err = runCmd("ls /persist/status/tpmmgr/EdgeNodeCert/*.json", false, false)
	if err == nil {
		printColor("\n - TPMmgr Edgenode Certs:", CYAN)
		lines := splitLines(retStr)
		for _, l := range lines {
			retStr1, err := runCmd("cat "+l, false, false)
			if err != nil {
				continue
			}
			var data types.EdgeNodeCert
			json.Unmarshal([]byte(retStr1), &data)
			fmt.Printf(" %s:\n", getJsonFileID(l))
			fmt.Printf("  hash Algo: %d, Cert ID: %s, Cert Type: %s, Is TPM: %v\n",
				data.HashAlgo, base64.StdEncoding.EncodeToString(data.CertID), certType[data.CertType], data.IsTpm)
			printCert(data.Cert)
		}
	}

	retStr, err = runCmd("ls /persist/status/zedagent/CipherContext/*.json", false, false)
	if err == nil {
		printColor("\n - Cipher Context:", CYAN)
		lines := splitLines(retStr)
		for _, l := range lines {
			retStr1, err := runCmd("cat "+l, false, false)
			if err != nil {
				continue
			}
			var data types.CipherContext
			json.Unmarshal([]byte(retStr1), &data)
			fmt.Printf(" %s:\n", getJsonFileID(l))
			fmt.Printf("  ID: %s, Device Cert Hash: %s\n",
				data.ContextID, base64.StdEncoding.EncodeToString(data.DeviceCertHash))
			fmt.Printf("  Controller Cert Hash: %s\n", base64.StdEncoding.EncodeToString(data.ControllerCertHash))
		}
	}

	retStr, err = runCmd("ls /persist/status/zedagent/ControllerCert/*.json", false, false)
	if err == nil {
		printColor("\n - Controller Certs:", CYAN)
		lines := splitLines(retStr)
		for _, l := range lines {
			retStr1, err := runCmd("cat "+l, false, false)
			if err != nil {
				continue
			}
			var data types.ControllerCert
			json.Unmarshal([]byte(retStr1), &data)
			fmt.Printf(" %s:\n", getJsonFileID(l))
			fmt.Printf("  hash Algo: %d, Type: %d, hash %s\n",
				data.HashAlgo, data.Type, base64.StdEncoding.EncodeToString(data.CertHash))
			printCert(data.Cert)
		}
	}
}

func printCert(certdata []byte) {
	block, _ := pem.Decode(certdata)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("cert err %v\n", err)
		return
	}
	fmt.Printf("    subject: %s, serial: %d, valid until: %v\n", cert.Subject, cert.SerialNumber, cert.NotAfter)
	fmt.Printf("     issuer: %s\n", cert.Issuer)
}

func runConfigItems() {
	printColor(" - global settings:", CYAN)
	// make a fake path. edge-view container does not have this mounted
	// getConfigItems() reads this file
	fakedir := "/hostfs/sys/fs/cgroup/memory/eve"
	if _, err := os.Stat(fakedir); os.IsNotExist(err) {
		os.MkdirAll(fakedir, 0664)
	}
	fakefile := fakedir + "/memory.soft_limit_in_bytes"
	if _, err := os.Stat(fakefile); os.IsNotExist(err) {
		ff, err := os.Create(fakedir+"/memory.soft_limit_in_bytes")
		if err == nil {
			ff.WriteString("786432000")
			ff.Close()
		}
	}
	configitems := getConfigItems()

	configMap := types.NewConfigItemSpecMap()
	// global
	for k, g := range configitems.GlobalSettings {
		//fmt.Printf("key: %s; value %v\n", k, g)
		s := configMap.GlobalSettings[k]
		s1 := types.ConfigItemValue{
			ItemType: s.ItemType,
			IntValue: s.IntDefault,
			StrValue: s.StringDefault,
			BoolValue: s.BoolDefault,
			TriStateValue: s.TriStateDefault,
		}
		if getCfgValue(g) == getCfgValue(s1) {
			buff := fmt.Sprintf(" %s: %s\n", k, getCfgValue(g))
			fmt.Printf("%s", buff)
		} else {
			buff := fmt.Sprintf(" %s: %s; default %s\n", k, getCfgValue(g), getCfgValue(s1))
			printColor(buff, YELLOW)
		}
		//fmt.Printf("   default: %v\n", configMap.GlobalSettings[k])
	}

	// agent
	printColor("\n - agent settings:", CYAN)
	for k, g := range configitems.AgentSettings {
		printColor("  "+k+":  ", RED)
		for k1, g1 := range g {
			fmt.Printf("    %s, %s\n", k1, getCfgValue(g1))
		}
	}
}

func getConfigItems() types.ConfigItemValueMap {
	var cfgItem types.ConfigItemValueMap
	retStr, err := runCmd("cat /persist/status/zedagent/ConfigItemValueMap/global.json", false, false)
	if err != nil {
		return cfgItem
	}
	json.Unmarshal([]byte(retStr), &cfgItem)
	return cfgItem
}

func getCfgValue(g types.ConfigItemValue) string {
	value := ""
	switch g.ItemType {
	case types.ConfigItemTypeInt:
		value = strconv.Itoa(int(g.IntValue))
	case types.ConfigItemTypeBool:
		value = strconv.FormatBool(g.BoolValue)
	case types.ConfigItemTypeString:
		value = g.StrValue
	case types.ConfigItemTypeTriState:
		if g.TriStateValue == types.TS_NONE {
			value = "None"
		} else if g.TriStateValue == types.TS_DISABLED {
			value = "Disabled"
		} else if g.TriStateValue == types.TS_ENABLED {
			value = "Enabled"
		} else {
			value = "un-supported"
		}
	default:
		value = "un-supported"
	}
	return value
}

func getDownload() {
	pubsubSvs("/run/", "volumemgr", "DownloaderConfig")
	pubsubSvs("/run/", "downloader", "DownloaderStatus")

	getMetricsMap("/run/downloader/MetricsMap/", nil, true)
	checkDownload("/persist/downloads")
	checkDownload("/persist/vault/downloader")
	checkDownload("/persist/vault/verifier")
}

func runPS(opt string) {
	var item string
	if strings.Contains(opt, "ps/") {
		opts := strings.SplitN(opt, "ps/", 2)
		item = opts[1]
	}
	runCmd("ps aux | grep "+item, false, true)
}

func checkDownload(dir string) {
	retStr, err := runCmd("ls -lR "+dir+" | grep root | grep -v drwx | grep -v dr-x | awk '{print $9}'", false, false)
	if err != nil || len(retStr) == 0 {
		return
	}
	printColor(" - in "+dir, CYAN)
	lines := splitLines(retStr)
	for _, jfile := range lines {
		retStr, err := runCmd("cd "+dir+" && find . -name "+jfile+" -print", false, false)
		if err != nil {
			continue
		}
		paths := strings.SplitN(retStr, "./", 2)
		if len(paths) < 2 {
			continue
		}
		path := paths[1]
		retStr, err = runCmd("ls -l "+dir+"/"+path, false, false)
		if err == nil {
			fmt.Printf("%s\n", retStr)
		}
	}
}

func runShell(opt string) {
	shell := strings.SplitN(opt, "shell/", 2)
	if len(shell) != 2 {
		fmt.Printf("shell needs a / and command input\n")
		return
	}
	printColor(" - shell cmd: "+shell[1], CYAN)
	runCmd(shell[1], false, true)
}

func runCopy(opt string) {
	path := strings.SplitN(opt, "cp/", 2)
	if len(path) != 2 {
		fmt.Printf("cp needs a cp/ and path input\n")
		return
	}
	file := path[1]
	info, err := os.Stat(file)
	if err != nil {
		fmt.Printf("os stat error %v\n", err)
		return
	}
	//fmt.Printf("file info %+v\n", info)
	cfile := copyFile{
		Name: info.Name(),
		Size: info.Size(),
		ModTsec: info.ModTime().Unix(),
		Sha256: fmt.Sprintf("%x", getFileSha256(file)),
	}
	jbytes, err := json.Marshal(cfile)
	if err != nil {
		fmt.Printf("json marshal error %v\n", err)
		return
	}
	websocketConn.WriteMessage(websocket.BinaryMessage, jbytes)

	// server side set
	isSvrCopy = true
	copyMsgChn = make(chan []byte)
	//websocketConn.SetReadDeadline(time.Now().Add(60 * time.Second))
	ahead := make(chan struct{})
	done := make(chan struct{})
	t := time.NewTimer(30 * time.Second)
	readerRunning := true

	go func() {
		for {
			select {
			case message := <-copyMsgChn:
				if !strings.Contains(string(message), StartCopyMessage) {
					fmt.Printf("webc read message. %s\n", string(message))
					//websocketConn.SetReadDeadline(time.Time{})
					readerRunning = false
					if !isClosed(ahead) {
						close(ahead)
					}
					isSvrCopy = false
					return
				} else {
					//fmt.Printf("start file transfer\n")
					close(ahead)
				}

			case <-t.C:
				readerRunning = false
				if !isClosed(ahead) {
					close(ahead)
				}
				isSvrCopy = false
				return

			case <- done:
				t.Stop()
				isSvrCopy = false
				return
			}
		}
	}()

	<- ahead
	if !readerRunning {
		return
	}
	f, err := os.Open(file)
	if err != nil {
		fmt.Printf("os open error %v\n", err)
		return
	}
	defer f.Close()

	buffer := make([]byte, 8192)
	totalBytes := 0
	for {
		n, err := f.Read(buffer)
		if err != nil {
			fmt.Printf("file read error %v\n", err)
			return
		}
		websocketConn.WriteMessage(websocket.BinaryMessage, buffer[:n])
		totalBytes += n
		if totalBytes >= int(cfile.Size) {
			break
		}
	}
	close(done)
}

func isClosed(c chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
	}
	return false
}

func getFileSha256(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		fmt.Printf("os open error %v\n", err)
		return nil
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		fmt.Printf("sha256 error %v\n", err)
		return nil
	}
	return h.Sum(nil)
}

func getCopyFile(msg []byte, fstatus *fileCopyStatus, mtype int) {
	var info copyFile
	if !fstatus.gotFileInfo {
		err := json.Unmarshal(msg, &info)
		if err != nil {
			//sendCopyErr("json unmarshal info file", err)
			// print the device info first
			fmt.Printf("%s\n", []byte(msg))
			return
		}

		fstatus.filename = info.Name
		fstatus.fileSize = info.Size
		fstatus.fileHash = info.Sha256
		fstatus.modTime = time.Unix(info.ModTsec, 0)
		fstatus.buf = make([]byte, info.Size)
		//fmt.Printf("json msg %s\n", string(msg))
		fmt.Printf("file: name %s, size %d\n", fstatus.filename, fstatus.fileSize)
		fstatus.gotFileInfo = true

		_, err = os.Stat(FileCopyDir)
		if err != nil {
			sendCopyErr("file stat ", err)
			return
		}
		fstatus.f, err = os.Create(FileCopyDir+fstatus.filename)
		if err != nil {
			sendCopyErr("file create", err)
			return
		}
		err = websocketConn.WriteMessage(websocket.TextMessage, []byte(StartCopyMessage))
		if err != nil {
			sendCopyErr("write start copy failed", err)
		}
		return
	}
	if mtype == websocket.TextMessage {
		fmt.Printf("recv test msg, exit\n")
		isCopy = false
		return
	}
	n, err := fstatus.f.Write(msg)
	if err != nil {
		isCopy = false
		fmt.Printf("file write error: %v\n", err)
		return
	}
	fstatus.currSize += int64(n)
	if fstatus.currSize >= fstatus.fileSize {
		fstatus.f.Close()
		shaStr := fmt.Sprintf("%x", getFileSha256(FileCopyDir+fstatus.filename))
		if shaStr == fstatus.fileHash {
			fmt.Printf("\n done. file sha256 verified\n")
			os.Chtimes(FileCopyDir+fstatus.filename, fstatus.modTime, fstatus.modTime)
		} else {
			fmt.Printf("\n file sha256 different. %s, should be %s\n", shaStr, fstatus.fileHash)
		}
		sendCopyErr("done", nil)
	}
}

func sendCopyErr(context string, err error) {
	if err != nil {
		fmt.Printf("%s error: %v\n", context, err)
	}
	websocketConn.WriteMessage(websocket.TextMessage, []byte(context))
	isCopy = false
}
// - end of system

// - log search

func runLogSearch(pattern string) {
	timeline := timeout
	fmt.Printf("log pattern %s, time %s, json %v, extraline %d, type %s\n",
		pattern, timeline, logjson, extralog, querytype)

	if !strings.Contains(timeline, "-") {
		fmt.Printf("log time needs to have dash between start and end\n")
		return
	}

	now := time.Now().Unix()
	// t1 >= t2 int64
	t1, t2 := getTimeSec(timeline, now)

	gfiles := walkLogDirs(t1, t2, now)

	op := " | grep -E "
	if extralog > 0 {
		op = " | grep -A " + strconv.Itoa(extralog) + " -B " + strconv.Itoa(extralog) + " -E "
	}
	for _, gf := range gfiles {
		cmd := "zcat " + gf.filepath + op + pattern
		olines, err := runCmd(cmd, true, false)
		if err == nil && len(olines) > 0 {
			bout := fmt.Sprintf("\n %s, -- %v --\n", gf.filepath, time.Unix(gf.filesec, 0).Format(time.RFC3339))
			printColor(bout, RED)

			colorMatch(olines, pattern)
		}
	}

	if now - t1 < 10 { // search for collect
		if querytype != "app" {
			searchLiveLogs(pattern, now, "dev")
		}
		if querytype != "dev" {
			searchLiveLogs(pattern, now, "app")
		}
	}
	fmt.Println()
}

func walkLogDirs(t1, t2, now int64) []logfiletime {
	var getfiles []logfiletime
	toMin := int((now - t2) / 60) + 10 // give 10 min more
	fromMin := int((now - t1) / 60)
	if fromMin > 10 {
		fromMin -= 10
	}

	newlogs, err := runCmd("ls /persist/newlog", false, false)
	if err != nil {
		fmt.Printf("ls /persist/newlog error %v\n", err)
		return getfiles
	}
	logdir := strings.Split(newlogs, "\n")

	gzfiles := make(map[string][]string)  
	for _, dir := range logdirectory {
		var found bool
		for _, d := range logdir {
			if strings.Contains(dir, d) {
				found = true
				break
			}
		}
		if found {
			cmd := "cd " + dir + " && find . -mmin -" + strconv.Itoa(toMin) + " -mmin +" + strconv.Itoa(fromMin)
			lineStr, err := runCmd(cmd, false, false)
			if err == nil {
				files := strings.Split(lineStr, "\n")
				gzfiles[dir] = files
			}
		}
	}

	for k, g := range gzfiles {
		//fmt.Printf("- %s, file: %s\n", k, g)
		for _, file := range g {
			if !strings.Contains(file, "dev") && !strings.Contains(file, "app") {
				continue
			}
			if querytype == "app" && !strings.Contains(file, "app") {
				continue
			}
			if querytype == "dev" && !strings.Contains(file, "dev") {
				continue
			}
			ftime := getFileTime(file)
			if ftime == 0 {
				continue
			}
			if ftime >= t2 && ftime <= t1 {
				file1 := strings.TrimPrefix(file, "./")
				gfile := logfiletime{
					filepath: k + file1,
					filesec: ftime,
				}
				getfiles = append(getfiles, gfile)
			}
		}
	}

	sort.Slice(getfiles, func(i1, i2 int) bool {
		return getfiles[i1].filesec < getfiles[i2].filesec
	})

	return getfiles
}

func searchLiveLogs(pattern string, now int64, typeStr string) {
	retStr, err := runCmd("ls /persist/newlog/collect/", false, false)
	if err != nil {
		return
	}
	lines := strings.Split(retStr, "\n")
	if len(lines) == 0 {
		return
	}
	for _, l := range lines[:len(lines)-1] {
		if !strings.HasPrefix(l, typeStr) {
			continue
		}
		file := "/persist/newlog/collect/" + l
		searchCurrentLogs(pattern, file, typeStr, now)
	}
}

func searchCurrentLogs(pattern, path, typeStr string, now int64) {
	retStr, err := runCmd("grep " + pattern + " " + path, false, false)
	if err == nil && len(retStr) > 0 {
		bout := fmt.Sprintf("\n current " + typeStr + " log, -- %v --\n", time.Unix(now, 0).Format(time.RFC3339))
		printColor(bout, RED)

		colorMatch(retStr, pattern)
	}
}

func colorMatch(olines, pattern string) {
	lines := strings.Split(olines, "\n")
	if strings.Contains(pattern, "|") {
		pat := strings.Split(pattern, "|")
		pattern = strings.TrimSuffix(pat[0], " ")
	}
	for i, l := range lines[:len(lines)-1] {
		if logjson {
			prettyJson, err := formatJSON([]byte(l))
			if err == nil {
				buff := strings.ReplaceAll(string(prettyJson), pattern, "\033[0;93m"+pattern+"\033[0m")
				fmt.Printf(" (%d) %s\n", i+1, buff)
			}
		} else {
			var entry LogEntry
			var content LogContent
			var bufStr string
			json.Unmarshal([]byte(l), &entry)
			err := json.Unmarshal([]byte(entry.Content), &content)
			if err != nil {
				var tlog string
				if entry.Timestamp != nil {
					tlog = time.Unix(entry.Timestamp.Seconds, 0).Format(time.RFC3339)
				}
				bufStr = fmt.Sprintf(" -(%d) %s, %s, %s, %v(%d)", i+1, strings.TrimSuffix(entry.Content, "\n"), entry.Severity, entry.Source,
					tlog, entry.Msgid)
			} else {
				bufStr = fmt.Sprintf(" -(%d) %s, %s, %s, %s, %s, %s, %s(%d)",
					i+1, content.Msg, entry.Severity, entry.Filename, entry.Function, content.Objtype,
					content.Source, content.Time, entry.Msgid)
			}
			buff := strings.ReplaceAll(bufStr, pattern, "\033[0;93m"+pattern+"\033[0m")
			fmt.Printf("%s", buff)
		}
		if !directQuery && i%20 == 0 {
			closePipe(true)
		} else {
			fmt.Println()
		}
	}
}

func getTimeSec(timeline string, now int64) (int64, int64) {
	var ti1, ti2 int64
	if strings.Contains(timeline, "Z-") {
		times := strings.Split(timeline, "Z-")

		t1, err1 := time.Parse(time.RFC3339, times[0] + "Z")
		t2, err2 := time.Parse(time.RFC3339, times[1])
		if err1 == nil && err2 == nil {
			//fmt.Printf("t1 %v, t2 %v\n", t1, t2)
		}
		ti1 = t1.Unix()
		ti2 = t2.Unix()
		if ti1 > now {
			ti1 = now
		}
		if ti2 > now {
			ti2 = now
		}
		
	} else {
		times := strings.Split(timeline, "-")
		f1, err1 := strconv.ParseFloat(times[0], 16)
		f2, err2 := strconv.ParseFloat(times[1], 16)
		if err1 != nil || err2 != nil {
			fmt.Printf("float error %v, %v\n", err1, err2)
		}

		ti1 = now - int64(f1 * 3600)
		ti2 = now - int64(f2 * 3600)
	}
	if ti1 >= ti2 {
		return ti1, ti2
	} else {
		return ti2, ti1
	}
}

// - end of log search

func pubsubSvs(startDir, pubsubDir, subDir string) {
	newdir := startDir + pubsubDir
	if subDir != "" {
		newdir = newdir + "/" + subDir
	}

	cmd := "cd " + newdir + " && find . -name '*.json' -print"
	retData, err := runCmd(cmd, false, false)
	if err != nil {
		fmt.Printf("pubsubSvs: error %v\n", err)
		return
	}

	files := strings.Split(retData, "\n")
	n := len(files)
	printpath := ""
	for _, f := range files[:n-1] {
		//fmt.Printf("file: %s\n", f)
		dir1 := strings.Split(f, "./")
		paths := strings.Split(dir1[1], "/")
		path := ""
		for _, p := range paths[:len(paths)-1] {
			path = path + "/" + p
		}
		if printpath != newdir+path {
			printColor("  "+newdir+path, GREEN)
			printpath = newdir + path
		}
		dirfile := newdir + "/" + dir1[1]
		fmt.Printf("   service: %s\n", paths[len(paths)-1])
		retData, err := runCmd("cat "+dirfile, false, false)
		if err != nil {
			//fmt.Printf("error: %v", err)
			continue
		}
		prettyJSON, err := formatJSON([]byte(retData))
		if err != nil {
			fmt.Printf("JsonFormet error %v\n", err)
		}

		fmt.Println(string(prettyJSON))
	}
}

func formatJSON(data []byte) ([]byte, error) {
	var out bytes.Buffer
	err := json.Indent(&out, data, "", "    ")
	if err == nil {
		return out.Bytes(), err
	}
	return data, nil
}

func addPackage(programName, pkgName string) error {
	retStr, err := runCmd("which "+programName, false, false)
	if err == nil {
		if len(retStr) > 0 {
			fmt.Printf("%s\n", retStr)
		}
	} else {
		retStr, err = runCmd("apk add "+pkgName, false, false)
		if err != nil {
			fmt.Printf("%v\n", err)
			return err
		}
	}
	return nil
}

func runCmd(cmd string, isEve, isPrint bool) (string, error) {
	if isEve && !isLocal {
		cmd = "eve exec pillar " + cmd + " 2&>1"
	}
	var retStr string
	var retBytes []byte
	var err error
	if isLocal {
		retBytes, err = exec.Command("sh", "-c", cmd).Output()
		if err == nil {
			retStr = string(retBytes)
		}
	} else {
		retStr, err = remoteRun("root", device, sshprivkey, cmd)
	}
	if err != nil {
		if !strings.HasSuffix(err.Error(), "status 1") {
			fmt.Printf("error: %v\n", err)
		}
	} else {
		if isPrint {
			fmt.Println(retStr)
			closePipe(true)
		}
	}
	return retStr, err
}

func printColor(msg, color string) {
	fmt.Printf(color, msg)
	fmt.Println("")
}

func printTitle(msg, color string, sendnow bool) {
	printColor(msg, color)
	if sendnow {
		closePipe(true)
	}
}

func splitLines(inStr string) []string {
	outStr := strings.Split(inStr, "\n")
	n := len(outStr)
	return outStr[:n-1]
}

func getJsonFileID(path string) string {
	strs := strings.Split(path, "/")
	n := len(strs)
	if n > 0 {
		filename := strs[n-1]
		fileid := strings.Split(filename, ".json")
		if len(fileid) > 0 {
			return fileid[0]
		}
	}
	return ""
}

func printHelp(opt string) {
	if opt == "" {
		log.Println(helpStr)
		fmt.Printf("  pub/ %v\n\n", pubsubopts)
		fmt.Printf("  %v\n", netopts)
		fmt.Printf("  %v\n", sysopts)
	} else {
		fmt.Printf("\n")
		switch opt {
		// network
		case "acl":
			helpOn("acl[/<filter>]", "to display all filters of running and configured ACL")
			helpExample("acl", "display all filters of ACL", true)
			helpExample("acl/nat", "display in table nat of ACL", false)
		case "app":
			helpOn("app[/app-string]", "to display all the app or one specific app")
			helpExample("app", "display all apps in brief", true)
			helpExample("app/iot", "display a specific app, which app name has substring of iot in more detail", false)
		case "arp":
			helpOn("arp[/filter]", "to display all the arp entry or with filter matching")
			helpExample("arp", "display all arp entries", true)
			helpExample("arp/192.168", "display all arp entries contain 192.168 string", false)
		case "connectivity":
			helpOn("connectivity", "run diag on ports, and display the port config list")
		case "flow":
			helpOn("flow[/<some patten>]", "display ip flow information in the kernel search patten")
			helpExample("flow/sport=53", "display all the ip flow matches source port of 53", true)
			helpExample("flow/10.1.0.2", "display all the ip flow matches ip address of 10.1.0.2", false)
		case "if":
			helpOn("if[/intf-name]", "display interface related information briefly")
			helpExample("if/eth0", "display interface eth0 related information", true)
		case "mdns":
			helpOn("mdns[/intf-name][/service]", "display zeroconfig related information")
			helpExample("mdns/eth0", "display mDNS for default service 'workstation' on interface 'eth0'", true)
			helpExample("mdns/bn1/https", "display mDNS for service 'https' on bridge 'bn1'", false)
			helpExample("mdns", "display mDNS for default service 'workstation' on all UP interafces", false)
		case "nslookup":
			helpOn("nslookup[/<ip or name>]", "display domain name and dns server information")
			helpExample("nslookup/www.amazon.com", "display DNS information on www.amazon.com", true)
			helpExample("nslookup/8.8.8.8", "display DNS inforamtion on address 8.8.8.8", false)
		case "ping":
			helpOn("ping[/<ip or name>]", "ping to 8.8.8.8 from all the UP interfaces or ping a specific address")
			helpExample("ping", "ping to 8.8.8.8 from each source IP address of the intefaces", true)
			helpExample("ping/192.168.1.1", "ping the address of 192.168.1.1", false)
		case "proxy":
			helpOn("proxy", "https proxy service by pointing your browser to the proxy server address:port printed")
		case "route":
			helpOn("route", "display all the ip rule and their ip table entries")
		case "socket":
			helpOn("socket", "display all the ipv4 litening socket ports and established ports")
		case "speed":
			helpOn("spped[/intf-name]", "run speed test and report the download and upload speed")
			helpExample("speed/wlan0", "run speed test on interface wlan0", true)
		case "tcp":
			helpOn("tcp/ip-address:port[/ip-address:port...]", "tcp connection to the ip addresses for services, local mapping ports 9001 and above")
			helpExample("tcp/192.168.1.1:8080", "points your browser to the locally listening port and http browsing 192.168.1.1:8080", true)
			helpExample("tcp/10.1.0.2:80/10.1.0.2:8081", "points your browser to the locally listening ports and http browsing remote 10.1.0.2 both 80 and 8081 ports", false)
		case "tcpdump":
			helpOn("tcpdump/intf-name/[options]", "tcpdump on the interface, can specify duration with -time, default is 60 sec")
			helpExample("tcpdump/eth0/", "run tcpdump on eth0 with default 60 seconds or maximum of 100 entries", true)
			helpExample("'tcpdump/eth0/port 443' -time 10", "run tcpdump on eth0 and port 443 with 10 seconds", false)
		case "trace":
			helpOn("trace[/<ip or name>]", "traceroute to www.google.com and zedcloud server, or to specified ip or name, 10 hops limit")
			helpExample("trace", "traceroute to www.google.com and to zedcloud server", true)
			helpExample("trace/www.microsoft.com", "run traceroute to www.microsoft.com", false)
		case "url":
			helpOn("url", "display url metrics for zedclient, zedagent, downloader and loguploader")
		case "wireless":
			helpOn("wireless", "display the iwconfig wlan0 info and wpa_supplicant.conf content")
		// system
		case "configitem":
			helpOn("configitem", "display the device configitem settings, highlight the non-default values")
		case "cp":
			helpOn("cp/<path>", "copy file from the device to locally mounted directory by specify the path")
			helpExample("cp//config/device.cert.pem", "copy the /config/device.cert.pem file to local directory", true)
			helpExample("cp//persist/newlog/keepSentQueue/dev.log.1630451424116.gz", "copy file with path to local directory", false)
		case "datastore":
			helpOn("datastore", "display the device current datastore: EQDN, type, cipher information")
		case "download":
			helpOn("download", "display the download config and status during downloading operation and url stats since reboot")
		case "hw":
			helpOn("hw", "display the hardware from lshw information in json format")
		case "model":
			helpOn("model", "display the hardware model information in json format")
		case "newlog":
			helpOn("newlog", "display the newlog statistics and file information in each of the newlog directory and disk usage")
		case "pci":
			helpOn("pci", "display the lspci information on device")
		case "ps":
			helpOn("ps/<string>", "display the process status information on matching string")
			helpExample("ps/containerd", "display the processes with name of containerd", true)
		case "cipher":
			helpOn("cipher", "display cipher information on datastore, device and controller certificates, etc.")
		case "usb":
			helpOn("usb", "display the lsusb information on device")
		case "shell":
			helpOn("shell/<some command>", "run shell on the command supplied on the device")
			helpExample("'shell/ls -l /run/nim'", "run 'ls -l /run/nim' command on device", true)
			helpExample("'shell/cat /config/server'", "run 'cat /config/server' command on device", false)
		case "volume":
			helpOn("volume", "display the app volume and content tree information for each app")
		// log
		case "log":
			helpOn("log/<search string> [-time <start>-<end>] [-json] [-type <app|dev>]", "display log with search-string, default is now to 30 mins ago")
			helpExample("log/panic -time 0.2-2.5", "display log contains 'panic', from 0.2 to 0.5 hours ago", true)
			helpExample("log/Clock -type app", "display previous 30 minutes log contains 'Clock' in app log", false)
			helpExample("log/certificate -time 2021-08-15T23:15:29Z-2021-08-15T22:45:00Z -json",
				"display log during the specified time in RFC3339 format which contains 'certificate' in json format", false)
		default:
			printHelp("")
		}
	}
}

func openPipe() (*os.File, *os.File, error) {
	if socketOpen {
		return nil, nil, fmt.Errorf("socket already opened\n")
	}
	oldStdout = os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		fmt.Printf("os.Pipe: %v\n", err)
		return nil, nil, err
	}
	os.Stdout = w
	socketOpen = true

	return r, w, nil
}

func closePipe(openAfter bool) {
	if !socketOpen {
		return
	}
	writeP.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	io.Copy(&buf, readP)
	socketOpen = false

	if websocketConn != nil && len(buf.String()) > 0 {
		err := websocketConn.WriteMessage(websocket.TextMessage, []byte(buf.String()))
		if err != nil {
			log.Println("write:", err)
			return
		}
		wsMsgCount++
		wsSentBytes += len(buf.String())
	}
	if openAfter {
		var err error
		readP, writeP, err = openPipe()
		if err != nil {
			fmt.Printf("open pipe error %v\n", err)
		}
	}
}

func helpOn(str1, str2 string) {
	fmt.Printf(" %s  -  %s\n", str1, str2)
}

func helpExample(str1, str2 string, printEG bool) {
	egStr := "    "
	if printEG {
		egStr = "e.g."
	}
	fmt.Printf("  %s %s  -- %s\n", egStr, str1, str2)
}