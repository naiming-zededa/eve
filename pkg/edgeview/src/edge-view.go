package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
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
	runOnServer   bool       // container running inside remote linux host
	directQuery   bool       // container using ssh-mode
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
	isTCPServer   bool
	isCopy        bool           // client side
	isSvrCopy     bool           // server side
	copyMsgChn    chan []byte
	tcpMsgChn     chan wsMessage
	tcpDataChn    []chan tcpData
	tcpServerDone chan struct{}
)

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

func main() {
	wsAddr := flag.String("ws", "", "http service address")
	phelpopt := flag.Bool("help", false, "command-line help")
	phopt := flag.Bool("h", false, "command-line help")
	pdevip := flag.String("device", "", "device ip option")
	pServer := flag.Bool("server", false, "service edge-view queries")
	ptoken := flag.String("token", "", "session token")
	pDebug := flag.Bool("debug", false, "log more in debug")
	flag.Parse()
	//log.SetFlags(0)
	//formatter := log.JSONFormatter{
	//	TimestampFormat: time.RFC3339Nano,
	//}
	log.SetFormatter(&log.TextFormatter{})

	if *pServer {
		runOnServer = true
	}
	if *pdevip != "" && !runOnServer {
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

	if *ptoken != "" && runOnServer {
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
		} else if strings.HasSuffix(word, "-debug") {
			*pDebug = true
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

	if *pDebug {
		log.SetLevel(log.DebugLevel)
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
			if directQuery {
				fmt.Printf("tcp is not supported in ssh mode\n")
				return
			}
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
			if directQuery {
				fmt.Printf("proxy is not supported in ssh mode\n")
				return
			}
			isTCPClient = true
			fmt.Printf("proxy server locally listening on: 0.0.0.0:9001\n")
			pnetopt = pqueryopt
		} else if strings.HasPrefix(pqueryopt, "cp/") {
			if directQuery {
				fmt.Printf("cp is not supported in ssh mode\n")
				return
			}
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
		if !runOnServer {
			hostname = os.Getenv("HOSTNAME")
		} else {
			hostname = getHostname()
		}
		fmt.Printf("%s connecting to %s\n", hostname, urlSt.String())
		ok := setupWebC(hostname, *ptoken, urlSt, runOnServer)
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

	if *ptoken != "" && !runOnServer && !directQuery {
		cmdStr = cmdStr + "-token=" + *ptoken + "+++"
		cmdSlice = append(cmdSlice, "-token=" + *ptoken)
	}
	cmdSlice = append(cmdSlice, "")

	if directQuery { // ssh query mode
		parserAndRun(cmdSlice)
		return
	} else if runOnServer {
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
				if isSvrCopy {
					copyMsgChn <- message
					continue
				} else if isTCPServer {
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
						log.Debugf("tcpConnMap(%d) has no chan %d on server, launch\n", mid, jmsg.ChanNum)
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
	} else { // query client in websocket mode
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
							log.Info("reset by peer, try reconnect %v", time.Now())
							websocketConn.Close()
							tcpRetryWait = true
							time.Sleep(100 * time.Millisecond)
							ok := setupWebC(hostname, *ptoken, urlSt, false)
							tcpRetryWait = false
							if ok {
								continue
							} else {
								log.Info("retry failed. exit")
							}
						}
					}
					return
				}
				if strings.Contains(string(message), CloseMessage) {
					log.Infof("%s\nreceive message done\n", string(message))
					done <- struct{}{}
					break
				} else if isTCPClient {
					if mtype == websocket.TextMessage {
						log.Debugf("setup tcp client: %s\n", message)
						if !tcpClientRun { // got ok messsage from tcp server side, run client
							if bytes.Contains(message, []byte(TCPSetupOKMessage)) {
								tcpClientsLaunch(tcpclientCnt, remotePorts)
							}
						} else {
							log.Infof(" tcp client running, receiving close probably due to server timed out: %v\n", string(message))
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
					fmt.Printf("%s\n", message)
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