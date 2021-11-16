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
	"os/signal"
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
	EdgeViewVersion   = "0.8.0"
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

type cmdOpt struct {
	Version      string     `json:"version"`
	DevIPAddr    string     `json:"devIPAddr"`
	Network      string     `json:"network"`
	System       string     `json:"system"`
	Pubsub       string     `json:"pubsub"`
	Logopt       string     `json:"logopt"`
	Timerange    string     `json:"timerange"`
	IsJson       bool       `json:"isJson"`
	Extraline    int        `json:"extraline"`
	Logtype      string     `json:"logtype"`
	SessToken    string     `json:"sessToken"`
}

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
	log.SetFormatter(&log.TextFormatter{})

	if *pServer {
		runOnServer = true
	}
	if *pdevip != "" && !runOnServer {
		directQuery = true
	}

	if directQuery { // ssh-mode
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
	// the reason for this loop to get our own params is that it allows
	// some options do not have to specify the "-something" in the front.
	// the flag does not allow this.
	// for example, put all the common usage in a script:
	// ./myscript.sh log/<pattern>
	// or ./myscript.sh log/<pattern> -time 0.2-0.5 -json
	// or ./myscript.sh -device <ip-addr> route
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

	// query option syntax checks
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
				if tcpclientCnt > TCPMaxMappingNUM {
					log.Println("tcp maximum mapping is: ", TCPMaxMappingNUM)
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
				} else if pStr == "proxy" {
					remotePorts[i] = 0
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

	urlWSS := url.URL{Scheme: "wss", Host: *wsAddr, Path: "/edge-view"}

	var done chan struct{}
	hostname := ""
	if !directQuery {
		if !runOnServer {
			hostname = os.Getenv("HOSTNAME")
		} else {
			hostname = getHostname()
		}
		fmt.Printf("%s connecting to %s\n", hostname, urlWSS.String())
		ok := setupWebC(hostname, *ptoken, urlWSS, runOnServer)
		if !ok {
			return
		}
		defer websocketConn.Close()
		done = make(chan struct{})
	}

	queryCmds := cmdOpt{
		Version:    EdgeViewVersion,
		DevIPAddr:  *pdevip,
		Network:    pnetopt,
		System:     psysopt,
		Pubsub:     ppubsubopt,
		Logopt:     logopt,
		Timerange:  timeopt,
		IsJson:     jsonopt,
		Extraline:  extraopt,
		SessToken:  *ptoken,
	}
	if typeopt != "all" {
		queryCmds.Logtype = typeopt
	}

	if directQuery { // ssh query mode
		parserAndRun(queryCmds)
		return
	} else if runOnServer { // websocket mode on device 'server' side
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
						ok := setupWebC(hostname, *ptoken, urlWSS, true)
						tcpRetryWait = false
						if ok {
							continue
						}
					}
					return
				}

				var recvCmds cmdOpt
				var isJson bool
				if mtype == websocket.TextMessage {
					err := json.Unmarshal(message, &recvCmds)
					if err != nil {
						log.Printf("recv not json msg: %s\n", message)
					} else {
						printCmds := recvCmds
						printCmds.SessToken = ""
						log.Printf("recv: %+v", printCmds)
						isJson = true
					}
					if !isJson && (strings.Contains(string(message), "no device online") ||
						strings.Contains(string(message), CloseMessage)) {
						log.Println("read: no device, continue")
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
				// process client query
				go goRunQuery(recvCmds)
			}
		}()
	} else { // query client in websocket mode
		// send the query command to websocket/server
		jdata, err := json.Marshal(queryCmds)
		if err != nil {
			log.Println("json Marshal queryCmds error", err)
			return
		}
		err = websocketConn.WriteMessage(websocket.TextMessage, jdata)
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
							ok := setupWebC(hostname, *ptoken, urlWSS, false)
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
					// print query replies
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

func goRunQuery(cmds cmdOpt) {
	var err error
	wsMsgCount = 0
	wsSentBytes = 0
	// save output to buffer
	readP, writeP, err = openPipe()
	if err == nil {
		parserAndRun(cmds)
		if isTCPServer {
			return
		}
		closePipe(false)
		err = websocketConn.WriteMessage(websocket.TextMessage, []byte(CloseMessage))
		if err != nil {
			log.Println("sent done msg error:", err)
		}
		log.Printf("Sent %d messages, total %d bytes to websocket\n", wsMsgCount, wsSentBytes)
	}
}

func parserAndRun(cmds cmdOpt) {
	if stoken != "" && stoken != cmds.SessToken {
		fmt.Printf("session authentication failed\n")
		return
	}

	if cmds.Timerange != "" {
		timeout = cmds.Timerange
	}
	device = cmds.DevIPAddr
	logjson = cmds.IsJson
	if cmds.Logtype != "" {
		querytype = cmds.Logtype
	}

	getBasics()
	if cmds.Network != "" {
		runNetwork(cmds.Network)
	} else if cmds.Pubsub != "" {
		runPubsub(cmds.Pubsub)
	} else if cmds.System != "" {
		runSystem(cmds.System)
	} else if cmds.Logopt != "" {
		runLogSearch(cmds.Logopt)
	} else {
		fmt.Printf("no supported options\n")
		return
	}
}

func intSigStart() {
	intSignal = make(chan os.Signal, 1)
	signal.Notify(intSignal, os.Interrupt)
}
