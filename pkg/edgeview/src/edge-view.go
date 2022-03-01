// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

var (
	evDevice      string     // ip-address or domain name of Edge-View device
	runOnServer   bool       // container running inside remote linux host
	directQuery   bool       // container using ssh-mode
	querytype     string
	cmdTimeout    string
	sshprivkey    []byte
	log           *base.LogObject
)

const (
	agentName         = "edgeview"
	closeMessage      = "+++Done+++"
	edgeViewVersion   = "0.8.0"
	cpLogFileString   = "copy-logfiles"
)

type cmdOpt struct {
	Version       string     `json:"version"`
	DevIPAddr     string     `json:"devIPAddr"`
	Network       string     `json:"network"`
	System        string     `json:"system"`
	Pubsub        string     `json:"pubsub"`
	Logopt        string     `json:"logopt"`
	Timerange     string     `json:"timerange"`
	IsJSON        bool       `json:"isJSON"`
	Extraline     int        `json:"extraline"`
	Logtype       string     `json:"logtype"`
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

	logger := logrus.New()
	log = base.NewSourceLogObject(logger, agentName, os.Getpid())

	if *pServer {
		runOnServer = true
	}
	if *pdevip != "" && !runOnServer {
		directQuery = true
	}

	var evStatus  types.EdgeviewStatus
	pathStr := "/edge-view"
	if directQuery { // ssh-mode
		var err error
		sshprivkey, err = ioutil.ReadFile("/ssh-private-key")
		if err != nil {
			fmt.Printf("ssh key file need to be docker mounted in '/ssh-private-key', error: %v\n", err)
			return
		}
	} else {
		// if wss endpoint is not passed in, try to get it from the JWT
		if *ptoken != "" && *wsAddr == "" {
			addrport, path, err := getAddrFromJWT(*ptoken, *pServer, &evStatus)
			if err != nil {
				fmt.Printf("%v\n", err)
				return
			}
			if path != "" {
				pathStr = path
			}
			*wsAddr = addrport
		}
		if *wsAddr == "" {
			fmt.Printf("wss address:port needs to be specified when '-token' is used\n")
			return
		}
	}

	initOpts()

	var intSignal  chan os.Signal
	var fstatus fileCopyStatus
	remotePorts := make(map[int]int)
	var tcpclientCnt int
	var pqueryopt, pnetopt, psysopt, ppubsubopt, logopt, timeopt string
	var jsonopt bool
	typeopt := "all"
	extraopt := 0
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

	if *phopt || *phelpopt {
		printHelp(pqueryopt)
		return
	}

	if *pDebug {
		logger.SetLevel(logrus.DebugLevel)
	}

	if *pdevip == "" && *ptoken == "" {
		fmt.Printf("either -device or -token option is needed\n")
		return
	}

	// query option syntax checks
	if pqueryopt != "" {
		if strings.HasPrefix(pqueryopt, "log/") {
			logs := strings.SplitN(pqueryopt, "log/", 2)
			logopt = logs[1]
			if logopt == "" {
				fmt.Printf("log/ needs search string\n")
				printHelp("")
				return
			}
			if logopt == cpLogFileString {
				if directQuery {
					fmt.Printf("log/copy-logfiles is not supported in ssh mode\n")
					return
				}
				isCopy = true
			}
		} else if strings.HasPrefix(pqueryopt, "pub/") {
			pubs := strings.SplitN(pqueryopt, "pub/", 2)
			ppubsubopt = pubs[1]
			_, err := checkOpts(ppubsubopt, pubsubopts)
			if err != nil {
				fmt.Printf("pub/ option error\n")
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
			var ok bool
			ok, tcpclientCnt, remotePorts = processTCPcmd(pqueryopt, remotePorts)
			if !ok {
				return
			}
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

			if psysopt == "techsupport" {
				if directQuery {
					fmt.Printf("techsupport is not supported in ssh mode\n")
					return
				}
				isCopy = true
			}
		}
	}

	if !runOnServer {
		// client side can break the session
		intSignal = make(chan os.Signal, 1)
		signal.Notify(intSignal, os.Interrupt)
	}
	urlWSS := url.URL{Scheme: "wss", Host: *wsAddr, Path: pathStr}

	var done chan struct{}
	hostname := ""
	if !directQuery {
		if !runOnServer {
			hostname = os.Getenv("HOSTNAME")
		} else {
			hostname = getHostname()
		}
		tokenHash16 := getTokenHashString(*ptoken)
		fmt.Printf("%s connecting to %s\n", hostname, urlWSS.String())
		// on server, the script will retry in some minutes later
		ok := setupWebC(hostname, string(tokenHash16), urlWSS, runOnServer)
		if !ok {
			return
		}
		defer websocketConn.Close()
		done = make(chan struct{})
	}

	queryCmds := cmdOpt{
		Version:       edgeViewVersion,
		DevIPAddr:     *pdevip,
		Network:       pnetopt,
		System:        psysopt,
		Pubsub:        ppubsubopt,
		Logopt:        logopt,
		Timerange:     timeopt,
		IsJSON:        jsonopt,
		Extraline:     extraopt,
	}
	if typeopt != "all" {
		queryCmds.Logtype = typeopt
	}
	if logopt != "" && timeopt == "" { // default log search is previous half an hour
		queryCmds.Timerange = "0-0.5"
	}

	// for edgeview server side to use
	var infoPub pubsub.Publication
	trigPubchan := make(chan bool, 1)
	pubStatusTimer := time.NewTimer(1 * time.Second)
	pubStatusTimer.Stop()

	// edgeview container can run in 3 different modes:
	// 1) ssh-mode, 'directQuery' is set, send out query and wait for reply from device
	// 2) non-ssh/websocket server mode, runs on device: 'runOnServer' is set
	// 3) non-ssh/websocket client mode, runs on operator/laptop side
	if directQuery { // 1) ssh query mode
		parserAndRun(queryCmds)
		return
	} else if runOnServer { // 2) websocket mode on device 'server' side

		err := initPolicy()
		if err != nil {
			return
		}

		infoPub = initpubInfo(logger)
		if infoPub == nil {
			return
		}

		go func() {
			defer close(done)
			for {
				mtype, msg, err := websocketConn.ReadMessage()
				if err != nil {
					if retryWebSocket(hostname, *ptoken, urlWSS, err) {
						continue
					}
					return
				}

				var recvCmds cmdOpt
				isJSON, verifyOK, message := verifyAuthenData(msg)
				if !isJSON {
					if strings.Contains(string(msg), "no device online") {
						log.Noticef("read: peer not there yet, continue")
					}
					continue
				}
				if !verifyOK {
					log.Noticef("authen failed on json msg")
					continue
				}

				if mtype == websocket.TextMessage {
					if strings.Contains(string(message), "no device online") ||
						strings.Contains(string(message), closeMessage) {
						log.Noticef("read: no device, continue")
						continue
					} else {
						log.Noticef("recv cmd msg: %s", message)
						if isTCPServer {
							close(tcpServerDone)
							continue
						}
					}

					err := json.Unmarshal(message, &recvCmds)
					if err != nil {
						log.Noticef("unmarshal json msg error: %v", err)
						continue
					} else {
						// check the query commands against defined policy
						ok := checkCmdPolicy(recvCmds, &evStatus)
						if !ok {
							closePipe(false)
							continue
						}
						trigPubchan <- true
					}
				}
				if isSvrCopy {
					copyMsgChn <- message
				} else if isTCPServer {
					recvClientData(mtype, message)
				} else {
					// process client query
					go goRunQuery(recvCmds)
				}
			}
		}()
	} else { // 3) websocket mode on client side

		if !clientSendQuery(queryCmds) {
			return
		}
		go func() {
			defer close(done)
			for {
				mtype, msg, err := websocketConn.ReadMessage()
				if err != nil {
					if retryWebSocket(hostname, *ptoken, urlWSS, err) {
						continue
					}
					return
				}

				isJSON, verifyOK, message := verifyAuthenData(msg)
				if !isJSON {
					fmt.Printf("%s\nreceive message done\n", string(msg))
					done <- struct{}{}
					break
				}

				if !verifyOK {
					fmt.Printf("\nverify msg failed\n")
					done <- struct{}{}
					break
				}

				if strings.Contains(string(message), closeMessage) {
					done <- struct{}{}
					break
				} else if isCopy {
					recvCopyFile(message, &fstatus, mtype)
					if mtype == websocket.TextMessage && isCopy && fstatus.f != nil {
						defer fstatus.f.Close()
					}
				} else if isTCPClient {
					if mtype == websocket.TextMessage {
						if !tcpClientRun { // got ok message from tcp server side, run client
							if bytes.Contains(message, []byte(tcpSetupOKMessage)) {
								tcpClientsLaunch(tcpclientCnt, remotePorts)
							} else {
								// this could be the tcp policy disallow the setup message
								fmt.Printf("%s\n", message)
							}
						} else {
							fmt.Printf(" tcp client running, receiving close probably due to server timed out: %v\n", string(message))
							done <- struct{}{}
							break
						}
					} else {
						recvServerData(mtype, message)
					}
				} else {
					fmt.Printf("%s", message)
				}
			}
		}()
	}

	// ssh or non-ssh client wait for replies and finishes with a 'done' or gets a Ctrl-C
	// non-ssh server will be killed when the session is expired with the script
	for {
		select {
		case <- trigPubchan:
			// not to publish the status too fast
			pubStatusTimer = time.NewTimer(15 * time.Second)
		case <-pubStatusTimer.C:
			err := infoPub.Publish("global", evStatus)
			if err != nil {
				log.Noticef("evinfopub: publish error: %v\n", err)
			}
		case <-done:
			tcpClientSendDone()
			return
		case <-intSignal:
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
		err = signAuthAndWriteWss([]byte(closeMessage), true)
		if err != nil {
			log.Noticef("sent done msg error: %v", err)
		}
		log.Noticef("Sent %d messages, total %d bytes to websocket", wsMsgCount, wsSentBytes)
	}
}

func parserAndRun(cmds cmdOpt) {
	if cmds.Timerange != "" {
		cmdTimeout = cmds.Timerange
	}
	evDevice = cmds.DevIPAddr
	if cmds.Logtype != "" {
		querytype = cmds.Logtype
	}

	getBasics()
	//
	// All query commands are categorized into one of the 'network', 'system', 'pubssub' and 'log-search'
	// This is shared by ssh and non-ssh mode.
	//
	if cmds.Network != "" {
		runNetwork(cmds.Network)
	} else if cmds.Pubsub != "" {
		runPubsub(cmds.Pubsub)
	} else if cmds.System != "" {
		runSystem(cmds.System)
	} else if cmds.Logopt != "" {
		runLogSearch(cmds)
	} else {
		log.Noticef("no supported options")
		return
	}
}

func initpubInfo(logger *logrus.Logger) pubsub.Publication {
	ps := *pubsub.New(&socketdriver.SocketDriver{Logger: logger, Log: log}, logger, log)
	infoPub, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.EdgeviewStatus{},
		})
	if err != nil {
		log.Errorf("evinfopub: pubsub create error: %v", err)
		return nil
	}
	err = infoPub.ClearRestarted()
	if err != nil {
		log.Errorf("evinfopub: pubsub clear restart error: %v", err)
		return nil
	}

	return infoPub
}