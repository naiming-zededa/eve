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

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

var (
	evDevice      string     // ip-address or domain name of Edge-View device
	runOnServer   bool       // container running inside remote linux host
	directQuery   bool       // container using ssh-mode
	querytype     string
	tokenHash16   []byte     // 16 bytes of sha256 hashed from session token
	timeout       string
	logjson       bool
	extralog      int
	sshprivkey    []byte
	intSignal     chan os.Signal
)

const (
	closeMessage      = "+++Done+++"
	edgeViewVersion   = "0.8.0"
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
	SessTokenHash []byte     `json:"sessTokenHash"`
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

	initOpts()

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

	if *pDebug {
		log.SetLevel(log.DebugLevel)
	}

	if *phopt || *phelpopt {
		printHelp(pqueryopt)
		return
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
		}
	}

	if logopt != "" && timeopt == "" { // default log search is previous half an hour
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
		tokenHash16 = getTokenHashString(*ptoken)
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
		SessTokenHash: tokenHash16,
	}
	if typeopt != "all" {
		queryCmds.Logtype = typeopt
	}

	// edgeview container can run in 3 different modes:
	// 1) ssh-mode, directQuery, send out query and wait for reply from device
	// 2) non-ssh server mode, runs on device: 'runOnServer' is set
	// 3) non-ssh client mode, runs on operator side
	if directQuery { // ssh query mode
		parserAndRun(queryCmds)
		return
	} else if runOnServer { // websocket mode on device 'server' side

		err := initPolicy()
		if err != nil {
			return
		}

		go func() {
			defer close(done)
			for {
				mtype, message, err := websocketConn.ReadMessage()
				if err != nil {
					if retryWebSocket(hostname, *ptoken, urlWSS, err) {
						continue
					}
					return
				}

				var recvCmds cmdOpt
				var isJSON bool
				if mtype == websocket.TextMessage {
					err := json.Unmarshal(message, &recvCmds)
					if err != nil {
						log.Printf("recv not json msg: %s\n", message)
					} else {
						isJSON = true
						ok := checkCmdPolicy(recvCmds)
						if !ok {
							closePipe(false)
							continue
						}
					}
					if !isJSON && (strings.Contains(string(message), "no device online") ||
						strings.Contains(string(message), closeMessage)) {
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
					recvClientData(mtype, message)
					continue
				}
				// process client query
				go goRunQuery(recvCmds)
			}
		}()
	} else { // query client in websocket mode

		if !clientSendQuery(queryCmds) {
			return
		}
		go func() {
			defer close(done)
			for {
				mtype, message, err := websocketConn.ReadMessage()
				if err != nil {
					if retryWebSocket(hostname, *ptoken, urlWSS, err) {
						continue
					}
					return
				}
				if strings.Contains(string(message), closeMessage) {
					log.Infof("%s\nreceive message done\n", string(message))
					done <- struct{}{}
					break
				} else if isCopy {
					getCopyFile(message, &fstatus, mtype)
					if mtype == websocket.TextMessage && isCopy && fstatus.f != nil {
						defer fstatus.f.Close()
					}
				} else if isTCPClient {
					if mtype == websocket.TextMessage {
						log.Debugf("setup tcp client: %s\n", message)
						if !tcpClientRun { // got ok message from tcp server side, run client
							ok, msg := checkReplyMsgOk(message)
							if ok {
								if bytes.Contains(msg, []byte(tcpSetupOKMessage)) {
									tcpClientsLaunch(tcpclientCnt, remotePorts)
								} else {
									// this could be the tcp policy disallow the setup message
									fmt.Printf("%s\n", msg)
								}
							}
						} else {
							log.Infof(" tcp client running, receiving close probably due to server timed out: %v\n", string(message))
							done <- struct{}{}
							break
						}
					} else {
						recvServerData(mtype, message)
					}
				} else {
					ok, msg := checkReplyMsgOk(message)
					if ok {
						fmt.Printf("%s\n", msg)
					}
				}
			}
		}()
	}

	// ssh or non-ssh client wait for replies and finishes with a 'done' or gets a Ctrl-C
	// non-ssh server will be killed when the session is expired with the script
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
		err = websocketConn.WriteMessage(websocket.TextMessage, []byte(closeMessage))
		if err != nil {
			log.Println("sent done msg error:", err)
		}
		log.Printf("Sent %d messages, total %d bytes to websocket\n", wsMsgCount, wsSentBytes)
	}
}

func parserAndRun(cmds cmdOpt) {
	if len(tokenHash16) > 0 && !bytes.Equal(tokenHash16, cmds.SessTokenHash) {
		fmt.Printf("session authentication failed\n")
		return
	}

	if cmds.Timerange != "" {
		timeout = cmds.Timerange
	}
	evDevice = cmds.DevIPAddr
	logjson = cmds.IsJSON
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
