package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

type Endpt struct {
	Host string
	Port int
}

func (endpoint *Endpt) String() string {
	return fmt.Sprintf("%s:%d", endpoint.Host, endpoint.Port)
}

// client TCP service to be forwarded, starts from 9001
var clientTCPEndpoint = Endpt{
	Host: "0.0.0.0",
	Port: 9000,
}

// internal proxy server endpoint on device side
var proxyServerEndpoint = Endpt{
	Host: "localhost",
	Port: 8888,
}

// tcpConnRWMap is fixed port-mapping, within it can have multiple flows each
// has it's tcpconn. In other words, the tcpConnRWMap defines the destination
// endpoint such as "10.1.0.4:8080", and it can have multiple source endpoints
type tcpConnRWMap struct {
	m map[int]tcpconn
}

const (
	TCPMaxMappingNUM int = 5
)

var tcpMapMutex sync.Mutex
var wssWrMutex  sync.Mutex
var tcpConnM []tcpConnRWMap

var tcpServerRecvTime time.Time   // updated by all the tcp sessions
var tcpTimeMutex      sync.Mutex

// Virtual TCP Port Mapping service

// tcp mapping on the client end
func tcpClientsLaunch(tcpclientCnt int, remotePorts map[int]int) {
	tcpConnM = make([]tcpConnRWMap, tcpclientCnt)
	idx := 0
	for {
		rPort := remotePorts[idx]
		go tcpClientStart(idx, rPort)
		idx++
		if idx >= tcpclientCnt {
			break
		}
	}
	tcpClientRun = true
}

func tcpClientStart(idx int, rport int) {
	clientep := clientTCPEndpoint
	clientep.Port += (idx + 1)
	listener, err := net.Listen("tcp", clientep.String())
	if err != nil {
		return
	}

	newChan := make(chan net.Conn)
	tcpConnM[idx].m = make(map[int]tcpconn)
	channelNum := 0
	cleanMapTimer := time.Tick(3 * time.Minute)
	go func (l net.Listener) {
		for {
			here, err := listener.Accept()
			if err != nil {
				fmt.Printf("Accept error %v\n", err)
				return
			}
			newChan <- here
		}
	}(listener)
	for {
		select {
		case here := <-newChan:
			channelNum++
			go clientTCPtunnel(here, idx, channelNum, rport)
		case <- cleanMapTimer:
			cleanClosedMapEntries(idx)
		}
	}
}

func clientTCPtunnel(here net.Conn, idx, chNum int, rport int) error {

	fmt.Printf("clientwebtunnel(idx %d): starts in chan %d, rport %d\n", idx, chNum, rport)
	done := make(chan struct{})
	myConn := tcpconn{
		conn:    here,
		msgChan: make(chan wsMessage, 50),
	}
	msgChan := tcpConnM[idx].AssignConn(chNum, myConn)

	go func(here net.Conn) {
		for {
			select {
			case tcpmsg := <-msgChan:
				myConn := tcpConnM[idx].RecvWssInc(chNum)
				buf := bytes.NewBuffer(tcpmsg.msg)
				log.Debugf("Ch-%d[idx %d port %d], From wss recv, %s, len %d\n", chNum, idx, rport, time.Now().Format("2006-01-02 15:04:05"), len(tcpmsg.msg))
				if myConn.pending {
					log.Debugf("Ch(%d)-%d, pending close send to client, %v\n", idx, chNum, time.Now())
				}
				io.Copy(here, buf)
			case <- done:
				return
			}
		}
	}(here)

	buf := make([]byte, 4096)
	var justEnter bool
	if rport >= 5900 && rport <= 5910 { // VNC does not send any data initially
		justEnter = true
	}
	var reqLen int
	var err error
	for {
		if justEnter {
			justEnter = false
		} else {
			reqLen, err = here.Read(buf)
			if err != nil {
				log.Infof("clientTCPtunnel-%d[idx %d rport %d]: tcp socket error from local client, %v, %v, break\n",
					chNum, idx, rport, time.Now(), err)
				if err == io.EOF {
					time.Sleep(1 * time.Second)
					log.Debugf("clientTCPtunnel-%d: delay 1 second pending close after EOF, %v\n", chNum, time.Now())
				}
				here.Close()
				tcpConnM[idx].CloseChan(chNum)
				break
			}
			tcpConnM[idx].RecvLocalInc(chNum)
		}

		wrdata := tcpData{
			MappingID: uint16(idx + 1),
			ChanNum:   uint16(chNum),
			Data:      buf[:reqLen],
		}
		jdata, err := json.Marshal(wrdata)
		if err != nil {
			fmt.Printf("ch(%d)-%d, client json marshal error %v\n", idx, chNum, err)
			continue
		}

		if tcpRetryWait {
			fmt.Printf("wait for tcp retry before write to wss: ch-%d\n", chNum)
			time.Sleep(1 * time.Second)
		}
		log.Debugf("ch-%d[idx %d, port %d], client wrote len %d to wss, %s\n", chNum, idx, rport, len(jdata), time.Now().Format("2006-01-02 15:04:05"))

		if websocketConn == nil {
			close(done)
			fmt.Printf("ch(%d)-%d, websocketConn nil. exit\n", idx, chNum)
			return nil
		}
		wssWrMutex.Lock()
		err = websocketConn.WriteMessage(websocket.BinaryMessage, jdata)
		wssWrMutex.Unlock()
		if err != nil {
			close(done)
			fmt.Printf("ch(%d)-%d, client write wss error %v\n", idx, chNum, err)
			return err
		}
	}
	return nil
}

// TCP mapping on server side
func setAndStartProxyTCP(opt string, isProxy bool) {
	var ipAddrPort []string
	var proxySvr *http.Server
	proxyServerDone := make(chan struct{})

	mappingCnt := 1
	ipAddrPort = make([]string, mappingCnt)
	if isProxy {
		proxySvr = proxyServer(proxyServerDone)
	} else if strings.Contains(opt, "/") {
		params := strings.Split(opt, "/")
		mappingCnt = len(params)
		ipAddrPort = make([]string, mappingCnt)
		for i, ipport := range params {
			if !strings.Contains(opt, ":") {
				fmt.Printf("tcp option needs ipaddress:port format\n")
				return
			}
			ipAddrPort[i] = ipport
		}
	} else {
		if !strings.Contains(opt, ":") {
			fmt.Printf("tcp option needs ipaddress:port format\n")
			return
		}
		ipAddrPort[0] = opt
	}

	// send tcp-setup-ok to client side
	fmt.Printf(" %v\n", TCPSetupOKMessage)
	tcpConnM = make([]tcpConnRWMap, mappingCnt)
	tcpDataChn = make([]chan tcpData, mappingCnt)

	closePipe(false)
	isTCPServer = true
	tcpServerDone = make(chan struct{})

	idx := 0
	serverDone := make([]chan struct{}, mappingCnt)
	for {
		serverDone[idx] = make(chan struct{})
		go startTCPServer(idx, ipAddrPort[idx], isProxy, serverDone[idx])
		idx++
		if idx >= mappingCnt {
			break
		}
	}

	for {
		select {
		case <- tcpServerDone:
			for _, d := range serverDone {
				if !isClosed(d) {
					close(d)
				}
			}
			if isProxy && proxySvr != nil {
				fmt.Printf("TCP exist. calling proxSvr.Close\n")
				proxySvr.Close()
			}
			isTCPServer = false
			return

		case <- proxyServerDone:
			for _, d := range serverDone {
				if !isClosed(d) {
					close(d)
				}
			}
			isTCPServer = false
			return
		}
	}
}

// each mapping of port with 'idx', and each flow within the mapping in the 'ChnNum'
// the 'idx' is fixed after setup, but flow of 'Chn' is dynamic
func startTCPServer(idx int, ipAddrPort string, isProxy bool, tcpServerDone chan struct{}) {
	tcpConnM[idx].m = make(map[int]tcpconn)
	cleanMapTimer := time.NewTicker(3 * time.Minute)
	tcpDataChn[idx] = make(chan tcpData)

	log.Debugf("tcp server(%d) proxy starts to server %s, waiting for first client packet\n", idx, ipAddrPort)
	var proxyluanchCnt int
	for {
		select {
		case wssMsg := <- tcpDataChn[idx]:
			if int(wssMsg.ChanNum) > proxyluanchCnt {
				proxyluanchCnt++
			} else {
				log.Debugf("tcp proxy re-launch channel(%d): %d\n", idx, wssMsg.ChanNum)
			}
			go tcpTransfer(ipAddrPort, wssMsg, idx, isProxy)
		case <- tcpServerDone:
			fmt.Printf("tcp server done(%d). exit\n", idx)
			isTCPServer = false
			cleanMapTimer.Stop()
			doneTCPtransfer(idx)
			cleanClosedMapEntries(idx)
			return
		case <- cleanMapTimer.C:
			cleanClosedMapEntries(idx)
		}
	}
}

func tcpTransfer(url string, wssMsg tcpData, idx int, isProxy bool) {
	var conn net.Conn
	var err error
	var proxyStr string
	var connClosed bool

	chNum := int(wssMsg.ChanNum)
	done := make(chan struct{})
	d := net.Dialer{Timeout: 30 * time.Second}
	if isProxy {
		conn, err = d.Dial("tcp", proxyServerEndpoint.String())
		proxyStr = "(proxy)"
	} else {
		conn, err = d.Dial("tcp", url)
	}
	if err != nil {
		fmt.Printf("tcp dial(%d) error%s: %v\n", idx, proxyStr, err)
		return
	}
	defer conn.Close()

	myConn := tcpconn{
		conn:    conn,
		msgChan: make(chan wsMessage, 50),
		done:    done,
	}
	oldChan, ok := tcpConnM[idx].Get(chNum)
	if ok {
		myConn.recvLocal = oldChan.recvLocal
		myConn.recvWss = oldChan.recvWss
	}

	msgChan := tcpConnM[idx].AssignConn(chNum, myConn)
	msg := wsMessage{
		mtype: websocket.BinaryMessage,
		msg:   []byte(wssMsg.Data),
	}
	myConn.msgChan <- msg // first message from client

	log.Debugf("tcpTrasfer(%d) starts%s for chNum %d. got conn, localaddr %s\n", idx, proxyStr, chNum, conn.LocalAddr())
	//done := make(chan struct{})
	// receive from clinet/websocket and relay to tcp server
	go func(conn net.Conn, done chan struct{}) {
		t := time.NewTimer(600 * time.Second)
		for {
			select {
			case <-t.C:
				// other sessions still ongoing, continue
				if !tcpRecvTimeCheckExpire() {
					t = time.NewTimer(600 * time.Second)
					log.Infof("tcp session timeout, but continue ch(%d)-%d\n", idx, chNum) // XXX remove
					continue
				}
				log.Debugf("tcp session timeout ch(%d)-%d\n", idx, chNum)
				log.Infof("tcp session timeout ch(%d)-%d\n", idx, chNum) // XXX remove
				wssWrMutex.Lock()
				websocketConn.WriteMessage(websocket.TextMessage, []byte("\n"))
				wssWrMutex.Unlock()
				if !connClosed {
					conn.Close()
				}
				tcpConnM[idx].CloseChan(chNum)
				return
			case <-done:
				log.Debugf("done here, ch(%d)-%d\n", idx, chNum)
				log.Infof("done here, conn.CLose() ch(%d)-%d\n", idx, chNum) // XXX remove
				t.Stop()
				tcpConnM[idx].CloseChan(chNum)
				if !connClosed {
					conn.Close()
				}
				return
			case wsmsg := <-msgChan:
				tcpConnM[idx].RecvWssInc(chNum)
				if wsmsg.mtype == websocket.TextMessage {
					conn.Close()
					t.Stop()
					tcpConnM[idx].CloseChan(chNum)
					return
				}
				buf := bytes.NewBuffer(wsmsg.msg)
				io.Copy(conn, buf)
				t.Stop()
				t = time.NewTimer(600 * time.Second)
				tcpRecvTimeUpdate()
			}
		}
	}(conn, done)

	buf := make([]byte, 25600)
	for {
		reqLen, err := conn.Read(buf)
		if err != nil {
			//fmt.Printf("Ch-%d, %v, read error %v\n", chNum, time.Now(), err)
			break
		}

		myConn = tcpConnM[idx].RecvLocalInc(chNum)
		//fmt.Printf("Ch-%d, recv TCP server conn count [%d], %v, write to wss\n", chNum, myConn.recvLocal, time.Now()) // XXX

		wrdata := tcpData{
			MappingID: uint16(idx + 1),
			ChanNum:   uint16(chNum),
			Data:      buf[:reqLen],
		}
		jdata, err := json.Marshal(wrdata)
		if err != nil {
			fmt.Printf("ch(%d)-%d, server json marshal error %v\n", idx, chNum, err)
			continue
		}

		if tcpRetryWait {
			fmt.Printf("wait for tcp retry before write to wss: ch-%d\n", chNum)
			time.Sleep(1 * time.Second)
		}
		//fmt.Printf("ch-%d, server to wss, len %d\n", chNum, len(jdata))
		if websocketConn == nil {
			close(done)
			fmt.Printf("ch(%d)-%d, websocketConn nil. exit\n", idx, chNum) // XXX
			return
		}
		wssWrMutex.Lock()
		err = websocketConn.WriteMessage(websocket.BinaryMessage, jdata)
		wssWrMutex.Unlock()
		if err != nil {
			fmt.Printf("ch(%d)-%d, server wrote error %v\n", idx, chNum, err)
			break
		}
	}
	if !isClosed(done) {
		close(done)
	}
	connClosed = true
}


func cleanClosedMapEntries(idx int) {
	tcpMapMutex.Lock()
	deleted := 0
	recvlocal := 0
	recvWss := 0
	for i, m := range tcpConnM[idx].m {
		if m.closed && time.Since(m.closeTime).Seconds() > 60 {
			recvlocal += m.recvLocal
			recvWss += m.recvWss
			delete(tcpConnM[idx].m, i)
			deleted++
		}
	}
	log.Debugf("done with cleanup(%d). deleted %d, exist num %d\n", idx, deleted, len(tcpConnM[idx].m))
	tcpMapMutex.Unlock()
}

func doneTCPtransfer(idx int) {
	tcpMapMutex.Lock()
	closed := 0
	for _, m := range tcpConnM[idx].m {
		if !isClosed(m.done) {
			close(m.done)
			closed++
		}
	}
	tcpMapMutex.Unlock()
	log.Infof("doneTCPtransfer(%d) closed %d threads\n", idx, closed)
}

func (r tcpConnRWMap) Get(ch int) (tcpconn, bool) {
	tcpMapMutex.Lock()
	t, ok := r.m[ch]
	if !ok {
		tcpMapMutex.Unlock()
		return tcpconn{}, ok
	}
	tcpMapMutex.Unlock()
	return t, ok
}

func (r tcpConnRWMap) RecvWssInc(ch int) tcpconn {
	tcpMapMutex.Lock()
	m := r.m[ch]
	m.recvWss++
	r.m[ch] = m
	tcpMapMutex.Unlock()
	return m
}

func (r tcpConnRWMap) RecvLocalInc(ch int) tcpconn {
	tcpMapMutex.Lock()
	m := r.m[ch]
	m.recvLocal++
	r.m[ch] = m
	tcpMapMutex.Unlock()
	return m
}

func (r tcpConnRWMap) CloseChan(ch int) {
	tcpMapMutex.Lock()
	m := r.m[ch]
	m.closed = true
	m.closeTime = time.Now()
	r.m[ch] = m
	tcpMapMutex.Unlock()
}

func (r tcpConnRWMap) PendingChan(ch int) {
	tcpMapMutex.Lock()
	m := r.m[ch]
	m.pending = true
	r.m[ch] = m
	tcpMapMutex.Unlock()
}

func (r tcpConnRWMap) AssignConn(ch int, m tcpconn) chan wsMessage {
	tcpMapMutex.Lock()
	r.m[ch] = m
	tcpMapMutex.Unlock()
	return m.msgChan
}

func tcpRecvTimeUpdate() {
	tcpTimeMutex.Lock()
	tcpServerRecvTime = time.Now()
	tcpTimeMutex.Unlock()
}

func tcpRecvTimeCheckExpire() bool {
	var expired bool
	tcpTimeMutex.Lock()
	if time.Since(tcpServerRecvTime).Seconds() > 600 {
		expired = true
	}
	tcpTimeMutex.Unlock()
	return expired
}

func tcpClientSendDone() {
	if !isTCPClient {
		wssWrMutex.Lock()
		websocketConn.WriteMessage(websocket.CloseMessage, []byte{})
		wssWrMutex.Unlock()
		return
	}
	wssWrMutex.Lock()
	fmt.Printf("interrupted. send done msg over\n")
	websocketConn.WriteMessage(websocket.TextMessage, []byte(TCPDONEMessage))
	websocketConn.WriteMessage(websocket.CloseMessage, []byte{})
	wssWrMutex.Unlock()
}