package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type endPoint struct {
	hostname  string
	wsConn    *websocket.Conn
}

const (
	noDeviceMsg string = "no device online\n+++Done+++"
	tokenReqMsg string = "token is required"
	moretwoMsg  string = "can't have more than 2 peers"
)

var upgrader = websocket.Upgrader{} // use default options
// reqAddrTokeConn indexed by 'toke' then 'remoteAddr' strings
var reqAddrTokenEP   map[string]map[string]endPoint
// mutex for access the maps
var connMutex sync.Mutex
// connection id, keep inc
var connID int
// debug set
var needDebug bool

func socketHandler(w http.ResponseWriter, r *http.Request) {
    // Upgrade our raw HTTP connection to a websocket based one
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        fmt.Printf("Error during connection upgradation: %v\n", err)
        return
    }
    defer conn.Close()

	if _, ok := r.Header["X-Session-Token"]; !ok {
		err = conn.WriteMessage(websocket.TextMessage, []byte(tokenReqMsg))
		return
	}
	if len(r.Header["X-Session-Token"]) == 0 {
		err = conn.WriteMessage(websocket.TextMessage, []byte(tokenReqMsg))
		return
	}
	token := r.Header["X-Session-Token"][0]

	connID++
	myConnID := connID
	var hostname string
	if _, ok := r.Header["X-Hostname"]; ok {
		if len(r.Header["X-Hostname"]) > 0 {
			hostname = r.Header["X-Hostname"][0]
		}
	}

	remoteAddr := r.RemoteAddr
	connMutex.Lock()
	tmpMap := reqAddrTokenEP[token]
	if tmpMap == nil {
		tmpMap := make(map[string]endPoint)
		reqAddrTokenEP[token] = tmpMap
	}

	if len(tmpMap) == 2 {
		var addOK bool
		// check to see if this one is from the same host
		for addr, e := range tmpMap {
			if e.hostname == hostname {
				fmt.Printf("%v received connection with same hostname %s, close old w/Addr %s\n", time.Now(), hostname, addr)
				e.wsConn.Close()
				addOK = true
			}
		}
		if !addOK {
			err = conn.WriteMessage(websocket.TextMessage, []byte(moretwoMsg))
			connMutex.Unlock()
			return
		}
	}

	ep := endPoint{
		wsConn:    conn,
		hostname:  hostname,
	}
	if _, ok := reqAddrTokenEP[token][remoteAddr]; !ok {
		reqAddrTokenEP[token][remoteAddr] = ep
	}
	sizeMap := len(tmpMap)
	connMutex.Unlock()
	if sizeMap < 2 {
		err = conn.WriteMessage(websocket.TextMessage, []byte(noDeviceMsg))
	}
	fmt.Printf("%v client %s from %s connected, ID: %d\n",
		time.Now().Format("2006-01-02 15:04:05"), hostname, remoteAddr, myConnID)

	cnt := 0
	nopeerPkts := 0
    for {
        messageType, message, err := conn.ReadMessage()
		now := time.Now()
		nowStr := now.Format("2006-01-02 15:04:05")
        if err != nil {
            fmt.Printf("%s on reading host %s from %s, ID %d: %v\n", nowStr, hostname, remoteAddr, myConnID, err)
			cleanConnMap(token, remoteAddr)
            break
        }

		connMutex.Lock()
		tmpMap = reqAddrTokenEP[token]
		if tmpMap == nil {
			connMutex.Unlock()
			continue
		}

		myEP := endPoint{}
		var peerAddr string

		for addr, e := range tmpMap {
			if remoteAddr == addr {
				continue
			}
			dest := strings.Split(addr, ":")
			if len(dest) == 2 {
				addr = dest[1]
			}
			if needDebug {
				fmt.Printf("%s (%d/%d): [%v], t-%d len %d, to %s\n",
					nowStr, myConnID, cnt, hostname, messageType, len(message), addr)
			}
			peerAddr = addr
			myEP = e
			nopeerPkts = 0
			break
		}
		connMutex.Unlock()

		if myEP.wsConn == nil {
			nopeerPkts++
			fmt.Printf("%s can not find peer %d\n", nowStr, nopeerPkts)
			if nopeerPkts < 50 { // need sometime for ep to reconnect
				continue
			}
			err = conn.WriteMessage(websocket.TextMessage, []byte(noDeviceMsg))
        	if err != nil {
            	fmt.Printf("Error during message writing: %v\n", err)
				cleanConnMap(token, remoteAddr)
            	break
        	}
			continue
		}
		err = myEP.wsConn.WriteMessage(messageType, message)
        if err != nil {
            fmt.Printf("Error during message from %s writing to %s, ID %d: %v\n", hostname, peerAddr, myConnID, err)
			cleanConnMap(token, remoteAddr)
            break
        }
		cnt++
    }
}

func cleanConnMap(token, remoteAddr string) {
	connMutex.Lock()
	tmpMap := reqAddrTokenEP[token]
	if tmpMap != nil {
		if _, ok := tmpMap[remoteAddr]; ok {
			delete(tmpMap, remoteAddr)
		}
		if len(tmpMap) == 0 {
			delete(reqAddrTokenEP, token)
		}
	}
	connMutex.Unlock()
}

// Get preferred outbound ip of this machine
func GetOutboundIP() string {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)
    return localAddr.IP.String()
}

// the edge-view websocket dispatcher example
func main() {
	reqAddrTokenEP = make(map[string]map[string]endPoint)
	debugPtr := flag.Bool("debug", false, "more debug info")
	flag.Parse()
	if *debugPtr {
		needDebug = true
	}

    http.HandleFunc("/edge-view", socketHandler)
	localIP := GetOutboundIP()
	fmt.Printf("Listen TLS on: %s:4000\n", localIP)
    log.Fatal(http.ListenAndServeTLS(localIP+":4000",
		"host-ubuntu.crt", "host-ubuntu.key", nil))
}