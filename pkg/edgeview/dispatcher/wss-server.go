package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
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
		err := conn.WriteMessage(websocket.TextMessage, []byte(tokenReqMsg))
		if needDebug {
			fmt.Printf("websocket write: %v\n", err)
		}
		return
	}
	if len(r.Header["X-Session-Token"]) == 0 {
		err := conn.WriteMessage(websocket.TextMessage, []byte(tokenReqMsg))
		if needDebug {
			fmt.Printf("websocket write: %v\n", err)
		}
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
			err := conn.WriteMessage(websocket.TextMessage, []byte(moretwoMsg))
			if needDebug {
				fmt.Printf("websocket write: %v\n", err)
			}
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
		err := conn.WriteMessage(websocket.TextMessage, []byte(noDeviceMsg))
		if needDebug {
			fmt.Printf("websocket write: %v\n", err)
		}
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
		delete(tmpMap, remoteAddr)
		if len(tmpMap) == 0 {
			delete(reqAddrTokenEP, token)
		}
	}
	connMutex.Unlock()
}

// Get preferred outbound ip of this machine
func getOutboundIP() string {
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
	helpPtr := flag.Bool("h", false, "help string")
	debugPtr := flag.Bool("debug", false, "more debug info")
	portPtr := flag.String("port", "", "websocket listen port")
	certFilePtr := flag.String("cert", "", "server certificate pem file")
	keyFilePtr := flag.String("key", "", "server key pem file")
	clientcertFilePtr := flag.String("clientcert", "", "client certificate pem file")
	flag.Parse()

	if *helpPtr {
		fmt.Println(" -h                    this help")
		fmt.Println(" -port <port number>   mandatory, tcp port number")
		fmt.Println(" -cert <path>          mandatory, server certificate path in PEM format")
		fmt.Println(" -key <path>           mandatory, server key file path in PEM format")
		fmt.Println(" -debug                optional, turn on more debug")
		fmt.Println(" -clientcert <path>    optional, client certificate path in PEM format")
		return
	}

	if *debugPtr {
		needDebug = true
	}
	if *portPtr == "" {
		fmt.Println("port needs to be specified")
		return
	}
	if *certFilePtr == "" || *keyFilePtr == "" {
		fmt.Println("server cert and key files need to be specified")
		return
	}
	clientCertPath := *clientcertFilePtr
	tlsConfig := &tls.Config{
	}
	if clientCertPath != "" {
		caCert, err := ioutil.ReadFile(clientCertPath)
		if err != nil {
			fmt.Println("can not read cert file", clientCertPath)
			return
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	localIP := getOutboundIP()
	server := &http.Server{
		Addr:      localIP+":"+*portPtr,
		TLSConfig: tlsConfig,
	}

    http.HandleFunc("/edge-view", socketHandler)
	fmt.Printf("Listen TLS on: %s:%s\n", localIP, *portPtr)
    log.Fatal(server.ListenAndServeTLS(*certFilePtr, *keyFilePtr))
}
