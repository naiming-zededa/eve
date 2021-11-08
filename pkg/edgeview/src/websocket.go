package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)


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
						log.Printf("file create error %v\n", err)
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
				log.Printf("dial: %v, wait for 10 sec\n", err)
			} else {
				log.Printf("dial: %v, status code %d, wait for 10 sec\n", err, resp.StatusCode)
			}
			time.Sleep(10 * time.Second)
		} else {
			websocketConn = c
			log.Printf("connect success to websocket server\n")
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
			log.Println("sent done msg error:", err)
		}
		log.Printf("Sent %d messages, total %d bytes to websocket\n", wsMsgCount, wsSentBytes)
	}
}


func openPipe() (*os.File, *os.File, error) {
	if socketOpen {
		return nil, nil, fmt.Errorf("socket already opened\n")
	}
	oldStdout = os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		log.Println("os.Pipe:", err)
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
			log.Println("open pipe error:", err)
		}
	}
}
