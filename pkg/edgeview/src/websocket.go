package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)


func setupWebC(hostname, token string, u url.URL, isServer bool) bool {
	var pport int
	var pIP string
	retry := 0
	// if the device uses proxy cert, add to the container side
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
	for { // wait to be connected to the dispatcher
		tlsDialer, err := tlsDial(isServer, pIP, pport)
		if err != nil {
			return false
		}
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
		if !isServer && retry > 1 {
			return false
		}
	}
	return true
}

// TLS Dialer
func tlsDial(isServer bool, pIP string, pport int) (*websocket.Dialer, error) {
	tlsConfig := &tls.Config{}

	// if wss dispatcher server certificate file is mounted
	_, err0 := os.Stat(serverCertFile)
	if err0 == nil {
		caCertPool := x509.NewCertPool()
		caCert, err := ioutil.ReadFile(serverCertFile)
		if err != nil {
			log.Errorf("can not read server cert file, %v\n", err)
			return nil, err
		}
		if !caCertPool.AppendCertsFromPEM(caCert) {
			errStr := fmt.Sprintf("append cert failed")
			log.Errorf("%s\n", errStr)
			return nil, errors.New(errStr)
		}
		tlsConfig.RootCAs = caCertPool
		fmt.Printf("wss server cert appended to TLS\n")
	} else {
		tlsConfig.InsecureSkipVerify = true
	}

	// attach the client certs if configured so
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

	return dialer, nil
}

// hijack the stdout to buffer and later send the content through
// websocket to the requester of the info
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
