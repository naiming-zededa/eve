package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

// Virtual forward proxy server for handling the https service
func proxyServer(done chan struct{}) *http.Server {
	server := &http.Server{
		Addr: proxyServerEndpoint.String(),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	fmt.Printf("proxyServer: listenAndServeTLS\n")
	// always accept http from local, no proxy certs involved
	go func() {
		defer close(done)

		err := server.ListenAndServe()
		if err != nil {
			fmt.Printf("proxy server close. listen error: %v\n", err)
		}
	}()

	return server
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	dest_conn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	log.Debugf("handleTunneling: %s\n", r.Host)
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		fmt.Printf("handleTunneling: hijacker error: %v\n", err)
	}
	go transfer(dest_conn, client_conn, true)
	go transfer(client_conn, dest_conn, false)
}

func transfer(destination io.WriteCloser, source io.ReadCloser, toremote bool) {
	defer destination.Close()
	defer source.Close()
	log.Debugf("transfer: before io.Copy to-remove %v\n", toremote)
	io.Copy(destination, source)
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
