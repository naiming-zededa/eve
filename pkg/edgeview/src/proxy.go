// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

// Virtual forward proxy server for handling the https service on site
func proxyServer(done chan struct{}, dnsIP string) *http.Server {
	server := &http.Server{
		Addr: proxyServerEndpoint.String(),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r, dnsIP)
			} else {
				handleHTTP(w, r)
			}
		}),

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

func handleTunneling(w http.ResponseWriter, r *http.Request, dnsIP string) {
	remoteHost := r.Host
	var destConn net.Conn
	var err error
	if dnsIP != "" { // this is probably needed for internal/vpn https service with private DNS server
		r := &net.Resolver{
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Millisecond * time.Duration(10000),
				}
				return d.DialContext(ctx, network, dnsIP+":53")
			},
		}
		d := net.Dialer{Resolver: r, Timeout: 10*time.Second}
		log.Debugf("handleTunneling: custom dialer")
		destConn, err = d.Dial("tcp", remoteHost)
	} else {
		destConn, err = net.DialTimeout("tcp", remoteHost, 10*time.Second)
	}
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
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		fmt.Printf("handleTunneling: hijacker error: %v\n", err)
	}
	go transfer(destConn, clientConn, true)
	go transfer(clientConn, destConn, false)
}

func transfer(destination io.WriteCloser, source io.ReadCloser, toremote bool) {
	defer destination.Close()
	defer source.Close()
	log.Debugf("transfer: before io.Copy to-remove %v\n", toremote)
	_, _ = io.Copy(destination, source)
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
	_, _ = io.Copy(w, resp.Body)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
