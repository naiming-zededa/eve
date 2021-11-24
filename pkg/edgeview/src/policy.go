// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

type policies struct {
	DeviceAllow       bool     `json:"deviceAllow"`       // allow device related commands
	ApplicationAllow  bool     `json:"applicationAllow"`  // allow app instances or external hosts related commands
	Device struct {
		NotSSH        bool   `json:"notSSH"`              // not allow ssh into device
		NotReboot     bool   `json:"notReboot"`           // not allow issuing 'reboot' of device
		NotAppConsole bool   `json:"notAppConsole"`       // not allow app console access from device
	}                          `json:"device"`
	Apps struct {
		NotProxy   bool      `json:"notProxy"`            // not allow proxy operation
		OnlyPorts  []int     `json:"onlyPorts"`           // only allow defined tcp ports
		NotPorts   []int     `json:"notPorts"`            // not allow defined tcp ports
		OnlyAddrs  []string  `json:"nolyAddrs"`           // only allow defined ip-addresses
		NotAddrs   []string  `json:"notAddrs"`            // not allow defined ip-addresses
	}                          `json:"apps"`
}

var devIntfIPs []string

func initPolicy() error {
	p := policies{}
	_, err := os.Stat(policyFile)
	if err == nil {
		data, err := ioutil.ReadFile(policyFile)
		if err != nil {
			log.Errorf("can not read policy file: %v\n", err)
			return err
		}
		err = json.Unmarshal(data, &p)
		if err != nil {
			log.Errorf("policy json file unmarshal error: %v\n", err)
			return err
		}
	} else {
		p.DeviceAllow = true
		p.ApplicationAllow = true
	}

	policy = p

	devIntfIPs = getLocalIPs()
	devIntfIPs = append(devIntfIPs, "0.0.0.0")
	devIntfIPs = append(devIntfIPs, "localhost")

	return nil
}

func checkCmdPolicy(cmds cmdOpt) bool {
	// log the incoming edge-view command from client
	printCmds := cmds
	printCmds.SessTokenHash = []byte{}
	log.Printf("recv: %+v", printCmds)

	if !policy.DeviceAllow {
		if cmds.Logopt != "" || cmds.Pubsub != "" || cmds.System != "" {
			fmt.Printf("cmds not allowed by policy\n")
			return false
		}
		network := cmds.Network
		if network != "" && !strings.HasPrefix(network, "tcp/") {
			fmt.Printf("network cmds not allowed by policy\n")
			return false
		}
	}

	system := cmds.System
	if strings.HasPrefix(system, "shell/reboot") && policy.Device.NotReboot {
		fmt.Printf("reboot cmd not allowed by policy\n")
		return false
	}
	return true
}

func checkTCPPolicy(tcpOpts string) bool {
	if strings.Contains(tcpOpts, "/") {
		params := strings.Split(tcpOpts, "/")
		for _, ipport := range params {
			if !checkIPportPolicy(ipport) {
				return false
			}
		}
	} else {
		if !checkIPportPolicy(tcpOpts) {
			return false
		}
	}
	return true
}

func checkIPportPolicy(tcpOpt string) bool {
	if strings.HasPrefix(tcpOpt, "proxy") && policy.Apps.NotProxy {
		return false
	}

	if strings.Contains(tcpOpt, ":") {
		opts := strings.Split(tcpOpt, ":")
		if len(opts) != 2 {
			return false
		}
		addr := opts[0]
		port := opts[1]
		isAddrDevice := checkAddrLocal(addr)
		if isAddrDevice {
			if !checkDevPolicy(port) {
				return false
			}
		} else {
			if !checkAppPolicy(addr, port) {
				return false
			}
		}
	}

	return true
}

func checkAddrLocal(addr string) bool {
	for _, a := range devIntfIPs {
		if a == addr {
			return true
		}
	}
	return false
}

func checkDevPolicy(port string) bool {
	if port == "22" && policy.Device.NotSSH {
		return false
	}

	pNumber, _ := strconv.Atoi(port)
	if pNumber >= 5900 && pNumber <= 5909 && policy.Device.NotAppConsole {
		return false
	}

	return true
}

func checkAppPolicy(addr, portStr string) bool {
	if !policy.ApplicationAllow {
		return false
	}

	if len(policy.Apps.OnlyAddrs) > 0 {
		var found bool
		for _, a := range policy.Apps.OnlyAddrs {
			if addr == a {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	port, _ := strconv.Atoi(portStr)
	if len(policy.Apps.OnlyPorts) > 0 {
		var found bool
		for _, p := range policy.Apps.OnlyPorts {
			if port == p {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(policy.Apps.NotAddrs) > 0 {
		for _, a := range policy.Apps.NotAddrs {
			if addr == a {
				return false
			}
		}
	}

	if len(policy.Apps.NotPorts) > 0 {
		for _, p := range policy.Apps.NotPorts {
			if port == p {
				return false
			}
		}
	}
	return true
}
