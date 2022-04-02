// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"golang.org/x/crypto/ssh"
)

const (
	colorRED     = "\033[1;31m%s\033[0m"
	colorBLUE    = "\033[1;34m%s\033[0m"
	colorCYAN    = "\033[1;36m%s\033[0m"
	colorGREEN   = "\033[0;32m%s\033[0m"
	colorYELLOW  = "\033[0;93m%s\033[0m"
	colorPURPLE  = "\033[1;95m%s\033[0m"
	colorRESET   = "\033[0m"
)

var (
	netopts       []string
	pubsubopts    []string
	pubsubpersist []string
	pubsublarge   []string
	sysopts       []string
	logdirectory  []string
)

var edgeviewInstID int   // if set, from 1 to 5

const maxInstNumber = 5  // allow up to five edgeview sessions and instances
const instStatsEPString = "localhost:8234"

// all the supported options
func initOpts() {
	netopts = []string{
		"acl",
		"app",
		"arp",
		"connectivity",
		"flow",
		"if",
		"mdns",
		"nslookup",
		"ping",
		"route",
		"socket",
		"speed",
		"tcp",
		"tcpdump",
		"trace",
		"url",
		"wireless"}

	pubsubopts = []string{
		"baseosmgr",
		"domainmgr",
		"downloader",
		"edgeview",
		"global",
		"loguploader",
		"newlogd",
		"nim",
		"nodeagent",
		"tpmmgr",
		"vaultmgr",
		"volumemgr",
		"watcher",
		"zedagent",
		"zedclient",
		"zedmanager",
		"zedrouter"}

	pubsubpersist = []string{
		"nim",
		"tpmmgr",
		"volumemgr",
		"zedagent",
		"zedclient",
		"zedmanager",
		"zedrouter"}

	pubsublarge = []string{
		"zedagent",
		"zedmanager"}

	sysopts = []string{
		"app",
		"configitem",
		"cp",
		"datastore",
		"download",
		"hw",
		"lastreboot",
		"model",
		"newlog",
		"pci",
		"ps",
		"cipher",
		"usb",
		"shell",
		"techsupport",
		"volume",
	}

	logdirectory = []string{
		"/persist/newlog/keepSentQueue/",
		"/persist/newlog/devUpload/",
		"/persist/newlog/appUpload/",
		"/persist/newlog/failedUpload/",
	}
}

func getHostname() string {
	var hostname string
	retStr, err := runCmd("hostname", false, false)
	if err != nil {
		return hostname
	}
	hostname = strings.TrimSuffix(retStr, "\n")
	return hostname
}

func checkOpts(opt string, optslice []string) ([]string, error) {
	opts := strings.Split(opt, ",")
	for _, o := range opts {
		ok := false
		if strings.Contains(o, "/") {
			opt1 := strings.Split(o, "/")
			ok = isValidOpt(opt1[0], optslice)
		} else {
			ok = isValidOpt(o, optslice)
		}
		if !ok {
			return []string{}, fmt.Errorf("options available: %v", optslice)
		}
	}
	return opts, nil
}

func isValidOpt(value string, optslice []string) bool {
	for _, opt := range optslice {
		if opt == value {
			return true
		}
	}
	return false
}

// get url and path from JWT token string
func getAddrFromJWT(token string, isServer bool, evStatus *types.EdgeviewStatus, instID int) (string, string, error) {
	var addrport, path string
	tparts := strings.Split(token, ".")
	if len(tparts) != 3 {
		return addrport, path, fmt.Errorf("no ip:port or invalid JWT")
	}

	if instID > 0 {
		if instID > maxInstNumber {
			return addrport, path, fmt.Errorf("JWT inst number incorrect")
		}
		edgeviewInstID = instID
	}

	data, err := base64.RawURLEncoding.DecodeString(tparts[1])
	if err != nil {
		return addrport, path, err
	}

	var jdata types.EvjwtInfo
	err = json.Unmarshal(data, &jdata)
	if err != nil {
		return addrport, path, err
	}

	var uuidStr string
	if isServer {
		retStr, err := runCmd("cat /persist/status/uuid", false, false)
		if err == nil {
			uuidStr = strings.TrimSuffix(retStr, "\n")
		}
	}

	if jdata.Exp == 0 || jdata.Dep == "" {
		return addrport, path, fmt.Errorf("read JWT data failed")
	}
	if uuidStr != "" && jdata.Sub != uuidStr {
		return addrport, path, fmt.Errorf("uuid does not match JWT jti")
	}

	now := time.Now()
	nowSec := uint64(now.Unix())
	if nowSec > jdata.Exp {
		return addrport, path, fmt.Errorf("JWT expired %d sec ago", nowSec - jdata.Exp)
	}

	if jdata.Num > 1 && instID < 1 {
		return addrport, path, fmt.Errorf("Edgeview is in multi-instance mode, inst-id(1-%d) needs to be specifed", jdata.Num)
	} else if jdata.Num == 1 && instID > 0 {
		return addrport, path, fmt.Errorf("Edgeview is not in multi-instance mode, no need to specify inst-ID")
	}

	if strings.Contains(jdata.Dep, "/") {
		urls := strings.SplitN(jdata.Dep, "/", 2)
		addrport = urls[0]
		path = "/" + urls[1]
	} else {
		addrport = jdata.Dep
	}

	evStatus.ExpireOn = jdata.Exp
	evStatus.StartedOn = now
	encryptInit(jdata)

	return addrport, path, nil
}

func getBasics() {
	if runOnServer {
		if _, err := os.Stat("/config"); err != nil {
			return
		}
	}

	retStr, err := runCmd("ip -4 -br a | grep UP", false, false)
	if err == nil {
		lines := splitLines(retStr)
		ips := []string{}
		for _, l := range lines {
			if strings.HasPrefix(l, "bn") {
				continue
			}
			//fmt.Printf("l: %s\n", l)
			words := strings.Fields(l)
			n := len(words)
			ipaddrs := strings.Split(words[n-1], "/")
			ips = append(ips, ipaddrs[0])
		}
		if myEvEndPoint != "" {
			fmt.Printf("Device IPs: %v; Endpoint IP %s\n", ips, myEvEndPoint)
		} else {
			fmt.Printf("Device IPs: %v\n", ips)
		}
	}
	retStr, err = runCmd("cat /persist/status/uuid", false, false)
	if err == nil {
		fmt.Printf("  UUID: %s", retStr)
	}
	retStr, err = runCmd("cat /config/server", false, false)
	if err == nil {
		var printed bool
		conts := strings.Split(retStr, "zedcloud.")
		if len(conts) == 2 {
			cont2s := strings.Split(conts[1], ".zededa.net")
			if len(cont2s) == 2 {
				cluster := cont2s[0]
				controller := strings.Replace(retStr, cluster, "\033[0;93m"+cluster+"\033[0m", 1)
				fmt.Printf("  Controller: %s", controller)
				printed = true
			}
		}
		if !printed {
			fmt.Printf("  Controller: %s", retStr)
		}
	}
	retStr, err = runCmd("cat /run/eve-release && echo -n ', ' && cat /run/eve.id", false, false)
	if err == nil {
		fmt.Printf("  EVE-OS release %s", retStr)
	}
	fmt.Printf("  Edge-View Ver: %s\n", edgeViewVersion)
	retStr, err = runCmd("uptime", false, false)
	if err == nil {
		ret1 := strings.Split(retStr, " load")
		uptime := ret1[0]
		loc, _ := time.LoadLocation("UTC")
		fmt.Printf("  %v(%v), uptime %s", time.Now().In(loc).Format(time.RFC3339), loc, uptime)
	}
	fmt.Println()
	fmt.Println()
	closePipe(true)
}

// dynamically install package for uncommon options
func addPackage(programName, pkgName string) error {
	retStr, err := runCmd("which "+programName, false, false)
	if err == nil {
		if len(retStr) > 0 {
			fmt.Printf("%s\n", retStr)
		}
	} else {
		_, err = runCmd("apk add "+pkgName, false, false)
		if err != nil {
			fmt.Printf("%v\n", err)
			return err
		}
	}
	return nil
}

func runCmd(cmd string, isEve, isPrint bool) (string, error) {
	if isEve && !runOnServer {
		cmd = "eve exec pillar " + cmd + " 2&>1"
	}
	var retStr string
	var retBytes []byte
	var err error
	if runOnServer {
		retBytes, err = exec.Command("sh", "-c", cmd).Output()
		if err == nil {
			retStr = string(retBytes)
		}
	} else {
		retStr, err = remoteRun("root", evDevice, sshprivkey, cmd)
	}
	if err != nil {
		if !strings.HasSuffix(err.Error(), "status 1") {
			fmt.Printf("error: %v\n", err)
		}
	} else {
		if isPrint {
			fmt.Println(retStr)
			closePipe(true)
		}
	}
	return retStr, err
}

// used in ssh-mode
func remoteRun(user string, addr string, privateKey []byte, cmd string) (string, error) {
	key, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		fmt.Printf("ssh parse key error: %v\n", err)
		return "", err
	}
	// Authentication
	config := &ssh.ClientConfig{
		User: user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
	}
	// Connect
	client, err := ssh.Dial("tcp", net.JoinHostPort(addr, "22"), config)
	if err != nil {
		fmt.Printf("ssh dial error: %v\n", err)
		return "", err
	}
	// Create a session. It is one session per command.
	session, err := client.NewSession()
	if err != nil {
		fmt.Printf("ssh session error: %v\n", err)
		return "", err
	}
	defer session.Close()
	var b bytes.Buffer
	session.Stdout = &b // get output

	// Finally, run the command
	err = session.Run(cmd)
	return b.String(), err
}

func printColor(msg, color string) {
	fmt.Printf(color, msg)
	fmt.Println("")
}

func printTitle(msg, color string, sendnow bool) {
	printColor(msg, color)
	if sendnow {
		closePipe(true)
	}
}

func splitLines(inStr string) []string {
	outStr := strings.Split(inStr, "\n")
	n := len(outStr)
	return outStr[:n-1]
}

func getJSONFileID(path string) string {
	strs := strings.Split(path, "/")
	n := len(strs)
	if n > 0 {
		filename := strs[n-1]
		fileid := strings.Split(filename, ".json")
		if len(fileid) > 0 {
			return fileid[0]
		}
	}
	return ""
}

func getTokenHashString(token string) []byte {
	if edgeviewInstID > 0 {
		token = token + "." + strconv.Itoa(edgeviewInstID)
	}
	h := sha256.New()
	_, err := h.Write([]byte(token))
	if err != nil {
		fmt.Printf("hash write error: %v\n", err)
	}
	hash16 := h.Sum(nil)[:16]
	return []byte(base64.RawURLEncoding.EncodeToString(hash16))
}

// in the format of yyyyMMDDhhmmss to use as part of the file name
func getFileTimeStr(t1 time.Time) string {
	t := t1.UTC()
	return fmt.Sprintf("%d%02d%02d%02d%02d%02d", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
}

var helpStr =`edge-view-query [ -token <session-token> | -device <ip-addr> ] [ -debug ] [ -inst <instance-id> ] <query string>
 options:
  log/search-pattern [ -time <start_time>-<end_time> -json -type <app|dev> -extra num ]
`
func printHelp(opt string) {
	if opt == "" {
		fmt.Println(helpStr)
		fmt.Printf("  pub/ %v\n\n", pubsubopts)
		fmt.Printf("  %v\n", netopts)
		fmt.Printf("  %v\n", sysopts)
	} else {
		fmt.Printf("\n")
		switch opt {
		// network
		case "acl":
			helpOn("acl[/<filter>]", "to display all filters of running and configured ACL")
			helpExample("acl", "display all filters of ACL", true)
			helpExample("acl/nat", "display in table nat of ACL", false)
		case "app":
			helpOn("app[/app-string]", "to display all the app or one specific app")
			helpExample("app", "display all apps in brief", true)
			helpExample("app/iot", "display a specific app, which app name has substring of iot in more detail", false)
		case "arp":
			helpOn("arp[/filter]", "to display all the arp entry or with filter matching")
			helpExample("arp", "display all arp entries", true)
			helpExample("arp/192.168", "display all arp entries contain 192.168 string", false)
		case "connectivity":
			helpOn("connectivity", "run diag on ports, and display the port config list")
		case "flow":
			helpOn("flow[/<some pattern>]", "display ip flow information in the kernel search pattern")
			helpExample("flow/sport=53", "display all the ip flow matches source port of 53", true)
			helpExample("flow/10.1.0.2", "display all the ip flow matches ip address of 10.1.0.2", false)
		case "if":
			helpOn("if[/intf-name]", "display interface related information briefly")
			helpExample("if/eth0", "display interface eth0 related information", true)
		case "mdns":
			helpOn("mdns[/intf-name][/service]", "display zeroconfig related information")
			helpExample("mdns/eth0", "display mDNS for default service 'workstation' on interface 'eth0'", true)
			helpExample("mdns/bn1/https", "display mDNS for service 'https' on bridge 'bn1'", false)
			helpExample("mdns", "display mDNS for default service 'workstation' on all UP interafces", false)
		case "nslookup":
			helpOn("nslookup[/<ip or name>]", "display domain name and dns server information")
			helpExample("nslookup/www.amazon.com", "display DNS information on www.amazon.com", true)
			helpExample("nslookup/8.8.8.8", "display DNS information on address 8.8.8.8", false)
		case "ping":
			helpOn("ping[/<ip or name>]", "ping to 8.8.8.8 from all the UP interfaces or ping a specific address")
			helpExample("ping", "ping to 8.8.8.8 from each source IP address of the intefaces", true)
			helpExample("ping/192.168.1.1", "ping the address of 192.168.1.1", false)
		case "route":
			helpOn("route", "display all the ip rule and their ip table entries")
		case "socket":
			helpOn("socket", "display all the ipv4 litening socket ports and established ports")
		case "speed":
			helpOn("speed[/intf-name]", "run speed test and report the download and upload speed")
			helpExample("speed/wlan0", "run speed test on interface wlan0", true)
		case "tcp":
			helpOn("tcp/ip-address:port[/ip-address:port...][/proxy[@ip-addr]]", "tcp connection to the ip addresses for services, local mapping ports 9001 and above")
			helpExample("tcp/192.168.1.1:8080", "points your browser to the locally listening port and http browsing 192.168.1.1:8080", true)
			helpExample("tcp/10.1.0.2:80/10.1.0.2:8081", "points your browser to the locally listening ports and http browsing remote 10.1.0.2 both 80 and 8081 ports", false)
			helpExample("tcp/proxy/localhost:5903", "https proxy to locally listening ports and vnc viewer to #3 port on device", false)
			helpExample("tcp/proxy@10.1.2.3", "https proxy and specify the address of DNS name server for URL lookup", false)
		case "tcpdump":
			helpOn("tcpdump/intf-name/[options]", "tcpdump on the interface, can specify duration with -time, default is 60 sec")
			helpExample("tcpdump/eth0/", "run tcpdump on eth0 with default 60 seconds or maximum of 100 entries", true)
			helpExample("'tcpdump/eth0/port 443' -time 10", "run tcpdump on eth0 and port 443 with 10 seconds", false)
		case "trace":
			helpOn("trace[/<ip or name>]", "traceroute to www.google.com and zedcloud server, or to specified ip or name, 10 hops limit")
			helpExample("trace", "traceroute to www.google.com and to zedcloud server", true)
			helpExample("trace/www.microsoft.com", "run traceroute to www.microsoft.com", false)
		case "url":
			helpOn("url", "display url metrics for zedclient, zedagent, downloader and loguploader")
		case "wireless":
			helpOn("wireless", "display the iwconfig wlan0 info and wpa_supplicant.conf content")
		// system
		case "configitem":
			helpOn("configitem", "display the device configitem settings, highlight the non-default values")
		case "cp":
			helpOn("cp/<path>", "copy file from the device to locally mounted directory by specify the path")
			helpExample("cp//config/device.cert.pem", "copy the /config/device.cert.pem file to local directory", true)
			helpExample("cp//persist/newlog/keepSentQueue/dev.log.1630451424116.gz", "copy file with path to local directory", false)
		case "datastore":
			helpOn("datastore", "display the device current datastore: EQDN, type, cipher information")
		case "download":
			helpOn("download", "display the download config and status during downloading operation and url stats since reboot")
		case "hw":
			helpOn("hw", "display the hardware from lshw information in json format")
		case "lastreboot":
			helpOn("lastreboot", "display the last reboot reasons and stack if the information is saved")
		case "model":
			helpOn("model", "display the hardware model information in json format")
		case "newlog":
			helpOn("newlog", "display the newlog statistics and file information in each of the newlog directory and disk usage")
		case "pci":
			helpOn("pci", "display the lspci information on device")
		case "ps":
			helpOn("ps/<string>", "display the process status information on matching string")
			helpExample("ps/containerd", "display the processes with name of containerd", true)
		case "cipher":
			helpOn("cipher", "display cipher information on datastore, device and controller certificates, etc.")
		case "usb":
			helpOn("usb", "display the lsusb information on device")
		case "shell":
			helpOn("shell/<some command>", "run shell on the command supplied on the device")
			helpExample("'shell/ls -l /run/nim'", "run 'ls -l /run/nim' command on device", true)
			helpExample("'shell/cat /config/server'", "run 'cat /config/server' command on device", false)
		case "techsupport":
			helpOn("techsupport", "show tech-support, run various edgeview commands with output downloaded in a compressed file")
		case "volume":
			helpOn("volume", "display the app volume and content tree information for each app")
		// log
		case "log":
			helpOn("log/<search string> [-time <start>-<end>] [-json] [-type <app|dev>]", "display log with search-string, default is now to 30 mins ago")
			helpExample("log/panic -time 0.2-2.5", "display log contains 'panic', from 0.2 to 0.5 hours ago", true)
			helpExample("log/Clock -type app", "display previous 30 minutes log contains 'Clock' in app log", false)
			helpExample("log/certificate -time 2021-08-15T23:15:29Z-2021-08-15T22:45:00Z -json",
				"display log during the specified time in RFC3339 format which contains 'certificate' in json format", false)
			helpExample("log/copy-logfiles -time 2022-02-15T22:25:00Z-2022-02-15T22:40:00Z",
				"download all logfiles in the specified time duration, maximum time frame is 30 minutes", false)
		default:
			printHelp("")
		}
	}
}

func helpOn(str1, str2 string) {
	fmt.Printf(" %s  -  %s\n", str1, str2)
}

func helpExample(str1, str2 string, printEG bool) {
	egStr := "    "
	if printEG {
		egStr = "e.g."
	}
	fmt.Printf("  %s %s  -- %s\n", egStr, str1, str2)
}
