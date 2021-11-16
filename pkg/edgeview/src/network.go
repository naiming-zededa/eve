package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/grandcat/zeroconf"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func runNetwork(netw string) {
	opts, err := checkOpts(netw, netopts)
	if err != nil {
		fmt.Println("runNetwork:", err)
	}

	for _, opt := range opts {
		//fmt.Printf("\n network option: %s\n", opt)
		var substring string
		if strings.Contains(opt, "/") {
			items := strings.SplitN(opt, "/", 2)
			opt = items[0]
			substring = items[1]
		}

		var intfStr, server string
		if opt == "if" || opt == "ping" || opt == "trace" {
			intfStr, _ = runIntfCmd()
		}
		if opt == "ping" || opt == "trace" {
			server, err = runCmd("cat /config/server", false, false)
			server = strings.TrimSuffix(server, "\n")
		}
		if opt == "url" {
			getURL()
		} else if opt == "route" {
			runRoute()
		} else if opt == "socket" {
			printColor(" listening socket ports: ", BLUE)
			runCmd("ss -tunlp4", true, true)
			printColor(" socket established: ", BLUE)
			runCmd("ss -t state established", true, true)
		} else if opt == "nslookup" {
			getDNS(substring)
		} else if opt == "arp" {
			getARP(substring)
		} else if opt == "acl" {
			runACLs(false, substring)
			runACLs(true, substring)
		} else if opt == "connectivity" {
			printColor(" - Connectivity: ", BLUE)
			getConnectivity()
		} else if opt == "if" {
			fmt.Printf("%s\n", intfStr)
			printTitle(" ip -br link:", CYAN, false)
			retStr, err := runCmd("ip -br link", false, false)
			if err != nil {
				continue
			}
			r := strings.Split(retStr, "\n")
			n := len(r)
			for _, intf := range r[:n-1] {
				if !strings.Contains(intf, substring) {
					continue
				}
				fmt.Printf("%s\n", intf)
			}
			getPortCfg(substring, true)
			printTitle(" proxy:", CYAN, false)
			getProxy(true)
		} else if opt == "app" {
			retStr, err := runCmd("ls /run/zedrouter/AppNetworkStatus/*.json", false, false)
			if err != nil {
				continue
			}
			r := strings.Split(retStr, "\n")
			n := len(r)
			for _, s := range r[:n-1] {
				retStr1, err := runCmd("cat "+s, false, false)
				if err != nil {
					continue
				}
				status := strings.TrimSuffix(retStr1, "\n")
				doAppNet(status, substring, false)
			}
		} else if opt == "trace" {
			if substring != "" {
				cmd := "traceroute -4 -m 10 -q 2 " + substring
				if timeout != "" {
					cmd = "timeout " + timeout + " " + cmd
				}
				printTitle(" traceroute to "+substring, CYAN, true)
				retStr, _ := runCmd(cmd, false, false) // timeout will generate error
				fmt.Printf("%s\n", retStr)
			} else {
				printTitle(" traceroute to google", CYAN, true)
				runCmd("traceroute -4 -m 10 -q 2 www.google.com", false, true)
				if server != "" {
					printTitle(" traceroute to "+server, CYAN, true)
					runCmd("traceroute -4 -m 10 -q 2 "+server, false, true)
				}
			}
		} else if opt == "ping" {
			runPing(intfStr, server, substring)
		} else if opt == "tcpdump" {
			runTcpDump(substring)
		} else if opt == "wireless" {
			runWireless()
		} else if opt == "speed" {
			runSpeedTest(substring)
		} else if opt == "flow" {
			getFlow(substring)
		} else if opt == "mdns" {
			runmDNS(substring)
		} else if opt == "tcp" { // tcp and proxy are special
			setAndStartProxyTCP(substring)
		} else {
			fmt.Printf("\n not supported yet\n")
		}
	}
}

// doAppNet
func doAppNet(status, appstr string, isSummary bool) string {
	var appStatus types.AppNetworkStatus
	json.Unmarshal([]byte(status), &appStatus)
	niType := map[types.NetworkInstanceType]string{
		types.NetworkInstanceTypeSwitch:      "switch",
		types.NetworkInstanceTypeLocal:       "local",
		types.NetworkInstanceTypeCloud:       "cloud",
		types.NetworkInstanceTypeHoneyPot:    "honeypot",
		types.NetworkInstanceTypeTransparent: "transparent",
	}

	name := appStatus.DisplayName
	nameLower := strings.ToLower(name)
	appStrLower := strings.ToLower(appstr)
	if appstr != "" && !strings.Contains(nameLower, appStrLower) {
		return ""
	}
	printColor("\n - app: "+name+", appNum: "+strconv.Itoa(appStatus.AppNum)+"\n", BLUE)
	fmt.Printf("   app uuid %s\n", appStatus.UUIDandVersion.UUID.String())

	if appStatus.GetStatsIPAddr != nil {
		fmt.Printf("\n - App Container Stats Collect IP %v\n", appStatus.GetStatsIPAddr)
	}

	for _, item := range appStatus.UnderlayNetworkList {
		niUUID := item.Network.String()
		retStr, err := runCmd("cat /run/zedrouter/NetworkInstanceStatus/"+niUUID+".json", false, false)
		if err != nil {
			continue
		}
		var niStatus types.NetworkInstanceStatus
		json.Unmarshal([]byte(retStr), &niStatus)
		//fmt.Printf("ni: %+v\n", niStatus)
		var ifname string
		var ipaddr net.IP
		for _, p := range item.ACLDependList {
			if ifname != p.Ifname || !ipaddr.Equal(p.IPAddr) {
				fmt.Printf("\n  - uplink port: %s, %v\n", p.Ifname, p.IPAddr)
				ifname = p.Ifname
				ipaddr = p.IPAddr
			}
		}
		fmt.Printf("\n == bridge: %s, %s, %v, %s\n", item.Bridge, item.Vif, item.AllocatedIPv4Addr, item.Mac)

		if isSummary {
			continue
		}

		// XXX ip flow

		ipStr := item.AllocatedIPv4Addr
		printColor("\n - ping app ip address: "+ipStr, RED)
		runCmd("ping -c 3 "+ipStr, false, true)

		if niStatus.Type != types.NetworkInstanceTypeSwitch {
			printColor("\n - check open ports for "+ipStr, RED)
			// nmap package

			retStr, err := runCmd("cat /run/zedrouter/dhcp-hosts."+item.Bridge+"/*.inet", false, false)
			if err == nil {
				printColor("\n - dhcp host file:\n", GREEN)
				lines := strings.Split(retStr, "\n")
				for _, l := range lines {
					if strings.Contains(l, item.Mac) {
						fmt.Printf("%s\n", l)
						break
					}
				}
			}

			retStr, err = runCmd("cat /run/zedrouter/dnsmasq.leases/"+item.Bridge, false, false)
			if err == nil {
				printColor("\n - dnsmasq lease files\n", GREEN)
				lines := strings.Split(retStr, "\n")
				for _, l := range lines {
					if strings.Contains(l, item.Mac) {
						fmt.Printf("%ss\n", l)
						items := strings.Split(l, " ")
						unixtime, _ := strconv.Atoi(items[0])
						fmt.Printf(" lease up to: %v\n", time.Unix(int64(unixtime), 0))
						break
					}
				}
			}

			runAppACLs(item.AllocatedIPv4Addr)

			getVifStats(item.Vif)

			getAppNetTable(item.AllocatedIPv4Addr, &niStatus)

			// NI
			printColor("\n - network instance: ", GREEN)
			fmt.Printf(" %s, type %s, logical lable: %s\n\n", niStatus.DisplayName,
				niType[niStatus.Type], niStatus.Logicallabel)
			fmt.Printf(" DHCP range start: %v, end: %v\n", niStatus.DhcpRange.Start, niStatus.DhcpRange.End)
			fmt.Printf(" Current Uplink: %s\n", niStatus.CurrentUplinkIntf)
			fmt.Printf(" Probe Status:\n")
			for k, p := range niStatus.PInfo {
				fmt.Printf(" Uplink Intfname: %s\n", k)
				upStatus := "Down"
				if p.SuccessCnt != 0 || p.SuccessProbeCnt != 0 {
					upStatus = "UP"
				}
				fmt.Printf("   Probe status: %s, Cost: %d, local sucess: %d, remote success: %d\n",
					upStatus, p.Cost, p.SuccessCnt, p.SuccessProbeCnt)
			}
			fmt.Printf("\n")
		}
		closePipe(true)
	}

	appUUIDStr := appStatus.UUIDandVersion.UUID.String()
	retStr, err := runCmd("cat /run/domainmgr/DomainStatus/"+appUUIDStr+".json", false, false)
	if err == nil {
		printColor("\n  - domain status:", GREEN)
		var domainS types.DomainStatus
		json.Unmarshal([]byte(retStr), &domainS)
		fmt.Printf("    state: %d, boot time: %v, tried count %d\n",
			domainS.State, domainS.BootTime, domainS.TriedCount)
		if domainS.Error != "" {
			fmt.Printf("    error: %s, error time: %v, boot failed: %v",
				domainS.Error, domainS.ErrorTime, domainS.BootFailed)
		}
	}
	return appUUIDStr
}


// getAppNetTable - in 'doAppNet'
func getAppNetTable(ipaddr string, niStatus *types.NetworkInstanceStatus) {
	dhcpStart := niStatus.DhcpRange.Start
	dhcpEnd := niStatus.DhcpRange.End
	_, ipnet, err := net.ParseCIDR(dhcpStart.String() + "/16")
	_, ipnet2, err2 := net.ParseCIDR(dhcpEnd.String() + "/16")
	if err != nil || err2 != nil {
		return
	}
	mask := "/24" // assume there is only /24 or /16 here
	if ipnet.Contains(ipnet2.IP) && ipnet2.Contains(ipnet.IP) {
		mask = "/16"
	}

	ips := strings.Split(ipaddr, ".")
	cmd := "ip rule | grep 'from " + ips[0] + "." + ips[1] + ".'" + " | grep " + mask
	retStr, err := runCmd(cmd, false, false)
	if err != nil {
		return
	}
	printColor("\n - ip route tables related to: "+ipaddr, GREEN)
	lines := strings.Split(retStr, "\n")
	n := len(lines)
	for _, l := range lines[:n-1] {
		l2 := strings.Split(l, " lookup ")
		table := strings.TrimSpace(l2[1])
		fmt.Printf(" ip rule: \n" + l + "\n")
		fmt.Printf("\n for table: " + table + "\n")
		runCmd("ip route show table "+table, false, true)
	}
}


// getVifStats - in 'doAppNet'
func getVifStats(vifStr string) {
	retStr, err := runCmd("cat /run/zedrouter/NetworkMetrics/global.json", false, false)
	if err != nil {
		return
	}
	printColor("\n - bridge Tx/Rx packets on: "+vifStr, GREEN)
	var ntMetric types.NetworkMetrics
	json.Unmarshal([]byte(retStr), &ntMetric)
	for _, m := range ntMetric.MetricList {
		if vifStr == m.IfName {
			fmt.Printf(" TxBytes: %d, RxBytes: %d, TxPkts: %d, RxPkts: %d\n",
				m.TxBytes, m.RxBytes, m.TxPkts, m.RxPkts)
			break
		}
	}
}

// runAppACLs - in 'doAppNet'
func runAppACLs(ipStr string) {
	printColor("\n - check for ACLs on: "+ipStr+"\n", GREEN)
	runAppACLTblAddr("-S", "filter", ipStr)
	runAppACLTblAddr("-nvL", "filter", ipStr)
	runAppACLTblAddr("-S", "nat", ipStr)
	runAppACLTblAddr("-nvL", "nat", ipStr)
}

func runAppACLTblAddr(op, tbl, ipaddr string) {
	retStr, err := runCmd("iptables "+op+" -t "+tbl+" | grep "+ipaddr, true, false)
	if err == nil {
		if len(retStr) > 0 {
			act := ""
			if strings.Contains(op, "S") {
				act = " configured"
			}
			fmt.Printf(" iptable " + tbl + act + " rules: \n")
			fmt.Printf("%s\n", retStr)
		}
	}
}

func getURL() {
	var totalStats urlStats
	getMetricsMap("/run/zedclient/MetricsMap/", &totalStats, true)
	getMetricsMap("/run/zedagent/MetricsMap/", &totalStats, true)
	getMetricsMap("/run/downloader/MetricsMap/", &totalStats, true)
	getMetricsMap("/run/loguploader/MetricsMap/", &totalStats, true)
	getMetricsMap("/run/zedrouter/MetricsMap/", &totalStats, true)
	getMetricsMap("/run/nim/MetricsMap/", &totalStats, true)
	getMetricsMap("/run/diag/MetricsMap/", &totalStats, true)

	printTitle(" - Total Send/Receive stats:\n", CYAN, false)
	fmt.Printf("  send bytes %d, recv bytes %d, send messages %d\n",
		totalStats.sentBytes, totalStats.recvBytes, totalStats.sentNumber)

	mgmtports := getPortCfg("", false)

	var intfRx, intfTx int
	for _, mgmt := range mgmtports {
		tx, rx := getTxRx(mgmt)
		intfTx += tx
		intfRx += rx
	}
	printTitle(" - Total Mgmt intf Send/Receive stats:\n", CYAN, false)
	fmt.Printf("  %v\n", mgmtports)
	fmt.Printf("  send bytes %d, recv bytes %d\n", intfTx, intfRx)

	retStr, err := runCmd("ip -4 -br a | grep UP", false, false)
	if err != nil {
		return
	}
	var bridgeports []string
	ports := strings.Split(retStr, "\n")
	for _, port := range ports {
		if strings.HasPrefix(port, "bn") {
			fields := strings.Fields(port)
			bridgeports = append(bridgeports, fields[0])
		}
	}
	if len(bridgeports) > 0 {
		printTitle(" - Total Bridge intf Send/Receive stats:\n", CYAN, false)
	}
	intfRx = 0
	intfTx = 0
	for _, bridge := range bridgeports {
		tx, rx := getTxRx(bridge)
		intfTx += tx
		intfRx += rx
	}
	fmt.Printf("  %v\n", bridgeports)
	fmt.Printf("  send bytes %d, recv bytes %d\n", intfTx, intfRx)
}

func getTxRx(intf string) (int, int) {
	var intfTx, intfRx int
	retStr, err := runCmd("ip -s -s link show "+intf, false, false)
	if err != nil {
		return intfTx, intfRx
	}
	data1 := strings.Split(retStr, "\n")
	var foundTx, foundRx bool
	for _, line := range data1 {
		if strings.Contains(line, "  RX: bytes") {
			foundRx = true
			continue
		} else if strings.Contains(line, "  TX: bytes") {
			foundTx = true
			continue
		}
		if foundRx {
			foundRx = false
			data2 := strings.Fields(line)
			count, _ := strconv.Atoi(data2[0])
			intfRx += count
		} else if foundTx {
			foundTx = false
			data2 := strings.Fields(line)
			count, _ := strconv.Atoi(data2[0])
			intfTx += count
		}
	}
	return intfTx, intfRx
}

// getPortCfg
func getPortCfg(opt string, isPrint bool) []string {
	var mgmtIntf []string
	if isPrint {
		fmt.Printf("\n - device port configure:\n")
	}
	outStr, err := runCmd("cat /run/zedagent/DevicePortConfig/zedagent.json", false, false)
	if err != nil {
		return mgmtIntf
	}
	if isPrint {
		fmt.Printf("%s\n", outStr)
	}

	var portcfg types.DevicePortConfig
	json.Unmarshal([]byte(outStr), &portcfg)

	dhcpStr := map[types.DhcpType]string{1: "Static", 2: "None", 4: "Client"}
	for _, p := range portcfg.Ports {
		if opt != "" && !strings.Contains(p.IfName, opt) {
			continue
		}
		if isPrint {
			fmt.Printf(" Intf Name: %s\n", p.IfName)
			fmt.Printf("   Is Mgmt %v, Cost %d, dhcp type %v\n", p.IsMgmt, p.Cost, dhcpStr[p.Dhcp])
		}
		if p.IsMgmt {
			mgmtIntf = append(mgmtIntf, p.IfName)
		}
	}
	return mgmtIntf
}

// runIntfCmd
func runIntfCmd() (string, error) {
	return runCmd("ip -br -4 a", false, false)
}

// getConnectivity
func getConnectivity() {
	fmt.Printf("  run diag: \n")
	runCmd("/opt/zededa/bin/diag -o /dev/stdout", true, true)

	retStr, err := runCmd("ls /run/global/DevicePortConfig", false, false)
	if err == nil {
		if strings.HasSuffix(retStr, ".json") {
			fmt.Printf("  override.json:\n")
			retStr1, err := runCmd("cat /run/global/DevicePortConfig/*.json", false, false)
			if err != nil {
				fmt.Printf("error: %v\n", err)
			} else {
				fmt.Println(retStr1)
			}
		} else {
			fmt.Printf("  No override.json\n\n")
		}
	}

	retStr, err = runCmd("cat /persist/status/nim/DevicePortConfigList/global.json", false, false)
	if err != nil {
		return
	}

	printColor(" - port config list", BLUE)
	var portlist types.DevicePortConfigList
	json.Unmarshal([]byte(retStr), &portlist)
	printColor(" Current Index "+strconv.Itoa(portlist.CurrentIndex), GREEN)

	i := 0
	for _, pls := range portlist.PortConfigList {
		str1 := fmt.Sprintf("Key: %s, Last Succeeded: %v, Last Failed: %v\n",
			pls.Key, pls.LastSucceeded, pls.LastFailed)
		if i == portlist.CurrentIndex {
			printColor(str1, RED)
		} else {
			fmt.Printf(str1)
		}
		for _, p := range pls.Ports {
			str2 := fmt.Sprintf("   Ifname: %s, Lable: %s, Mgmt: %v\n",
				p.IfName, p.Logicallabel, p.IsMgmt)
			if i == portlist.CurrentIndex {
				printColor(str2, RED)
			} else {
				fmt.Printf(str2)
			}
		}
		i++
	}
}

// getARP
func getARP(opt string) {
	printColor(" - arp entries: \n", BLUE)
	if opt == "" {
		runCmd("ip -4 n", false, true)
	} else {
		retStr, _ := runCmd("ip -4 n", false, false)
		lines := strings.Split(retStr, "\n")
		n := len(lines)
		for _, l := range lines[:n-1] {
			if !strings.Contains(l, opt) {
				continue
			}
			fmt.Printf("%s\n", l)
		}
	}
}

// runACLs
func runACLs(isRunningACL bool, filter string) {
	acltables := []string{"raw", "filter", "nat", "mangle"}
	for _, tbl := range acltables {
		if filter != "" && filter != tbl {
			continue
		}
		var op string
		if isRunningACL {
			printColor(" Configured iptables: "+tbl, CYAN)
			op = "-S"
		} else {
			printColor(" Installed iptables: "+tbl, CYAN)
			op = "-nvL"
		}
		runCmd("iptables "+op+" -t "+tbl, true, true)
	}
}

// runRoute
func runRoute() {
	rules, err := runCmd("ip rule", false, false)
	if err != nil {
		fmt.Printf("runRoute: %v", err)
		return
	}
	printColor(" - ip rule:", RED)
	fmt.Printf("%s\n", rules)
	tables := getTables(rules)
	for _, table := range tables {
		printColor("show route in table: "+table, CYAN)
		runCmd("ip route show table "+table, false, true)
	}
}

func getTables(rules string) []string {
	rulelines := strings.Split(rules, "\n")
	var t []string
	n := len(rulelines)
	for _, rule := range rulelines[:n-1] {
		table := strings.Split(rule, "lookup ")
		if len(table) > 0 {
			if !strings.Contains(table[1], "default") {
				t = append(t, table[1])
			}
		}
	}
	return t
}

func getMetricsMap(path string, stats *urlStats, isPrint bool) {
	retStr, err := runCmd("ls "+path, false, false)
	if err != nil {
		return
	}

	retStr, err = runCmd("cat "+path+"global.json", false, false)
	if err != nil {
		return
	}
	pathname := ""
	paths := strings.Split(path, "/")
	if len(paths) > 3 {
		pathname = paths[2] + " stats"
	}
	printColor(" - "+pathname, CYAN)
	var mmap types.MetricsMap
	json.Unmarshal([]byte(retStr), &mmap)
	//fmt.Printf("%v", mmap)
	for k, m := range mmap {
		fmt.Printf(" interface: %s\n", k)
		fmt.Printf(" Success: %d  Last Success: %v\n", m.SuccessCount, m.LastSuccess)
		if m.FailureCount > 0 {
			fmt.Printf(" Failure: %d  Last Failure: %v\n", m.FailureCount, m.LastFailure)
		}
		urlm := m.URLCounters
		for k1, m1 := range urlm {
			fmt.Printf("   %s\n", k1)
			fmt.Printf("     Recv (KBytes): %d, Sent %d, SentMsg: %d, TLS resume: %d, Total Time(sec): %d\n\n",
				m1.RecvByteCount/1000, m1.SentByteCount, m1.SentMsgCount, m1.SessionResume, m1.TotalTimeSpent/1000)
			if stats != nil {
				stats.recvBytes += m1.RecvByteCount
				stats.sentBytes += m1.SentByteCount
				stats.sentNumber += m1.SentMsgCount
			}
		}
	}
}

func getDNS(domain string) {
	if domain == "" {
		domain = "zedcloud.zededa.net"
	}
	printColor(" - nslookup: "+domain, CYAN)
	runCmd("nslookup "+domain, false, true)
}

func runPing(intfStr, server string, opt string) {
	if opt != "" {
		if strings.Contains(opt, "/") {
			opts := strings.Split(opt, "/")
			intf := opts[0]
			ipaddr := opts[1]
			printColor("\n - ping "+ipaddr+" through intf: "+intf, CYAN)
			runCmd("ping -c 3 -I "+intf+" "+ipaddr, false, true)
		} else {
			printColor("\n - ping "+opt, CYAN)
			runCmd("ping -c 3 "+opt, false, true)
		}
		return
	}
	if intfStr == "" {
		fmt.Printf(" can not find intf to ping\n")
		return
	}

	intfs := splitLines(intfStr)
	for _, intfline := range intfs {
		if !strings.Contains(intfline, "UP") || intfline == "" {
			continue
		}
		intf := strings.Fields(intfline)
		if strings.HasPrefix(intf[0], "bn") {
			continue
		}
		intfip := intf[len(intf)-1]
		fmt.Printf("intf %v, intfip %s, n %d\n", intf, intfip, len(intf))
		ipa, _, err := net.ParseCIDR(intfip)
		if err != nil {
			fmt.Printf("ip cidr parse error: %v\n", err)
		}
		ipaddr := "8.8.8.8"
		printColor("\n - ping "+ipaddr+" through intf: "+intf[0], CYAN)
		retStr, err := runCmd("ping -c 3 -I "+intf[0]+" "+ipaddr, false, false)
		if err != nil {
			fmt.Printf("ping: %v\n", err)
			continue
		}
		fmt.Printf("%s\n", retStr)
		// to zedcloud
		if server == "" {
			server = "zedcloud.canary.zededa.net"
		}
		printColor("\n - ping to "+server+", source "+ipa.String(), CYAN)
		if runOnServer {
			httpsclient(server, ipa)
		} else {
			runCmd("curl https://"+server+":/api/v1/edgeDevice/ping", true, true)
		}
		closePipe(true)
	}
}

func getProxy(needPrint bool) (string, int, [][]byte) {
	proxyIP := ""
	proxyPort := 0
	proxyPEM := [][]byte{}
	retStr, err := runCmd("cat /run/zedagent/DevicePortConfig/zedagent.json", false, false)
	if err != nil {
		return proxyIP, proxyPort, proxyPEM
	}
	var portcfg types.DevicePortConfig
	json.Unmarshal([]byte(retStr), &portcfg)

	for _, p := range portcfg.Ports {
		if !p.IsMgmt {
			continue
		}
		if len(p.Proxies) > 0 && needPrint {
			fmt.Printf("  ifname %s:\n", p.IfName)
		}
		for _, pp := range p.Proxies {
			if pp.Type == 1 { // https
				proxyIP = pp.Server
				proxyPort = int(pp.Port)

			}
			if needPrint {
				fmt.Printf("    type %d, server %s, port %d\n", pp.Type, pp.Server, pp.Port)
			}
		}
		for _, pem := range p.ProxyCertPEM {
			proxyPEM = append(proxyPEM, pem)
			if needPrint {
				fmt.Printf("    has proxy cert\n")
			}
		}
	}
	return proxyIP, proxyPort, proxyPEM
}


func httpsclient(server string, ipaddr net.IP) {

	localTCPAddr, _ := net.ResolveTCPAddr("tcp", ipaddr.String())
	transport := &http.Transport{
		Dial: (&net.Dialer{ Timeout: 30 * time.Second,
			KeepAlive: 30 * time.Second,
			LocalAddr: localTCPAddr}).Dial, TLSHandshakeTimeout: 10 * time.Second}
	client := &http.Client{
		Transport: transport,
	}

	resp, err := client.Get("https://"+server+":/api/v1/edgeDevice/ping")
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}

	htmlData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("%v\n", resp.Status)
	fmt.Printf(string(htmlData))
}

func getAppUUID(appStr string) (string, string) {
	var connPath, name string
	retData, err := runCmd("ls /run/zedrouter/AppNetworkStatus/*.json", false, false)
	if err != nil {
		fmt.Printf("no appnetworkstatus or error: %v\n", err)
		return connPath, name
	}
	r := strings.Split(retData, "\n")
	n := len(r)
	var appuuid string
	for _, s := range r[:n-1] {
		retData, err = runCmd("cat "+s, false, false)
		status := strings.TrimSuffix(retData, "\n")
		var appStatus types.AppNetworkStatus
		json.Unmarshal([]byte(status), &appStatus)
		name = appStatus.DisplayName
		nameLower := strings.ToLower(name)
		appStrLower := strings.ToLower(appStr)
		if !strings.Contains(nameLower, appStrLower) {
			continue
		}
		appuuid = appStatus.UUIDandVersion.UUID.String()
		break
	}

	if appuuid == "" {
		fmt.Printf("app for %s not found\n", appStr)
		return connPath, name
	}
	return appuuid, name
}

func getFlow(subStr string) {
	err := addPackage("conntrack", "conntrack-tools")
	if err != nil {
		return
	}
	printTitle("\n ip flow:", CYAN, true)

	cmd := "/usr/sbin/conntrack -L 2>&1 "
	if subStr != "" {
		cmd = cmd + "| grep -E " + subStr
	}
	retStr, err := runCmd(cmd, false, false)
	if err != nil {
		fmt.Printf("ip flow error: %v\n", err)
		return
	}

	var olines string
	lines := strings.Split(retStr, "\n")
	for i, l := range lines {
		if len(l) == 0 {
			continue
		}
		if strings.Contains(l, "conntrack v1.") {
			l2 := strings.Split(l, "conntrack v1.")
			l = l2[0]
		}
		var isApp bool
		var appStr string
		if strings.Contains(l, " mark=") { // add appNum and drop string at the end of line
			l2 := strings.Split(l, " mark=")
			if len(l2) != 2 {
				continue
			}
			l3 := strings.SplitN(l2[1], " ", 2)
			if len(l3) != 2 {
				continue
			}
			appNum, _ := strconv.Atoi(l3[0])
			if appNum > 1000 {
				if appNum == 0xffffff {
					appStr = " (drop)"
				} else {
					appN := appNum >> 24
					if appN > 0 && appN < 255 {
						isApp = true
						appStr = " (appNum " + strconv.Itoa(appN) + ")"
					}
				}
			}
			if !isApp && querytype == "app" {
				continue
			}
		}
		olines = l + appStr
		if subStr != "" {
			olines = strings.ReplaceAll(olines, subStr, "\033[0;93m"+subStr+"\033[0m")
		}
		fmt.Printf("%s", olines)
		if i%20 == 0 {
			closePipe(true)
		} else {
			fmt.Println()
		}
	}
}

func runmDNS(subStr string) {
	if directQuery {
		fmt.Printf("mdns is not supported in edge-view ssh mode\n")
		return
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("get interface error: %v\n", err)
		return
	}

	var intfname, serv, serviceStr string
	if strings.Contains(subStr, "/") {
		substrings := strings.Split(subStr, "/")
		if len(substrings) != 2 {
			fmt.Printf("mdns parameter is in the form interface/service\n")
			return
		}
		intfname = substrings[0]
		serv = substrings[1]
	} else {
		intfname = subStr
	}
	var ifs []net.Interface
	for _, intf := range ifaces {
		//fmt.Printf("interface %+v\n", intf)
		if intfname == "" {
			if strings.HasPrefix(intf.Flags.String(), "up|") {
				ifs = append(ifs, intf)
			}
		} else if intf.Name == intfname {
			ifs = append(ifs, intf)
			break
		}
	}

	if serv == "" {
		serviceStr = "_workstation._tcp"
	} else {
		serviceStr = "_" + serv + "._tcp"
	}

	var port []string
	for _, p := range ifs {
		port = append(port, p.Name)
	}
	printTitle(fmt.Sprintf("query mDNS service %s, on intfs %v\n", serviceStr, port), CYAN, true)

	ifOption := zeroconf.SelectIfaces(ifs)
	ipOption := zeroconf.SelectIPTraffic(zeroconf.IPv4)
	resolver, err := zeroconf.NewResolver(ipOption, ifOption)
	if err != nil {
		fmt.Printf("queryService: Failed to initialize resolver: %v", err)
		return
	}

	mctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(10))
	defer cancel()

	entries := make(chan *zeroconf.ServiceEntry)
	go func(results <-chan *zeroconf.ServiceEntry) {
		for entry := range results {
			fmt.Printf("  - %+v\n", entry)
		}
	}(entries)


	err = resolver.Browse(mctx, serviceStr, "local", entries)
	if err != nil {
		fmt.Printf("mdns resolver error %v", err)
		return
	}
	<-mctx.Done()
}

func runTcpDump(subStr string) {
	if !strings.Contains(subStr, "/") {
		fmt.Printf("need to have intf name separated by slash\n")
		return
	}
	err := addPackage("tcpdump", "tcpdump")
	if err != nil {
		return
	}

	subs := strings.SplitN(subStr, "/", 2)
	intf := subs[0]
	var timeValue string
	if timeout != "" {
		timeSec, err := strconv.Atoi(timeout)
		if err != nil {
			fmt.Printf("time option has to be seconds: %v\n", err)
			return
		}
		if timeSec > 120 {
			timeValue = "120"
			fmt.Printf("time value for tcpdump maximum is 120 seconds\n\n")
		} else {
			timeValue = timeout
		}
	} else {
		timeValue = "60"
	}
	cmd := "timeout " + timeValue + " tcpdump -i " + intf + " " + subs[1] + " -c 100"
	printTitle(" tcpdump with: "+cmd, GREEN, true)
	retStr, err := runCmd(cmd, false, false)
	if err != nil {
		fmt.Printf("err %v\n", err)
	} else {
		fmt.Printf("%s\n", retStr)
	}
}

func runWireless() {
	err := addPackage("iwconfig", "wireless-tools")
	if err != nil {
		return
	}

	printTitle("\n iwconfig wlan0", CYAN, false)
	runCmd("iwconfig wlan0", false, true)

	retStr, err := runCmd("cat /run/wlan/wpa_supplicant.conf", false, false)
	if err == nil {
		printTitle(" wpa_supplicant.conf:", CYAN, false)
		lines := strings.Split(retStr, "\n")
		for _, l := range lines[:len(lines)-1] {
			if strings.Contains(l, "psk=") {
				pos := strings.Split(l, "psk=")
				n := len(pos[1])
				pos2 := pos[0] + "psk=" + pos[1][:3] + "..." + pos[1][n-3:]
				fmt.Printf("%s\n", pos2)
			} else {
				fmt.Printf("%s\n", l)
			}
		}
	}
}

func runSpeedTest(intf string) {
	err := addPackage("speedtest", "speedtest-cli")
	if err != nil {
		return
	}
	var opt string
	if intf != "" {
		retStr, err := runCmd("ip -4 -br a | grep UP", false, false)
		if err == nil {
			lines := splitLines(retStr)
			for _, l := range lines {
				if strings.Contains(l, intf) {
					words := strings.Fields(l)
					n := len(words)
					ipaddr := strings.Split(words[n-1], "/")
					opt = " --source " + ipaddr[0]
				}
			}
		}
	}
	printTitle("\n speed test: on "+intf+", "+opt, CYAN, true)
	runCmd("/usr/bin/speedtest"+opt, false, true)
}
