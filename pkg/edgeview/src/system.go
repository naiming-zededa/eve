package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

func runSystem(sysOpt string) {
	opts, err := checkOpts(sysOpt, sysopts)
	if err != nil {
		fmt.Println("runSystem:", err)
	}

	for _, opt := range opts {
		if opt == "newlog" {
			getLogStats()
		} else if opt == "volume" {
			getVolume()
		} else if opt == "app" {
			getSysApp()
		} else if opt == "datastore" {
			getDataStore()
		} else if opt == "cipher" {
			getCipher()
		} else if opt == "configitem" {
			runConfigItems()
		} else if opt == "download" {
			getDownload()
		} else if strings.HasPrefix(opt, "ps/") {
			runPS(opt)
		} else if strings.HasPrefix(opt, "shell/") {
			runShell(opt)
		} else if strings.HasPrefix(opt, "cp/") {
			runCopy(opt)
		} else if strings.HasPrefix(opt, "usb") {
			runUSB()
		} else if strings.HasPrefix(opt, "pci") {
			runPCI()
		} else if strings.HasPrefix(opt, "model") {
			getModel()
		} else if strings.HasPrefix(opt, "hw") {
			getHW()
		} else {
			fmt.Printf("opt %s: not supported yet\n", opt)
		}
	}
}

// getLogStats - in 'runSystem'
func getLogStats() {
	retData, err := runCmd("cat /run/newlogd/NewlogMetrics/global.json", false, false)
	if err == nil {
		prettyJSON, err := formatJSON([]byte(retData))
		if err == nil {
			printColor(" - log stats:\n", CYAN)
			fmt.Printf("%s\n", prettyJSON)
		}
	}

	retData, err = runCmd("cd /persist/newlog && du -h |tail -1|awk '{print $1}'", false, false)
	if err == nil {
		printColor("\n newlog files total size: "+retData+"\n", GREEN)
	}

	printColor(" log file directorys:\n", CYAN)
	for _, d := range logdirectory {
		retData, err := runCmd("ls "+d, false, false)
		if err != nil {
			continue
		}
		lines := strings.Split(retData, "\n")
		fmt.Printf(" %s: number of gzip files: %d\n", d, len(lines)-1)
		app := 0
		dev := 0
		var tmin, tmax, appmin, appmax int64
		n := len(lines)
		for _, l := range lines[:n-1] {
			var isApp, isDev bool
			if strings.HasPrefix(l, "app.") {
				app++
				isApp = true
			} else if strings.HasPrefix(l, "dev.") {
				dev++
				isDev = true
			}

			time1 := getFileTime(l)
			if time1 == 0 {
				continue
			}
			if isDev && (tmin == 0 || tmin > time1) {
				tmin = time1
			}
			if isDev && (tmax == 0 || tmax < time1) {
				tmax = time1
			}
			if isApp && (appmin == 0 || appmin > time1) {
				appmin = time1
			}
			if isApp && (appmax == 0 || appmax < time1) {
				appmax = time1
			}
		}
		if app == 0 && dev == 0 {
			fmt.Printf("  directory empty\n")
		} else {
			fmt.Printf("  dev files: %d, app files: %d \n", dev, app)
			if tmin > 0 || tmax > 0 {
				fmt.Printf("   dev-earliest: %v, dev-latest: %v\n", time.Unix(tmin, 0).Format(time.RFC3339), time.Unix(tmax, 0).Format(time.RFC3339))
			}
			if appmin > 0 || appmax > 0 {
				fmt.Printf("   app-earlist: %v, app-latest: %v\n", time.Unix(appmin, 0).Format(time.RFC3339), time.Unix(appmax, 0).Format(time.RFC3339))
			}
		}
	}
	fmt.Println()
}

func getFileTime(filename string) int64 {
	var fn []string
	if strings.Contains(filename, ".gz") && strings.Contains(filename, ".log.") {
		fn = strings.Split(filename, ".gz")
	}
	if len(fn) < 2 {
		return 0
	}
	fn = strings.Split(fn[0], ".log.")
	if len(fn) < 2 {
		return 0
	}
	filetime, _ := strconv.Atoi(fn[1])
	return int64(filetime / 1000)
}

func getVolume() {
	retStr, err := runCmd("ls /run/zedagent/AppInstanceConfig/*.json", false, false)
	if err != nil {
		return
	}

	jlines := strings.Split(retStr, "\n")
	n := len(jlines)
	for _, line := range jlines[:n-1] {
		retStr, err = runCmd("cat "+line, false, false)
		if err != nil {
			continue
		}
		var appinst types.AppInstanceConfig
		json.Unmarshal([]byte(retStr), &appinst)
		for _, vol := range appinst.VolumeRefConfigList {
			printColor("\n - App "+appinst.DisplayName, CYAN)
			fmt.Printf("  volume config, ID: %s\n", vol.VolumeID.String())

			retStr, err = runCmd("cat /run/zedagent/VolumeConfig/"+vol.VolumeID.String()+"*.json", false, false)
			if err != nil {
				continue
			}
			var vol1 types.VolumeConfig
			json.Unmarshal([]byte(retStr), &vol1)
			fmt.Printf("   name: %s, ID %s, RefCount: %d \n", vol1.DisplayName, vol1.VolumeID.String(), vol1.RefCount)
			retStr2, err := runCmd("ls -l "+vol1.VolumeDir+"/"+vol1.VolumeID.String()+"*", false, false)
			if err != nil {
				continue
			}
			if strings.Contains(retStr2, "qcow") {
				fmt.Println(retStr2)
			} else {
				retStr1, err := runCmd("cat "+vol1.VolumeDir+"/"+vol1.VolumeID.String()+"*.container/image-config.json", false, false)
				if err != nil {
					continue
				}
				var img v1.Image
				json.Unmarshal([]byte(retStr1), &img)
				fmt.Printf("    container:\n")
				fmt.Printf("    os: %s, cmd: %s\n", img.OS, img.Config.Cmd)
				fmt.Printf("    labels: %v\n", img.Config.Labels)
			}

			printColor("\n content tree config: "+vol1.ContentID.String(), BLUE)
			retStr, err = runCmd("cat /run/zedagent/ContentTreeConfig/"+vol1.ContentID.String()+".json", false, false)
			var cont types.ContentTreeConfig
			json.Unmarshal([]byte(retStr), &cont)
			fmt.Printf("   url: %s, format: %s, sha: %s\n", cont.RelativeURL, cont.Format, cont.ContentSha256)
			fmt.Printf("   size: %d, name: %s\n", cont.MaxDownloadSize, cont.DisplayName)
		}
	}
}

func getSysApp() {
	memfile := "/proc/meminfo"
	if runOnServer {
		memfile = "/host" + memfile
	}
	retData, err := runCmd("cat "+memfile+" | grep 'Mem'", false, false)
	if err == nil {
		printColor(" - device memory", CYAN)
		fmt.Println(retData)
	}
	retData, err = runCmd("ls /run/zedrouter/AppNetworkStatus/*.json", false, false)
	if err != nil {
		return
	}
	r := strings.Split(retData, "\n")
	n := len(r)
	for _, s := range r[:n-1] {
		retData, err = runCmd("cat "+s, false, false)
		status := strings.TrimSuffix(retData, "\n")
		appuuid := doAppNet(status, "", true)
		retData, err = runCmd("cat /run/domainmgr/DomainMetric/"+appuuid+".json", false, false)
		if err == nil {
			var metric types.DomainMetric
			json.Unmarshal([]byte(retData), &metric)
			fmt.Printf("    CPU: %d, Used Mem(MB): %d, Avail Mem(BM): %d\n",
				metric.CPUTotalNs, metric.UsedMemory, metric.AvailableMemory)
		}

		retData, err = runCmd("cat /run/zedmanager/DomainConfig/"+appuuid+".json", false, false)
		if err != nil {
			continue
		}
		printColor("\n  - vnc/log info:", GREEN)
		var config types.DomainConfig
		json.Unmarshal([]byte(retData), &config)
		fmt.Printf("    VNC enabled: %v, VNC display id: %d, Applog disabled: %v\n",
			config.EnableVnc, config.VncDisplay, config.DisableLogs)
	}
}

func getDataStore() {
	retStr, err := runCmd("ls /run/zedagent/DatastoreConfig/*.json", false, false)
	if err != nil {
		return
	}

	printColor(" - DataStore:", CYAN)
	lines := splitLines(retStr)
	for _, l := range lines {
		retStr1, err := runCmd("cat "+l, false, false)
		if err != nil {
			continue
		}
		var data types.DatastoreConfig
		json.Unmarshal([]byte(retStr1), &data)
		if data.IsCipher {
			fmt.Printf("   Cipher Context ID: %s, Cipher Hash: %s\n",
				data.CipherContextID, base64.StdEncoding.EncodeToString(data.ClearTextHash))
		}
		fmt.Printf("\n   FQDN: %s, Path: %s, DS Type: %s, Is Cipher: %v\n", data.Fqdn, data.Dpath, data.DsType, data.IsCipher)
		if len(data.DsCertPEM) > 0 {
			for _, c := range data.DsCertPEM {
				printCert(c)
			}
		}
	}
}

func getModel() {
	printTitle("Model:", CYAN, false)
	runCmd("spec.sh", false, true)
}

func getHW() {
	printTitle("HW:", CYAN, false)
	runCmd("lshw -json", false, true)
}

func runUSB() {

	printTitle("USB:", CYAN, false)
	runCmd("apk add usbutils", false, false)
	retStr, err := runCmd("lsusb -v", false, false)
	if err != nil {
		fmt.Printf("%v\n", err)
	} else {
		fmt.Printf("%s\n", retStr)
	}
}

func runPCI() {

	printTitle("PCI:", CYAN, false)
	addPackage("lspci", "pciutils")
	retStr, err := runCmd("lspci -v", false, false)
	if err != nil {
		fmt.Printf("%v\n", err)
	} else {
		fmt.Printf("%s\n", retStr)
	}
}

func getCipher() {
	retStr, err := runCmd("ls -lt /persist/certs", false, false)
	if err == nil {
		printColor(" - /persist/certs:\n", CYAN)
		fmt.Println(retStr)
	}

	certType := map[types.CertType]string{
		types.CertTypeOnboarding:      "onboarding",
		types.CertTypeRestrictSigning: "signing",
		types.CertTypeEk:              "Ek",
		types.CertTypeEcdhXchange:     "EdchXchange",
	}

	printColor(" - Additional CA-Certificates:\n", CYAN)
	runCmd("ls -l /etc/ssl/certs/ | grep '/usr/local/share'", true, true)

	retStr, err = runCmd("ls /run/zedagent/DatastoreConfig/", false, false)
	if err == nil {
		printColor("\n - DataStore Config:", CYAN)
		lines := splitLines(retStr)
		for _, l := range lines {
			if !strings.HasSuffix(l, ".json") {
				continue
			}
			retStr1, err := runCmd("cat /run/zedagent/DatastoreConfig/"+l, false, false)
			if err != nil {
				continue
			}
			var data types.DatastoreConfig
			json.Unmarshal([]byte(retStr1), &data)
			fmt.Printf(" %s:\n", getJsonFileID(l))
			fmt.Printf("  type: %s, FQDN: %s, ApiKey: %s, path: %s, Is Cipher: %v\n",
				data.DsType, data.Fqdn, data.ApiKey, data.Dpath, data.IsCipher)
			if len(data.DsCertPEM) > 0 {
				for _, c := range data.DsCertPEM {
					printCert(c)
				}
			}
		}
	}

	retStr, err = runCmd("ls /run/domainmgr/CipherBlockStatus/", false, false)
	if err == nil {
		printColor("\n - Domainmgr CipherBlock:", CYAN)
		lines := splitLines(retStr)
		for _, l := range lines {
			if !strings.HasSuffix(l, ".json") {
				continue
			}
			retStr1, err := runCmd("cat /run/domainmgr/CipherBlockStatus/"+l, false, false)
			if err != nil {
				continue
			}
			var data types.CipherBlockStatus
			json.Unmarshal([]byte(retStr1), &data)
			fmt.Printf(" %s:\n", getJsonFileID(l))
			fmt.Printf("  ID: %s, Is Cipher: %v\n", data.CipherBlockID, data.IsCipher)
			retStr2, err := runCmd("ls /run/domainmgr/cloudinit/"+data.CipherBlockID+".cidata", false, false)
			if err == nil {
				if len(retStr2) > 0 {
					fmt.Printf("   cloudinit file: %s\n", retStr2)
				}
			}
		}
	}

	retStr, err = runCmd("ls /persist/status/tpmmgr/EdgeNodeCert/*.json", false, false)
	if err == nil {
		printColor("\n - TPMmgr Edgenode Certs:", CYAN)
		lines := splitLines(retStr)
		for _, l := range lines {
			retStr1, err := runCmd("cat "+l, false, false)
			if err != nil {
				continue
			}
			var data types.EdgeNodeCert
			json.Unmarshal([]byte(retStr1), &data)
			fmt.Printf(" %s:\n", getJsonFileID(l))
			fmt.Printf("  hash Algo: %d, Cert ID: %s, Cert Type: %s, Is TPM: %v\n",
				data.HashAlgo, base64.StdEncoding.EncodeToString(data.CertID), certType[data.CertType], data.IsTpm)
			printCert(data.Cert)
		}
	}

	retStr, err = runCmd("ls /persist/status/zedagent/CipherContext/*.json", false, false)
	if err == nil {
		printColor("\n - Cipher Context:", CYAN)
		lines := splitLines(retStr)
		for _, l := range lines {
			retStr1, err := runCmd("cat "+l, false, false)
			if err != nil {
				continue
			}
			var data types.CipherContext
			json.Unmarshal([]byte(retStr1), &data)
			fmt.Printf(" %s:\n", getJsonFileID(l))
			fmt.Printf("  ID: %s, Device Cert Hash: %s\n",
				data.ContextID, base64.StdEncoding.EncodeToString(data.DeviceCertHash))
			fmt.Printf("  Controller Cert Hash: %s\n", base64.StdEncoding.EncodeToString(data.ControllerCertHash))
		}
	}

	retStr, err = runCmd("ls /persist/status/zedagent/ControllerCert/*.json", false, false)
	if err == nil {
		printColor("\n - Controller Certs:", CYAN)
		lines := splitLines(retStr)
		for _, l := range lines {
			retStr1, err := runCmd("cat "+l, false, false)
			if err != nil {
				continue
			}
			var data types.ControllerCert
			json.Unmarshal([]byte(retStr1), &data)
			fmt.Printf(" %s:\n", getJsonFileID(l))
			fmt.Printf("  hash Algo: %d, Type: %d, hash %s\n",
				data.HashAlgo, data.Type, base64.StdEncoding.EncodeToString(data.CertHash))
			printCert(data.Cert)
		}
	}
}

func printCert(certdata []byte) {
	block, _ := pem.Decode(certdata)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("cert err %v\n", err)
		return
	}
	fmt.Printf("    subject: %s, serial: %d, valid until: %v\n", cert.Subject, cert.SerialNumber, cert.NotAfter)
	fmt.Printf("     issuer: %s\n", cert.Issuer)
}

func runConfigItems() {
	printColor(" - global settings:", CYAN)

	// /hostfs is need here to read the memory limit for eve item
	configitems := getConfigItems()

	configMap := types.NewConfigItemSpecMap()
	// global
	for k, g := range configitems.GlobalSettings {
		//fmt.Printf("key: %s; value %v\n", k, g)
		s := configMap.GlobalSettings[k]
		s1 := types.ConfigItemValue{
			ItemType: s.ItemType,
			IntValue: s.IntDefault,
			StrValue: s.StringDefault,
			BoolValue: s.BoolDefault,
			TriStateValue: s.TriStateDefault,
		}
		if getCfgValue(g) == getCfgValue(s1) {
			buff := fmt.Sprintf(" %s: %s\n", k, getCfgValue(g))
			fmt.Printf("%s", buff)
		} else {
			buff := fmt.Sprintf(" %s: %s; default %s\n", k, getCfgValue(g), getCfgValue(s1))
			printColor(buff, YELLOW)
		}
		//fmt.Printf("   default: %v\n", configMap.GlobalSettings[k])
	}

	// agent
	printColor("\n - agent settings:", CYAN)
	for k, g := range configitems.AgentSettings {
		printColor("  "+k+":  ", RED)
		for k1, g1 := range g {
			fmt.Printf("    %s, %s\n", k1, getCfgValue(g1))
		}
	}
}

func getConfigItems() types.ConfigItemValueMap {
	var cfgItem types.ConfigItemValueMap
	retStr, err := runCmd("cat /persist/status/zedagent/ConfigItemValueMap/global.json", false, false)
	if err != nil {
		return cfgItem
	}
	json.Unmarshal([]byte(retStr), &cfgItem)
	return cfgItem
}

func getCfgValue(g types.ConfigItemValue) string {
	value := ""
	switch g.ItemType {
	case types.ConfigItemTypeInt:
		value = strconv.Itoa(int(g.IntValue))
	case types.ConfigItemTypeBool:
		value = strconv.FormatBool(g.BoolValue)
	case types.ConfigItemTypeString:
		value = g.StrValue
	case types.ConfigItemTypeTriState:
		if g.TriStateValue == types.TS_NONE {
			value = "None"
		} else if g.TriStateValue == types.TS_DISABLED {
			value = "Disabled"
		} else if g.TriStateValue == types.TS_ENABLED {
			value = "Enabled"
		} else {
			value = "un-supported"
		}
	default:
		value = "un-supported"
	}
	return value
}

func getDownload() {
	pubsubSvs("/run/", "volumemgr", "DownloaderConfig")
	pubsubSvs("/run/", "downloader", "DownloaderStatus")

	getMetricsMap("/run/downloader/MetricsMap/", nil, true)
	checkDownload("/persist/downloads")
	checkDownload("/persist/vault/downloader")
	checkDownload("/persist/vault/verifier")
}

func runPS(opt string) {
	var item string
	if strings.Contains(opt, "ps/") {
		opts := strings.SplitN(opt, "ps/", 2)
		item = opts[1]
	}
	runCmd("ps aux | grep "+item, false, true)
}

func checkDownload(dir string) {
	retStr, err := runCmd("ls -lR "+dir+" | grep root | grep -v drwx | grep -v dr-x | awk '{print $9}'", false, false)
	if err != nil || len(retStr) == 0 {
		return
	}
	printColor(" - in "+dir, CYAN)
	lines := splitLines(retStr)
	for _, jfile := range lines {
		retStr, err := runCmd("cd "+dir+" && find . -name "+jfile+" -print", false, false)
		if err != nil {
			continue
		}
		paths := strings.SplitN(retStr, "./", 2)
		if len(paths) < 2 {
			continue
		}
		path := paths[1]
		retStr, err = runCmd("ls -l "+dir+"/"+path, false, false)
		if err == nil {
			fmt.Printf("%s\n", retStr)
		}
	}
}

func runShell(opt string) {
	shell := strings.SplitN(opt, "shell/", 2)
	if len(shell) != 2 {
		fmt.Printf("shell needs a / and command input\n")
		return
	}
	printColor(" - shell cmd: "+shell[1], CYAN)
	runCmd(shell[1], false, true)
}

func isClosed(c chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
	}
	return false
}

func getFileSha256(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		fmt.Printf("os open error %v\n", err)
		return nil
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		fmt.Printf("sha256 error %v\n", err)
		return nil
	}
	return h.Sum(nil)
}
