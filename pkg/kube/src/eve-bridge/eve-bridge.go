// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/rpc/jsonrpc"
	"os"
	"runtime"
	"strings"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	v1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ipam"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

const (
	eveKubeNamespace       = "eve-kube-app"
	zedrouterRPCSocketPath = "/run/zedrouter/rpc.sock"
	primaryIfName          = "eth0"
	clusterSvcIPRange      = "10.43.0.0/16"
	vmiPodNamePrefix       = "virt-launcher-"
)

const (
	logfileDir    = "/tmp/eve-bridge/"
	logfile       = logfileDir + "eve-bridge.log"
	logMaxSize    = 100 // 100 Mbytes in size
	logMaxBackups = 3   // old log files to retain
	logMaxAge     = 30  // days to retain old log files
)

var logFile *lumberjack.Logger

// EnvArgs encapsulates CNI_ARGS used by eve-bridge plugin.
type EnvArgs struct {
	types.CommonArgs
	MAC               types.UnmarshallableString
	K8S_POD_NAME      types.UnmarshallableString
	K8S_POD_NAMESPACE types.UnmarshallableString
}

// CommonRPCArgs : arguments used for every RPC.
type CommonRPCArgs struct {
	PodName          string
	PodNetNsPath     string
	PodInterfaceName string
	PodInterfaceMAC  net.HardwareAddr
}

// ConnectPodArgs : arguments for the ConnectPod RPC method handled by zedrouter.
type ConnectPodArgs struct {
	CommonRPCArgs
}

// ConnectPodRetval : type of the value returned by the ConnectPod RPC method.
type ConnectPodRetval struct {
	UseDHCP    bool
	Interfaces []NetworkInterface
}

// ConfigurePodIPArgs : arguments for the ConfigurePodIP RPC method handled by zedrouter.
type ConfigurePodIPArgs struct {
	CommonRPCArgs
	IPs    []PodIPAddress
	Routes []PodRoute
	DNS    PodDNS
}

// ConfigurePodIPRetval : type of the value returned by the ConfigurePodIP RPC method.
type ConfigurePodIPRetval struct{}

// DisconnectPodArgs : arguments for the DisconnectPod RPC method handled by zedrouter.
type DisconnectPodArgs struct {
	CommonRPCArgs
}

// DisconnectPodRetval : type of the value returned by the DisconnectPod RPC method.
type DisconnectPodRetval struct {
	UsedDHCP bool
}

// CheckPodConnectionArgs : arguments for the CheckPodConnection RPC method handled by zedrouter.
type CheckPodConnectionArgs struct {
	CommonRPCArgs
}

// CheckPodConnectionRetval : type of the value returned by the CheckPodConnection RPC method.
type CheckPodConnectionRetval struct {
	UsesDHCP bool
}

// NetworkInterface : single network interface (configured by zedrouter).
type NetworkInterface struct {
	Name   string
	MAC    net.HardwareAddr
	NsPath string
}

// PodIPAddress : ip address assigned to pod network interface.
type PodIPAddress struct {
	Address net.IPNet
	Gateway net.IP
}

// PodRoute : network IP route configured for pod network interface.
type PodRoute struct {
	Dst net.IPNet
	GW  net.IP
}

// PodDNS : settings for DNS resolver inside pod.
type PodDNS struct {
	Nameservers []string
	Domain      string
	Search      []string
	Options     []string
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread.
	runtime.LockOSThread()
}

type rawJSONStruct = map[string]interface{}

func parseArgs(args *skel.CmdArgs) (stdinArgs rawJSONStruct, cniVersion,
	podName string, mac net.HardwareAddr, isVMI, isEveApp bool, err error) {
	// Parse arguments received via stdin.
	versionDecoder := &version.ConfigDecoder{}
	cniVersion, err = versionDecoder.Decode(args.StdinData)
	if err != nil {
		err = fmt.Errorf("failed to decode CNI version: %v", err)
		log.Print(err)
		return
	}
	stdinArgs = make(rawJSONStruct)
	if err = json.Unmarshal(args.StdinData, &stdinArgs); err != nil {
		err = fmt.Errorf("failed to unmarshal stdin args: %v", err)
		log.Print(err)
		return
	}
	// Parse arguments received via environment variables.
	envArgs := EnvArgs{}
	err = types.LoadArgs(args.Args, &envArgs)
	if err != nil {
		err = fmt.Errorf("failed to parse env args: %v", err)
		log.Print(err)
		return
	}
	podName = string(envArgs.K8S_POD_NAME)
	isVMI = strings.HasPrefix(podName, vmiPodNamePrefix)
	isEveApp = string(envArgs.K8S_POD_NAMESPACE) == eveKubeNamespace
	if envArgs.MAC != "" {
		mac, err = net.ParseMAC(string(envArgs.MAC))
		if err != nil {
			err = fmt.Errorf("failed to parse mac address %s: %v", envArgs.MAC, err)
			log.Print(err)
			return
		}
	}
	return
}

// Prepare stdin args for a delegate call to the original bridge plugin.
func prepareStdinForBridgeDelegate(
	stdinArgs rawJSONStruct, isEveApp bool) ([]byte, error) {
	stdinArgs["isDefaultGateway"] = !isEveApp
	stdinArgs["forceAddress"] = true
	stdinArgs["hairpinMode"] = true
	if isEveApp {
		// Even though traffic is not routed via eth0 by default in EVE apps,
		// we should still send packets destined to Kubernetes service IPs through
		// this primary interface.
		ipamArgs, ok := stdinArgs["ipam"].(rawJSONStruct)
		if !ok {
			err := fmt.Errorf("failed to cast IPAM input args (actual type: %T)",
				stdinArgs["ipam"])
			log.Print(err)
			return nil, err
		}
		routes, ok := ipamArgs["routes"].([]interface{})
		if !ok {
			err := fmt.Errorf("failed to cast IPAM routes (actual type: %T)",
				ipamArgs["routes"])
			log.Print(err)
			return nil, err
		}
		nodeIP := stdinArgs["nodeIP"]
		if nodeIP == "" {
			err := errors.New("nodeIP was not provided")
			log.Print(err)
			return nil, err
		}
		clusterSvcRoute := rawJSONStruct{"dst": clusterSvcIPRange}
		routes = append(routes, clusterSvcRoute)
		nodeIPRoute := rawJSONStruct{"dst": nodeIP}
		routes = append(routes, nodeIPRoute)
		ipamArgs["routes"] = routes
	}
	bridgeArgs, err := json.Marshal(stdinArgs)
	if err != nil {
		err = fmt.Errorf("failed to marshal input args for the bridge plugin: %v", err)
		log.Print(err)
		return nil, err
	}
	return bridgeArgs, nil
}

// Prepare stdin args for a delegate call to the dhcp IPAM plugin.
func prepareStdinForDhcpDelegate(stdinArgs rawJSONStruct) ([]byte, error) {
	stdinArgs["ipam"] = rawJSONStruct{"type": "dhcp"}
	dhcpArgs, err := json.Marshal(stdinArgs)
	if err != nil {
		err = fmt.Errorf("failed to marshal input args for the dhcp plugin: %v", err)
		log.Print(err)
		return nil, err
	}
	return dhcpArgs, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	log.Printf("cmdAdd: stdinData: %s, env: %v",
		string(args.StdinData), os.Environ())
	stdinArgs, cniVersion, podName, mac, isVMI, isEveApp, err := parseArgs(args)
	if err != nil {
		// Error is already logged.
		return err
	}

	if args.IfName == primaryIfName {
		// Delegate creation of the eth0 interface to the original bridge plugin.
		bridgeArgs, err := prepareStdinForBridgeDelegate(stdinArgs, isEveApp)
		if err != nil {
			// Error is already logged.
			return err
		}
		log.Printf("Delegating cmdAdd to bridge plugin with args: %s", string(bridgeArgs))
		result, err := invoke.DelegateAdd(context.Background(), "bridge",
			bridgeArgs, nil)
		if err != nil {
			err = fmt.Errorf("bridge plugin failed to setup eth0: %v", err)
			log.Print(err)
			return err
		}
		return types.PrintResult(result, cniVersion)
	}

	// Continue here to create netX interface with the help from zedrouter microservice.

	// Ask zedrouter to connect Pod.
	// For now the interface will be without IP address, but in the case of a local NI
	// the DHCP server will be prepared.
	conn, err := net.Dial("unix", zedrouterRPCSocketPath)
	if err != nil {
		err = fmt.Errorf("failed to dial zedrouter RPC socket: %v", err)
		log.Print(err)
		return err
	}
	defer conn.Close()
	rpcClient := jsonrpc.NewClient(conn)
	commonRPCArgs := CommonRPCArgs{
		PodName:          podName,
		PodNetNsPath:     args.Netns,
		PodInterfaceName: args.IfName,
		PodInterfaceMAC:  mac,
	}
	connectPodArgs := ConnectPodArgs{CommonRPCArgs: commonRPCArgs}
	connectPodRetval := &ConnectPodRetval{}
	err = rpcClient.Call("RPCServer.ConnectPod", connectPodArgs, connectPodRetval)
	if err != nil {
		err = fmt.Errorf("RPC call ConnectPod(%+v) failed: %v", connectPodArgs, err)
		log.Print(err)
		return err
	}
	log.Printf("ConnectPod returned: %+v", connectPodRetval)

	podIntfIndex := -1
	result := &v1.Result{CNIVersion: v1.ImplementedSpecVersion}
	for i, netIntf := range connectPodRetval.Interfaces {
		result.Interfaces = append(result.Interfaces, &v1.Interface{
			Name:    netIntf.Name,
			Mac:     netIntf.MAC.String(),
			Sandbox: netIntf.NsPath,
		})
		if netIntf.Name == args.IfName {
			podIntfIndex = i
		}
	}
	if podIntfIndex == -1 {
		err = fmt.Errorf("missing interface %s in the list %v", args.IfName,
			connectPodRetval.Interfaces)
		log.Print(err)
		return err
	}

	l2Only := !connectPodRetval.UseDHCP || isVMI
	if l2Only {
		// We are done with L2-only connectivity.
		log.Printf("Returning result: %+v", result)
		return types.PrintResult(result, cniVersion)
	}

	// run the IPAM plugin and get back the IP config to apply.
	dhcpArgs, err := prepareStdinForDhcpDelegate(stdinArgs)
	if err != nil {
		// Error is already logged.
		return err
	}
	log.Printf("Running IPAM plugin \"dhcp\" (cmdAdd) with args: %s", string(dhcpArgs))
	r, err := ipam.ExecAdd("dhcp", dhcpArgs)
	if err != nil {
		err := fmt.Errorf("IPAM plugin failed: %v", err)
		log.Print(err)
		return err
	}

	// Convert whatever the IPAM result was into the current Result type.
	ipamResult, err := v1.NewResultFromResult(r)
	if err != nil {
		err = fmt.Errorf("conversion of IPAM results failed: %v", err)
		log.Print(err)
		return err
	}
	if len(ipamResult.IPs) == 0 {
		err = fmt.Errorf("IPAM plugin returned missing IP config: %v", ipamResult)
		log.Print(err)
		return err
	}
	for i := range ipamResult.IPs {
		ipamResult.IPs[i].Interface = &podIntfIndex
	}
	log.Printf("IPAM result: %+v", ipamResult)

	// Ask zedrouter to apply received IP config.
	configurePodIPArgs := ConfigurePodIPArgs{
		CommonRPCArgs: commonRPCArgs,
		DNS: PodDNS{
			Nameservers: ipamResult.DNS.Nameservers,
			Domain:      ipamResult.DNS.Domain,
			Search:      ipamResult.DNS.Search,
			Options:     ipamResult.DNS.Options,
		},
	}
	for _, ip := range ipamResult.IPs {
		configurePodIPArgs.IPs = append(configurePodIPArgs.IPs,
			PodIPAddress{Address: ip.Address, Gateway: ip.Gateway})
	}
	for _, route := range ipamResult.Routes {
		configurePodIPArgs.Routes = append(configurePodIPArgs.Routes,
			PodRoute{Dst: route.Dst, GW: route.GW})
	}
	configurePodIPRetval := &ConfigurePodIPRetval{}
	err = rpcClient.Call("RPCServer.ConfigurePodIP",
		configurePodIPArgs, configurePodIPRetval)
	if err != nil {
		log.Printf("RPC call ConfigurePodIP(%+v) failed: %v", configurePodIPArgs, err)
		return err
	}
	log.Printf("RPC call ConfigurePodIP(%+v) succeeded", configurePodIPArgs)

	result.IPs = ipamResult.IPs
	result.Routes = ipamResult.Routes
	result.DNS = ipamResult.DNS
	log.Printf("Returning result: %+v", result)
	return types.PrintResult(result, cniVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	log.Printf("cmdDel: stdinData: %s, env: %v",
		string(args.StdinData), os.Environ())
	stdinArgs, _, podName, mac, isVMI, isEveApp, err := parseArgs(args)
	if err != nil {
		// Error is already logged.
		return err
	}

	if args.IfName == primaryIfName {
		// Delegate deletion of the eth0 interface to the original bridge plugin.
		bridgeArgs, err := prepareStdinForBridgeDelegate(stdinArgs, isEveApp)
		if err != nil {
			// Error is already logged.
			return err
		}
		log.Printf("Delegating cmdDel to bridge plugin with args: %s", string(bridgeArgs))
		err = invoke.DelegateDel(context.Background(), "bridge",
			bridgeArgs, nil)
		if err != nil {
			err = fmt.Errorf("bridge plugin failed to delete eth0: %v", err)
			log.Print(err)
			return err
		}
		return nil
	}

	// Continue here to remove netX interface with the help from zedrouter microservice.

	// Ask zedrouter to disconnect Pod.
	conn, err := net.Dial("unix", zedrouterRPCSocketPath)
	if err != nil {
		err = fmt.Errorf("failed to dial zedrouter RPC socket: %v", err)
		log.Print(err)
		return err
	}
	defer conn.Close()
	rpcClient := jsonrpc.NewClient(conn)
	commonRPCArgs := CommonRPCArgs{
		PodName:          podName,
		PodNetNsPath:     args.Netns,
		PodInterfaceName: args.IfName,
		PodInterfaceMAC:  mac,
	}
	disconnectPodArgs := DisconnectPodArgs{CommonRPCArgs: commonRPCArgs}
	disconnectPodRetval := &DisconnectPodRetval{}
	err = rpcClient.Call("RPCServer.DisconnectPod", disconnectPodArgs, disconnectPodRetval)
	if err != nil {
		err = fmt.Errorf("RPC call DisconnectPod(%+v) failed: %v", disconnectPodArgs, err)
		log.Print(err)
		return err
	}
	log.Printf("DisconnectPod returned: %+v", disconnectPodRetval)

	l2Only := !disconnectPodRetval.UsedDHCP || isVMI
	if l2Only {
		// We are done removing L2-only connectivity.
		return nil
	}

	// Tell DHCP server to release the allocated IP address.
	dhcpArgs, err := prepareStdinForDhcpDelegate(stdinArgs)
	if err != nil {
		// Error is already logged.
		return err
	}
	log.Printf("Running IPAM plugin \"dhcp\" (cmdDel) with args: %s", string(dhcpArgs))
	err = ipam.ExecDel("dhcp", dhcpArgs)
	if err != nil {
		err := fmt.Errorf("IPAM plugin failed: %v", err)
		log.Print(err)
		return err
	}
	return nil
}

func cmdCheck(args *skel.CmdArgs) error {
	log.Printf("cmdCheck: stdinData: %s, env: %v",
		string(args.StdinData), os.Environ())
	stdinArgs, _, podName, mac, isVMI, isEveApp, err := parseArgs(args)
	if err != nil {
		// Error is already logged.
		return err
	}

	if args.IfName == primaryIfName {
		// Delegate check of the eth0 interface to the original bridge plugin.
		bridgeArgs, err := prepareStdinForBridgeDelegate(stdinArgs, isEveApp)
		if err != nil {
			// Error is already logged.
			return err
		}
		log.Printf("Delegating cmdCheck to bridge plugin with args: %s", string(bridgeArgs))
		err = invoke.DelegateCheck(context.Background(), "bridge",
			bridgeArgs, nil)
		if err != nil {
			err = fmt.Errorf("bridge plugin failed to check eth0: %v", err)
			log.Print(err)
			return err
		}
		return nil
	}

	// Continue here to check netX interface with the help from zedrouter microservice.

	// Ask zedrouter to check the interface.
	conn, err := net.Dial("unix", zedrouterRPCSocketPath)
	if err != nil {
		err = fmt.Errorf("failed to dial zedrouter RPC socket: %v", err)
		log.Print(err)
		return err
	}
	defer conn.Close()
	rpcClient := jsonrpc.NewClient(conn)
	commonRPCArgs := CommonRPCArgs{
		PodName:          podName,
		PodNetNsPath:     args.Netns,
		PodInterfaceName: args.IfName,
		PodInterfaceMAC:  mac,
	}
	checkPodConnectionArgs := CheckPodConnectionArgs{CommonRPCArgs: commonRPCArgs}
	checkPodConnectionRetval := &CheckPodConnectionRetval{}
	err = rpcClient.Call("RPCServer.CheckPodConnection", checkPodConnectionArgs,
		checkPodConnectionRetval)
	if err != nil {
		err = fmt.Errorf("RPC call CheckPodConnection(%+v) failed: %v",
			checkPodConnectionArgs, err)
		log.Print(err)
		return err
	}
	log.Printf("CheckPodConnection returned: %+v", checkPodConnectionRetval)

	l2Only := !checkPodConnectionRetval.UsesDHCP || isVMI
	if l2Only {
		// We are done checking L2-only connectivity.
		return nil
	}

	// Ask dhcp plugin to check pod interface from its point of view.
	dhcpArgs, err := prepareStdinForDhcpDelegate(stdinArgs)
	if err != nil {
		// Error is already logged.
		return err
	}
	log.Printf("Running IPAM plugin \"dhcp\" (cmdCheck) with args: %s", string(dhcpArgs))
	err = ipam.ExecCheck("dhcp", dhcpArgs)
	if err != nil {
		err := fmt.Errorf("IPAM plugin failed: %v", err)
		log.Print(err)
		return err
	}
	return nil
}

func main() {
	if _, err := os.Stat(logfileDir); os.IsNotExist(err) {
		if err := os.MkdirAll(logfileDir, 0755); err != nil {
			return
		}
	}
	logFile = &lumberjack.Logger{
		Filename:   logfile,       // Path to the log file.
		MaxSize:    logMaxSize,    // Maximum size in megabytes before rotation.
		MaxBackups: logMaxBackups, // Maximum number of old log files to retain.
		MaxAge:     logMaxAge,     // Maximum number of days to retain old log files.
		Compress:   true,          // Whether to compress rotated log files.
		LocalTime:  true,          // Use the local time zone for file names.
	}
	log.SetOutput(logFile)
	defer logFile.Close()

	log.Printf("eve-bridge main() Start")
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("eve-bridge"))
	log.Printf("eve-bridge main() exit")
}
