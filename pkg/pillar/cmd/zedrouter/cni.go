// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	rpcSocketPath     = runDirname + "/rpc.sock"
	defaultRPCTimeout = 10 * time.Second
)

type rpcRequest struct {
	signalDone chan error
	request    interface{}
}

func (r *rpcRequest) submitAndWait(z *zedrouter, timeout time.Duration) error {
	r.signalDone = make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	select {
	case z.cniRequests <- r:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-r.signalDone:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *rpcRequest) markDone(err error) {
	r.signalDone <- err
	close(r.signalDone)
}

// Handle RPC request from the zedrouter main event loop.
func (z *zedrouter) handleRPC(rpc *rpcRequest) {
	var err error
	switch request := rpc.request.(type) {
	case ConnectPodRequest:
		err = z.handleConnectPodRequest(request.Args, request.Retval)
	case ConfigurePodIPRequest:
		err = z.handleConfigurePodIPRequest(request.Args, request.Retval)
	case DisconnectPodRequest:
		err = z.handleDisconnectPodRequest(request.Args, request.Retval)
	case CheckPodConnectionRequest:
		err = z.handleCheckPodConnectionRequest(request.Args, request.Retval)
	default:
		err = fmt.Errorf("unhandled RPC request %T: %v", request, request)
	}
	if err != nil {
		z.log.Error(err)
	}
	rpc.markDone(err)
}

// RPCServer receives RPC calls from eve-bridge CNI and dispatches them to the main
// event loop of zedrouter.
type RPCServer struct {
	zedrouter *zedrouter
}

func (z *zedrouter) runRPCServer() error {
	server := &RPCServer{zedrouter: z}
	err := rpc.Register(server)
	if err != nil {
		return err
	}

	listener, err := net.Listen("unix", rpcSocketPath)
	if err != nil {
		return err
	}

	go func() {
		defer listener.Close()
		for {
			conn, err := listener.Accept()
			if err != nil {
				z.log.Warnf("Accept for RPC call failed: %v", err)
				continue
			}
			go rpc.ServeCodec(jsonrpc.NewServerCodec(conn))
		}
	}()
	return nil
}

// CommonRPCArgs : arguments used for every RPC served by zedrouter.
type CommonRPCArgs struct {
	PodName          string
	PodNetNsPath     string
	PodInterfaceName string
	PodInterfaceMAC  net.HardwareAddr
}

// ConnectPodRequest encapsulates args and retval for ConnectPod RPC method.
type ConnectPodRequest struct {
	Args   ConnectPodArgs
	Retval *ConnectPodRetval
}

// ConnectPodArgs : arguments for the ConnectPod RPC method.
type ConnectPodArgs struct {
	CommonRPCArgs
}

// ConnectPodRetval : type of the value returned by the ConnectPod RPC method.
type ConnectPodRetval struct {
	UseDHCP    bool
	Interfaces []NetworkInterface
}

// NetworkInterface : single network interface (configured by zedrouter).
type NetworkInterface struct {
	Name   string
	MAC    net.HardwareAddr
	NsPath string
}

// ConnectPod : establish L2 connection between pod and network instance.
func (h *RPCServer) ConnectPod(args ConnectPodArgs, retval *ConnectPodRetval) error {
	h.zedrouter.log.Noticef("RPC call: ConnectPod (%+v)", args)
	req := &rpcRequest{request: ConnectPodRequest{Args: args, Retval: retval}}
	err := req.submitAndWait(h.zedrouter, defaultRPCTimeout)
	if err == nil {
		h.zedrouter.log.Noticef("RPC call: ConnectPod (%+v) returned: %v", args, retval)
	} else {
		h.zedrouter.log.Errorf("RPC call: ConnectPod (%+v) failed: %v", args, err)
	}
	return err
}

func (z *zedrouter) handleConnectPodRequest(
	args ConnectPodArgs, retval *ConnectPodRetval) error {
	/*
		appName, appUUIDPrefix, err := kubeapi.GetAppNameFromPodName(args.PodName)
		if err != nil {
			return err
		}
		for _, item := range z.pubAppNetworkStatus.GetAll() {
			status := item.(types.AppNetworkStatus)
			if status.DisplayName != appName ||
				!strings.HasPrefix(status.UUIDandVersion.UUID.String(), appUUIDPrefix) {
				continue
			}
			for _, ulStatus := range status.UnderlayNetworkList {
				if bytes.Equal(args.PodInterfaceMAC, ulStatus.Mac) {
					retval.HostIfName = ulStatus.Vif
					return nil
				}
			}
		}
		return fmt.Errorf("failed to find app network status for %s/%s/%s",
			args.PodNamespace, args.PodName, args.InterfaceMAC)
	*/
	// TODO
	return errors.New("not implemented")
}

// ConfigurePodIPRequest encapsulates args and retval for ConfigurePodIP RPC method.
type ConfigurePodIPRequest struct {
	Args   ConfigurePodIPArgs
	Retval *ConfigurePodIPRetval
}

// ConfigurePodIPArgs : arguments for the ConfigurePodIP RPC method.
type ConfigurePodIPArgs struct {
	CommonRPCArgs
	IPs    []PodIPAddress
	Routes []PodRoute
	DNS    PodDNS
}

// ConfigurePodIPRetval : type of the value returned by the ConfigurePodIP RPC method.
type ConfigurePodIPRetval struct{}

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

// ConfigurePodIP : elevate a given L2 connection between pod and network instance
// into L3 by applying the submitted IP settings.
func (h *RPCServer) ConfigurePodIP(
	args ConfigurePodIPArgs, retval *ConfigurePodIPRetval) error {
	h.zedrouter.log.Noticef("RPC call: ConfigurePodIP (%+v)", args)
	req := &rpcRequest{request: ConfigurePodIPRequest{Args: args, Retval: retval}}
	err := req.submitAndWait(h.zedrouter, defaultRPCTimeout)
	if err == nil {
		h.zedrouter.log.Noticef("RPC call: ConfigurePodIP (%+v) returned: %v", args, retval)
	} else {
		h.zedrouter.log.Errorf("RPC call: ConfigurePodIP (%+v) failed: %v", args, err)
	}
	return err
}

func (z *zedrouter) handleConfigurePodIPRequest(
	args ConfigurePodIPArgs, retval *ConfigurePodIPRetval) error {
	// TODO
	return errors.New("not implemented")
}

// DisconnectPodRequest encapsulates args and retval for DisconnectPod RPC method.
type DisconnectPodRequest struct {
	Args   DisconnectPodArgs
	Retval *DisconnectPodRetval
}

// DisconnectPodArgs : arguments for the DisconnectPod RPC method.
type DisconnectPodArgs struct {
	CommonRPCArgs
}

// DisconnectPodRetval : type of the value returned by the DisconnectPod RPC method.
type DisconnectPodRetval struct {
	UsedDHCP bool
}

// DisconnectPod : un-configure the given connection between pod and network instance.
func (h *RPCServer) DisconnectPod(
	args DisconnectPodArgs, retval *DisconnectPodRetval) error {
	h.zedrouter.log.Noticef("RPC call: DisconnectPod (%+v)", args)
	req := &rpcRequest{request: DisconnectPodRequest{Args: args, Retval: retval}}
	err := req.submitAndWait(h.zedrouter, defaultRPCTimeout)
	if err == nil {
		h.zedrouter.log.Noticef("RPC call: DisconnectPod (%+v) returned: %v", args, retval)
	} else {
		h.zedrouter.log.Errorf("RPC call: DisconnectPod (%+v) failed: %v", args, err)
	}
	return err
}

func (z *zedrouter) handleDisconnectPodRequest(
	args DisconnectPodArgs, retval *DisconnectPodRetval) error {
	// TODO
	return errors.New("not implemented")
}

// CheckPodConnectionRequest encapsulates args and retval for CheckPodConnection RPC method.
type CheckPodConnectionRequest struct {
	Args   CheckPodConnectionArgs
	Retval *CheckPodConnectionRetval
}

// CheckPodConnectionArgs : arguments for the CheckPodConnection RPC method.
type CheckPodConnectionArgs struct {
	CommonRPCArgs
}

// CheckPodConnectionRetval : type of the value returned by the CheckPodConnection RPC method.
type CheckPodConnectionRetval struct {
	UsesDHCP bool
}

// CheckPodConnection : check if the given connection between pod and network instance
// is configured successfully.
func (h *RPCServer) CheckPodConnection(
	args CheckPodConnectionArgs, retval *CheckPodConnectionRetval) error {
	h.zedrouter.log.Noticef("RPC call: CheckPodConnection (%+v)", args)
	req := &rpcRequest{request: CheckPodConnectionRequest{Args: args, Retval: retval}}
	err := req.submitAndWait(h.zedrouter, defaultRPCTimeout)
	if err == nil {
		h.zedrouter.log.Noticef("RPC call: CheckPodConnection (%+v) returned: %v", args, retval)
	} else {
		h.zedrouter.log.Errorf("RPC call: CheckPodConnection (%+v) failed: %v", args, err)
	}
	return err
}

func (z *zedrouter) handleCheckPodConnectionRequest(
	args CheckPodConnectionArgs, retval *CheckPodConnectionRetval) error {
	// TODO
	return errors.New("not implemented")
}

//////////////////////////// TODO: Remove all below:

func nadNameForNI(niStatus *types.NetworkInstanceStatus) string {
	// FC 1123 subdomain must consist of lower case alphanumeric characters
	name := strings.ToLower(niStatus.UUID.String())
	return name
}

func (z *zedrouter) createOrUpdateNADForNI(niStatus *types.NetworkInstanceStatus) error {
	var spec string
	switch niStatus.Type {
	case types.NetworkInstanceTypeSwitch:
		spec = z.getNADSpecForSwitchNI(niStatus)
	case types.NetworkInstanceTypeLocal:
		spec = z.getNADSpecForLocalNI(niStatus)
	default:
		return fmt.Errorf("createOrUpdateNADForNI: NI type %v is not supported", niStatus.Type)
	}
	niUUID := niStatus.UUID
	name := nadNameForNI(niStatus)
	err := kubeapi.CreateOrUpdateNAD(z.log, name, spec)
	z.netInstNADs[niUUID.String()] = &NAD{
		NI:       niUUID,
		jsonSpec: spec,
		created:  err == nil,
	}
	if err == nil {
		z.log.Noticef("createOrUpdateNADForNI succeeded for NI %v/%v",
			niUUID, niStatus.DisplayName)
	} else {
		z.log.Errorf("createOrUpdateNADForNI failed for NI %v/%v: %v",
			niUUID, niStatus.DisplayName, err)
	}
	return err
}

func (z *zedrouter) getNADSpecForSwitchNI(niStatus *types.NetworkInstanceStatus) string {
	pluginName := "bridge-" + niStatus.BridgeName
	pluginBridge := niStatus.BridgeName
	macAddress := niStatus.BridgeMac
	return fmt.Sprintf(
		`{
    "cniVersion": "0.3.1",
    "plugins": [
      {
        "name": "%s",
        "type": "bridge",
        "bridge": "%s",
        "isDefaultGateway": false,
        "ipMasq": false,
        "hairpinMode": true,
        "mac": "%s",
        "ipam": {
          "type": "dhcp"
        }
      },
      {
        "capabilities": { "mac": true, "ips": true },
        "type": "tuning"
      },
      {
        "type": "eve-bridge"
      }
    ]
}`, pluginName, pluginBridge, macAddress)
}

func (z *zedrouter) getNADSpecForLocalNI(niStatus *types.NetworkInstanceStatus) string {
	pluginName := "bridge-" + niStatus.BridgeName
	pluginBridge := niStatus.BridgeName
	port := niStatus.PortLogicalLabel
	return fmt.Sprintf(
		`{
	"cniVersion": "0.3.1",
    "plugins": [
      {
        "name": "%s",
        "type": "bridge",
        "bridge": "%s",
        "isDefaultGateway": true,
        "ipMasq": false,
        "hairpinMode": true,
        "ipam": {
          "type": "dhcp"
        }
      },
      {
        "capabilities": { "mac": true, "ips": true },
        "type": "tuning"
      },
      {
        "port": "%s",
        "type": "eve-bridge"
      }
    ]
}`, pluginName, pluginBridge, port)
}

func (z *zedrouter) deleteNADForNI(niStatus *types.NetworkInstanceStatus) error {
	niUUID := niStatus.UUID
	name := nadNameForNI(niStatus)
	nad, exists := z.netInstNADs[niUUID.String()]
	if !exists {
		return nil
	}
	var err error
	if nad.created {
		err = kubeapi.DeleteNAD(z.log, name)
	}
	if err == nil {
		delete(z.netInstNADs, niUUID.String())
		z.log.Noticef("deleteNADForNI succeeded for NI %v/%v",
			niUUID, niStatus.DisplayName)
	} else {
		z.log.Errorf("deleteNADForNI failed for NI %v/%v: %v",
			niUUID, niStatus.DisplayName, err)
	}
	return err
}
