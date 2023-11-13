// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

import (
	"context"
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
	rpcSocketPath = runDirname + "/rpc.sock"
)

func nadNameForNI(niStatus *types.NetworkInstanceStatus) string {
	// FC 1123 subdomain must consist of lower case alphanumeric characters
	name := strings.ToLower(niStatus.UUID.String())
	return name
}

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

type GetHostIfNameRequest struct {
	Args   GetHostIfNameArgs
	Retval *GetHostIfNameRetval
}

type GetHostIfNameArgs struct {
	PodName      string
	PodNamespace string
	InterfaceMAC string
}

type GetHostIfNameRetval struct {
	HostIfName string
}

// RPCServer receives RPC calls from eve-bridge CNI and dispatches them to the main
// event loop of zedrouter.
type RPCServer struct {
	zedrouter *zedrouter
}

func (h *RPCServer) GetHostIfName(args GetHostIfNameArgs, retval *GetHostIfNameRetval) error {
	h.zedrouter.log.Noticef("RPC call: GetHostIfName (%+v)", args)
	req := &rpcRequest{request: GetHostIfNameRequest{Args: args, Retval: retval}}
	err := req.submitAndWait(h.zedrouter, 10*time.Second)
	if err == nil {
		h.zedrouter.log.Noticef("RPC call: GetHostIfName (%+v) returned: %v", args, retval)
	} else {
		h.zedrouter.log.Noticef("RPC call: GetHostIfName (%+v) failed: %v", args, err)
	}
	return err
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

// Handle RPC request from the zedrouter main event loop.
func (z *zedrouter) handleRPC(rpc *rpcRequest) {
	switch request := rpc.request.(type) {
	case GetHostIfNameRequest:
		err := z.handleGetHostIfName(request.Args, request.Retval)
		rpc.markDone(err)
	default:
		z.log.Errorf("Unhandled RPC request %T: %v", request, request)
	}
}

func (z *zedrouter) handleGetHostIfName(
	args GetHostIfNameArgs, retval *GetHostIfNameRetval) error {
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
			if args.InterfaceMAC == ulStatus.Mac.String() {
				retval.HostIfName = ulStatus.Vif
				return nil
			}
		}
	}
	return fmt.Errorf("failed to find app network status for %s/%s/%s",
		args.PodNamespace, args.PodName, args.InterfaceMAC)
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
