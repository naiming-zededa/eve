// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/nireconciler"
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

// connectPodAtL2Request encapsulates args and retval for ConnectPodAtL2 RPC method.
type connectPodAtL2Request struct {
	args   types.ConnectPodAtL2Args
	retval *types.ConnectPodAtL2Retval
}

// connectPodAtL3Request encapsulates args and retval for ConnectPodAtL3 RPC method.
type connectPodAtL3Request struct {
	args   types.ConnectPodAtL3Args
	retval *types.ConnectPodAtL3Retval
}

// disconnectPodRequest encapsulates args and retval for DisconnectPod RPC method.
type disconnectPodRequest struct {
	args   types.DisconnectPodArgs
	retval *types.DisconnectPodRetval
}

// checkPodConnectionRequest encapsulates args and retval for CheckPodConnection RPC method.
type checkPodConnectionRequest struct {
	args   types.CheckPodConnectionArgs
	retval *types.CheckPodConnectionRetval
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
	case connectPodAtL2Request:
		l2Only := types.PodIPAMConfig{}
		request.retval.UseDHCP, request.retval.Interfaces, err =
			z.handleConnectPodRequest(request.args.Pod, request.args.PodInterface, l2Only)
	case connectPodAtL3Request:
		_, _, err = z.handleConnectPodRequest(request.args.Pod,
			request.args.PodInterface, request.args.PodIPAMConfig)
	case disconnectPodRequest:
		err = z.handleDisconnectPodRequest(request.args, request.retval)
	case checkPodConnectionRequest:
		err = z.handleCheckPodConnectionRequest(request.args, request.retval)
	default:
		err = fmt.Errorf("unhandled RPC request %T: %v", request, request)
	}
	if err != nil {
		z.log.Error(err)
	}
	rpc.markDone(err)
}

// Used for both connectPodAtL2Request and connectPodAtL3Request.
// Will setup L3 connectivity if ipamConfig is defined, L2-only otherwise.
func (z *zedrouter) handleConnectPodRequest(pod types.AppPod,
	podInterface types.NetInterfaceWithNs, ipamConfig types.PodIPAMConfig) (
	niWithDHCP bool, interfaces []types.NetInterfaceWithNs, err error) {
	appConfig, appStatus, err := z.getAppByPodName(pod.Name)
	if err != nil {
		z.log.Error(err)
		return false, nil, err
	}
	appStatus.AppPod = pod
	var ulStatus *types.UnderlayNetworkStatus
	for i := range appStatus.UnderlayNetworkList {
		ulStatus = &appStatus.UnderlayNetworkList[i]
		if bytes.Equal(podInterface.MAC, ulStatus.Mac) {
			break
		}
		ulStatus = nil
	}
	if ulStatus == nil {
		err = fmt.Errorf("failed to find adapter with MAC %s for app %v",
			podInterface.MAC, appStatus.UUIDandVersion.UUID)
		z.log.Error(err)
		return false, nil, err
	}
	ulStatus.PodVif.GuestIfName = podInterface.Name
	ulStatus.PodVif.IPAM = ipamConfig
	z.publishAppNetworkStatus(appStatus)
	// Tell CNI plugin to use dhcp IPAM unless this is an air-gapped switch NI.
	netInstStatus := z.lookupNetworkInstanceStatus(ulStatus.Network.String())
	if netInstStatus == nil {
		// Should be unreachable.
		err = fmt.Errorf("missing network instance status for %s",
			ulStatus.Network.String())
		z.log.Error(err)
		return false, nil, err
	}
	niWithDHCP = z.niWithDHCP(netInstStatus)
	// Try to setup pod connectivity (L2 or L3).
	vifs, err := z.prepareConfigForVIFs(*appConfig, appStatus)
	if err != nil {
		z.log.Error(err)
		return false, nil, err
	}
	appConnRecStatus, err := z.niReconciler.UpdateAppConn(
		z.runCtx, *appConfig, appStatus.AppPod, vifs)
	if err != nil {
		z.log.Error(err)
		return false, nil, err
	}
	var vifStatus *nireconciler.AppVIFReconcileStatus
	for _, vif := range appConnRecStatus.VIFs {
		if vif.NetAdapterName == ulStatus.Name {
			vifStatus = &vif
			break
		}
	}
	if vifStatus == nil {
		err = fmt.Errorf("missing VIF status for adapter %s", ulStatus.Name)
		z.log.Error(err)
		return false, nil, err
	}
	if vifStatus.InProgress {
		// It is not expected that some config items are created asynchronously.
		err = fmt.Errorf("some config items related to VIF %v/%s are still in progress",
			appStatus.UUIDandVersion.UUID, ulStatus.Name)
		z.log.Error(err)
		return false, nil, err
	}
	var failedItems []string
	for itemRef, itemErr := range vifStatus.FailedItems {
		failedItems = append(failedItems, fmt.Sprintf("%v (%v)", itemRef, itemErr))
	}
	if len(failedItems) > 0 {
		err = fmt.Errorf("failed config items: %s", strings.Join(failedItems, ";"))
		z.log.Error(err)
		return false, nil, err
	}
	interfaces = append(interfaces, types.NetInterfaceWithNs{
		Name: netInstStatus.BridgeName,
		MAC:  netInstStatus.BridgeMac,
	})
	interfaces = append(interfaces, types.NetInterfaceWithNs{
		Name: vifStatus.HostIfName,
		// MAC on the host side is not published by NI Reconciler.
		// Most likely it is not needed anyway.
	})
	interfaces = append(interfaces, podInterface)
	return niWithDHCP, interfaces, nil
}

func (z *zedrouter) handleDisconnectPodRequest(
	args types.DisconnectPodArgs, retval *types.DisconnectPodRetval) error {
	appConfig, appStatus, err := z.getAppByPodName(args.Pod.Name)
	if err != nil {
		// App is already removed.
		// Most likely we got a duplicate CNI DEL call, which is allowed by the CNI spec.
		// According to the spec, we should not return error in this case.
		z.log.Warn(err)
		return nil
	}
	var ulStatus *types.UnderlayNetworkStatus
	for i := range appStatus.UnderlayNetworkList {
		ulStatus = &appStatus.UnderlayNetworkList[i]
		if ulStatus.PodVif.GuestIfName == args.PodInterface.Name {
			break
		}
		ulStatus = nil
	}
	if ulStatus == nil {
		// VIF is already removed.
		// Most likely we got a duplicate CNI DEL call, which is allowed by the CNI spec.
		// According to the spec, we should not return error in this case.
		z.log.Warnf("failed to find adapter with pod interface %s for app %v",
			args.PodInterface.Name, appStatus.UUIDandVersion.UUID)
		return nil
	}
	// Remove pod VIF from the config.
	ulStatus.PodVif = types.PodVIF{}
	z.publishAppNetworkStatus(appStatus)
	// Find out if DHCP was being used.
	netInstStatus := z.lookupNetworkInstanceStatus(ulStatus.Network.String())
	if netInstStatus == nil {
		// Should be unreachable.
		err = fmt.Errorf("missing network instance status for %s",
			ulStatus.Network.String())
		z.log.Error(err)
		return err
	}
	retval.UsedDHCP = z.niWithDHCP(netInstStatus)
	// Try to remove pod connectivity.
	vifs, err := z.prepareConfigForVIFs(*appConfig, appStatus)
	if err != nil {
		z.log.Error(err)
		return err
	}
	_, err = z.niReconciler.UpdateAppConn(
		z.runCtx, *appConfig, appStatus.AppPod, vifs)
	if err != nil {
		z.log.Error(err)
		return err
	}
	return nil
}

func (z *zedrouter) handleCheckPodConnectionRequest(
	args types.CheckPodConnectionArgs, retval *types.CheckPodConnectionRetval) error {
	_, appStatus, err := z.getAppByPodName(args.Pod.Name)
	if err != nil {
		z.log.Error(err)
		return err
	}
	var ulStatus *types.UnderlayNetworkStatus
	for i := range appStatus.UnderlayNetworkList {
		ulStatus = &appStatus.UnderlayNetworkList[i]
		if ulStatus.PodVif.GuestIfName == args.PodInterface.Name {
			break
		}
		ulStatus = nil
	}
	if ulStatus == nil {
		err = fmt.Errorf("failed to find adapter with pod interface %s for app %v",
			args.PodInterface.Name, appStatus.UUIDandVersion.UUID)
		z.log.Error(err)
		return err
	}
	// Find out if DHCP is being used.
	netInstStatus := z.lookupNetworkInstanceStatus(ulStatus.Network.String())
	if netInstStatus == nil {
		// Should be unreachable.
		err = fmt.Errorf("missing network instance status for %s",
			ulStatus.Network.String())
		z.log.Error(err)
		return err
	}
	retval.UsesDHCP = z.niWithDHCP(netInstStatus)
	// Check the state of the connection configuration in the network stack.
	appConnRecStatus, err := z.niReconciler.GetAppConnStatus(appStatus.UUIDandVersion.UUID)
	if err != nil {
		z.log.Error(err)
		return err
	}
	var vifStatus *nireconciler.AppVIFReconcileStatus
	for _, vif := range appConnRecStatus.VIFs {
		if vif.NetAdapterName == ulStatus.Name {
			vifStatus = &vif
			break
		}
	}
	if vifStatus == nil {
		err = fmt.Errorf("missing VIF status for adapter %s", ulStatus.Name)
		z.log.Error(err)
		return err
	}
	if vifStatus.InProgress {
		// It is not expected that some config items are created asynchronously.
		err = fmt.Errorf("some config items related to VIF %v/%s are still in progress",
			appStatus.UUIDandVersion.UUID, ulStatus.Name)
		z.log.Error(err)
		return err
	}
	var failedItems []string
	for itemRef, itemErr := range vifStatus.FailedItems {
		failedItems = append(failedItems, fmt.Sprintf("%v (%v)", itemRef, itemErr))
	}
	if len(failedItems) > 0 {
		err = fmt.Errorf("failed config items: %s", strings.Join(failedItems, ";"))
		z.log.Error(err)
		return err
	}
	return nil
}

func (z *zedrouter) niWithDHCP(netInstStatus *types.NetworkInstanceStatus) bool {
	airGapped := netInstStatus.PortLogicalLabel == ""
	switchNI := netInstStatus.Type == types.NetworkInstanceTypeSwitch
	return !switchNI || !airGapped
}

func (z *zedrouter) getAppByPodName(
	podName string) (*types.AppNetworkConfig, *types.AppNetworkStatus, error) {
	appName, appUUIDPrefix, err := kubeapi.GetAppNameFromPodName(podName)
	if err != nil {
		return nil, nil, err
	}
	for _, item := range z.pubAppNetworkStatus.GetAll() {
		appStatus := item.(types.AppNetworkStatus)
		if appStatus.DisplayName == appName &&
			strings.HasPrefix(appStatus.UUIDandVersion.UUID.String(), appUUIDPrefix) {
			appConfig := z.lookupAppNetworkConfig(appStatus.Key())
			if appConfig == nil {
				return nil, nil, fmt.Errorf("missing network config for app %v",
					appStatus.UUIDandVersion.UUID)
			}
			return appConfig, &appStatus, nil
		}
	}
	return nil, nil, fmt.Errorf("failed to find app network status for pod %s", podName)
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

// RPCServer receives RPC calls from eve-bridge CNI and dispatches them to the main
// event loop of zedrouter.
type RPCServer struct {
	zedrouter *zedrouter
}

// ConnectPodAtL2 : establish L2 connection between pod and network instance.
func (h *RPCServer) ConnectPodAtL2(
	args types.ConnectPodAtL2Args, retval *types.ConnectPodAtL2Retval) error {
	h.zedrouter.log.Noticef("RPC call: ConnectPodAtL2 (%+v)", args)
	req := &rpcRequest{request: connectPodAtL2Request{args: args, retval: retval}}
	err := req.submitAndWait(h.zedrouter, defaultRPCTimeout)
	if err == nil {
		h.zedrouter.log.Noticef("RPC call: ConnectPodAtL2 (%+v) returned: %v", args, retval)
	} else {
		h.zedrouter.log.Errorf("RPC call: ConnectPodAtL2 (%+v) failed: %v", args, err)
	}
	return err
}

// ConnectPodAtL3 : establish L3 connection between pod and network instance.
// Typically, it is used after ConnectPodAtL2 to elevate existing L2 connection
// into L3 by applying the submitted IP settings.
func (h *RPCServer) ConnectPodAtL3(
	args types.ConnectPodAtL3Args, retval *types.ConnectPodAtL3Retval) error {
	h.zedrouter.log.Noticef("RPC call: ConnectPodAtL3 (%+v)", args)
	req := &rpcRequest{request: connectPodAtL3Request{args: args, retval: retval}}
	err := req.submitAndWait(h.zedrouter, defaultRPCTimeout)
	if err == nil {
		h.zedrouter.log.Noticef("RPC call: ConnectPodAtL3 (%+v) returned: %v", args, retval)
	} else {
		h.zedrouter.log.Errorf("RPC call: ConnectPodAtL3 (%+v) failed: %v", args, err)
	}
	return err
}

// DisconnectPod : un-configure the given connection between pod and network instance.
func (h *RPCServer) DisconnectPod(
	args types.DisconnectPodArgs, retval *types.DisconnectPodRetval) error {
	h.zedrouter.log.Noticef("RPC call: DisconnectPod (%+v)", args)
	req := &rpcRequest{request: disconnectPodRequest{args: args, retval: retval}}
	err := req.submitAndWait(h.zedrouter, defaultRPCTimeout)
	if err == nil {
		h.zedrouter.log.Noticef("RPC call: DisconnectPod (%+v) returned: %v", args, retval)
	} else {
		h.zedrouter.log.Errorf("RPC call: DisconnectPod (%+v) failed: %v", args, err)
	}
	return err
}

// CheckPodConnection : check if the given connection between pod and network instance
// is configured successfully.
func (h *RPCServer) CheckPodConnection(
	args types.CheckPodConnectionArgs, retval *types.CheckPodConnectionRetval) error {
	h.zedrouter.log.Noticef("RPC call: CheckPodConnection (%+v)", args)
	req := &rpcRequest{request: checkPodConnectionRequest{args: args, retval: retval}}
	err := req.submitAndWait(h.zedrouter, defaultRPCTimeout)
	if err == nil {
		h.zedrouter.log.Noticef("RPC call: CheckPodConnection (%+v) returned: %v", args, retval)
	} else {
		h.zedrouter.log.Errorf("RPC call: CheckPodConnection (%+v) failed: %v", args, err)
	}
	return err
}
