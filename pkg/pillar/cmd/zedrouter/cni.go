// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

import (
	"fmt"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	rpcSocketPath    = runDirname + "/rpc.sock"
	vmiPodNamePrefix = "virt-launcher-"
)

func nadNameForNI(niStatus *types.NetworkInstanceStatus) string {
	// FC 1123 subdomain must consist of lower case alphanumeric characters
	name := strings.ToLower(niStatus.UUID.String())
	return name
}

type GetHostIfNameArgs struct {
	PodName      string
	PodNamespace string
	InterfaceMAC string
}

type GetHostIfNameRetval struct {
	HostIfName string
}

type ZedrouterRPCHandler struct {
	zedrouter *zedrouter
}

// GetAppNameFromPodName : get application display name and also prefix of the UUID
// from the pod name.
// TODO: move this function to pkg/kubeapi
func (h *ZedrouterRPCHandler) GetAppNameFromPodName(
	podName string) (displayName, uuidPrefix string, err error) {
	if strings.HasPrefix(podName, vmiPodNamePrefix) {
		suffix := strings.TrimPrefix(podName, vmiPodNamePrefix)
		lastSep := strings.LastIndex(suffix, "-")
		if lastSep == -1 {
			err = fmt.Errorf("unexpected pod name generated for VMI: %s", podName)
			return "", "", err
		}
		podName = suffix[:lastSep]
	}
	lastSep := strings.LastIndex(podName, "-")
	if lastSep == -1 {
		err = fmt.Errorf("pod name without dash separator: %s", podName)
		return "", "", err
	}
	return podName[:lastSep], podName[lastSep+1:], nil
}

func (h *ZedrouterRPCHandler) GetHostIfName(args GetHostIfNameArgs, retval *GetHostIfNameRetval) error {
	h.zedrouter.log.Noticef("RPC call: GetHostIfName (%+v)", args)
	appName, appUUIDPrefix, err := h.GetAppNameFromPodName(args.PodName)
	if err != nil {
		return err
	}
	for _, item := range h.zedrouter.pubAppNetworkStatus.GetAll() {
		status := item.(types.AppNetworkStatus)
		if status.DisplayName != appName ||
			!strings.HasPrefix(status.UUIDandVersion.UUID.String(), appUUIDPrefix) {
			h.zedrouter.log.Noticef(
				"RPC call: GetHostIfName - app (%v) does not match pod %s",
				status.UUIDandVersion.UUID, args.PodName)
			continue
		}
		for _, ulStatus := range status.UnderlayNetworkList {
			if args.InterfaceMAC == ulStatus.Mac.String() {
				h.zedrouter.log.Noticef(
					"RPC call: GetHostIfName - app (%v) interface %s matches args %+v",
					status.UUIDandVersion.UUID, ulStatus.Vif, args)
				retval.HostIfName = ulStatus.Vif
				return nil
			}
		}
	}
	return fmt.Errorf("failed to find app network status for %s/%s/%s",
		args.PodNamespace, args.PodName, args.InterfaceMAC)
}

func (z *zedrouter) runRPCServer() error {
	handler := &ZedrouterRPCHandler{zedrouter: z}
	err := rpc.Register(handler)
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

////////////////////////////////////////////////////////////////////////////

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
	var update bool
	if nad, exists := z.netInstNADs[niUUID.String()]; exists {
		update = nad.created
	}
	var err error
	if update {
		err = kubeapi.UpdateNAD(z.log, name, spec)
	} else {
		err = kubeapi.CreateNAD(z.log, name, spec)
	}
	z.netInstNADs[niUUID.String()] = &NAD{
		NI:       niUUID,
		jsonSpec: spec,
		created:  update || err == nil,
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
`, pluginName, pluginBridge, port)
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
