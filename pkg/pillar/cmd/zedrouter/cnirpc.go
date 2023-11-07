package zedrouter

import (
	"fmt"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	rpcSocketPath    = runDirname + "/rpc.sock"
	vmiPodNamePrefix = "virt-launcher-"
)

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
