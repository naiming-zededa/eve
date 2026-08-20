// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	netattdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Synthesizing AppNetworkConfig for directly-deployed Kubernetes workloads.
//
// Such workloads (raw yaml / helm charts) have no controller-assigned AppInstanceConfig, so
// zedrouter has no AppNetworkConfig to drive MAC/IP allocation and to match inbound CNI
// requests against. zedkube fills that gap: it watches the pods scheduled on THIS node that
// attach to a per-NI NAD ("eve-kube-app/ni-<...>") and publishes a synthesized
// types.AppNetworkConfig (with KubeApp set) which zedrouter consumes through its normal
// pipeline (subKubeAppNetworkConfig -> handleAppNetworkCreate -> doActivateAppNetwork).
//
// Node scope: like controller-managed clustered apps (see zedmanager getKubeAppActivateStatus),
// the network is activated only on the node where the workload runs. Each node publishes to its
// OWN local zedrouter; this is deliberately NOT leader-gated (contrast with the cluster-wide NAD
// in ninad.go). On migration the pod reappears on another node, whose zedkube then publishes;
// the CNI plugin's own retries cover the brief gap.
//
// Identity: the synthetic appUUID is base.KubeAppUUID(namespace, ownerName), where ownerName is
// the workload's controlling owner (the bare ReplicaSet for an RS-style app), or the pod name
// itself for an ownerless bare Pod. It is a pure function of stable metadata, so every node and
// every restart derive the same UUID -> the ClusterDeterministic MAC stays stable across reboot
// and migration. A same-named bare Pod therefore retains its network identity when recreated.
// For a Deployment Pod, the immediate ReplicaSet owner remains the network identity while the
// controlling Deployment name is used as the human-facing AppNetworkConfig display/DNS name.
//
// VMIs (virt-launcher pods) are intentionally skipped here: their pod name is
// "virt-launcher-<vmi>-<rand>", which the zedrouter matcher (KubePodMatchesOwner) does not yet
// resolve. RS-style workloads are the supported shape; VMI support is a follow-up.

const networksAnnotation = "k8s.v1.cni.cncf.io/networks"

// portMapAnnotation lets a directly-deployed workload publish port-maps (physical-port external
// port -> app target port). Value is a JSON array, e.g.
//
//	eve.zededa.com/portmap: '[{"protocol":"tcp","externalPort":8080,"targetPort":80}]'
const portMapAnnotation = "eve.zededa.com/portmap"

// kubeAppMarkerDir holds one empty marker file per native ZKS workload pod scheduled on this
// node that attaches to a per-NI NAD. eve-bridge stats "<dir>/<namespace>_<podname>" at
// eth0-CNI time to classify the pod as native ZKS and preserve the primary eth0 default route,
// including for pods outside the eve-kube-app namespace. THIS PATH IS A CONTRACT shared with
// pkg/kube/eve-bridge.
const kubeAppMarkerDir = "/run/zedkube/kubeapp-net"

// portMapSpec is the user-facing port-map shape parsed from portMapAnnotation.
type portMapSpec struct {
	Protocol     string `json:"protocol"`
	ExternalPort int    `json:"externalPort"`
	TargetPort   int    `json:"targetPort"`
}

// reconcileKubeAppNetworks lists the pods scheduled on this node and (re)publishes a synthesized
// AppNetworkConfig for each directly-deployed workload attaching to a per-NI NAD, unpublishing
// configs whose workload no longer runs here.
func (z *zedkube) reconcileKubeAppNetworks() {
	z.reconcileKubeAppNetworksWithClient(getKubeClientSet)
}

func (z *zedkube) reconcileKubeAppNetworksWithClient(
	getClient func() (*kubernetes.Clientset, error)) {
	if !z.clusterConfig.NativeK8sOrchestrationEnabled() {
		return
	}
	if z.nodeName == "" {
		// Node identity not known yet; nothing to reconcile against.
		return
	}
	clientset, err := getClient()
	if err != nil {
		log.Errorf("reconcileKubeAppNetworks: clientset: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + z.nodeName,
	})
	if err != nil {
		log.Errorf("reconcileKubeAppNetworks: list pods on %s: %v", z.nodeName, err)
		return
	}
	replicaSets, err := clientset.AppsV1().ReplicaSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		// Keep networking functional if owner lookup temporarily fails. DNS names will use
		// the immediate ReplicaSet owner until a later reconciliation succeeds.
		log.Warnf("reconcileKubeAppNetworks: list ReplicaSets: %v", err)
	}
	var deploymentNames map[string]string
	if replicaSets != nil {
		deploymentNames = deploymentNamesByReplicaSet(replicaSets.Items)
	}

	desired := make(map[string]types.AppNetworkConfig)
	markers := make(map[string]bool)
	for i := range pods.Items {
		pod := &pods.Items[i]
		config, ok := z.kubeAppNetConfigForPod(pod, deploymentNames)
		if ok {
			desired[config.Key()] = config
			markers[kubeAppMarkerName(pod.Namespace, pod.Name)] = true
		}
	}

	for key, config := range desired {
		c := config
		if err := z.pubKubeAppNetworkConfig.Publish(key, c); err != nil {
			log.Errorf("reconcileKubeAppNetworks: publish %s: %v", key, err)
		}
	}
	for key := range z.pubKubeAppNetworkConfig.GetAll() {
		if _, ok := desired[key]; !ok {
			if err := z.pubKubeAppNetworkConfig.Unpublish(key); err != nil {
				log.Errorf("reconcileKubeAppNetworks: unpublish %s: %v", key, err)
			}
		}
	}
	reconcileKubeAppMarkers(markers)
}

// kubeAppNetConfigForPod builds the synthesized AppNetworkConfig for a single pod, or returns
// ok=false if the pod is not a directly-deployed workload attaching to a per-NI NAD.
func (z *zedkube) kubeAppNetConfigForPod(pod *corev1.Pod,
	deploymentNames map[string]string) (types.AppNetworkConfig, bool) {
	// VMIs are out of scope for now (see file comment).
	if strings.HasPrefix(pod.Name, base.VMIPodNamePrefix) {
		return types.AppNetworkConfig{}, false
	}
	sels := parseNetworksAnnotation(pod.Annotations[networksAnnotation])
	if len(sels) == 0 {
		return types.AppNetworkConfig{}, false
	}
	var adapters []types.AppNetAdapterConfig
	niIfIdx := make(map[uuid.UUID]uint32)
	for _, sel := range sels {
		niUUID, ok := z.niUUIDForNAD(sel.Namespace, sel.Name)
		if !ok {
			continue
		}
		var mac net.HardwareAddr
		if sel.MacRequest != "" {
			if parsed, err := net.ParseMAC(sel.MacRequest); err == nil {
				mac = parsed
			} else {
				log.Warnf("kubeAppNetConfigForPod: pod %s/%s bad mac %q: %v",
					pod.Namespace, pod.Name, sel.MacRequest, err)
			}
		}
		idx := len(adapters)
		adapters = append(adapters, types.AppNetAdapterConfig{
			Name:       fmt.Sprintf("net%d", idx),
			Network:    niUUID,
			AppMacAddr: mac,
			IntfOrder:  uint32(idx),
			IfIdx:      niIfIdx[niUUID],
			// A synthesized config with an empty ACL list would be DEFAULT-DROP in zedrouter
			// (all traffic blocked except DHCP/DNS), so attach a permissive default plus any
			// user-requested port-maps. The same set is applied to every adapter.
			ACLs: buildKubeAppACLs(pod),
		})
		niIfIdx[niUUID]++
	}
	if len(adapters) == 0 {
		return types.AppNetworkConfig{}, false
	}

	// Keep the immediate controller name as the network identity. For Deployment Pods this is
	// the ReplicaSet name, which prevents old and new rollout generations from sharing a MAC.
	// Use the Deployment name only as the human-facing display/DNS name.
	ownerName, displayName := kubeAppNames(pod, deploymentNames)
	appUUID := base.KubeAppUUID(pod.Namespace, ownerName)
	return types.AppNetworkConfig{
		UUIDandVersion:    types.UUIDandVersion{UUID: appUUID, Version: "1"},
		DisplayName:       displayName,
		Activate:          true,
		AppNetAdapterList: adapters,
		KubeApp: &types.KubeAppInfo{
			Namespace: pod.Namespace,
			OwnerName: ownerName,
		},
	}, true
}

// deploymentNamesByReplicaSet maps "namespace/replicaset" to the name of its controlling
// Deployment. A directly-created ReplicaSet has no entry and therefore keeps its own name.
func deploymentNamesByReplicaSet(replicaSets []appsv1.ReplicaSet) map[string]string {
	names := make(map[string]string)
	for i := range replicaSets {
		rs := &replicaSets[i]
		for _, ref := range rs.OwnerReferences {
			if ref.Controller != nil && *ref.Controller && ref.Kind == "Deployment" {
				names[rs.Namespace+"/"+rs.Name] = ref.Name
				break
			}
		}
	}
	return names
}

// kubeAppNames returns the stable immediate-controller identity used for Pod matching and MAC
// generation, plus a human-facing display name used by DNS and status reporting.
func kubeAppNames(pod *corev1.Pod, deploymentNames map[string]string) (
	ownerName, displayName string) {
	ownerName = pod.Name
	displayName = pod.Name
	for _, ref := range pod.OwnerReferences {
		if ref.Controller == nil || !*ref.Controller {
			continue
		}
		ownerName = ref.Name
		displayName = ownerName
		if ref.Kind == "ReplicaSet" {
			if deploymentName := deploymentNames[pod.Namespace+"/"+ownerName]; deploymentName != "" {
				displayName = deploymentName
			}
		}
		break
	}
	return ownerName, displayName
}

// niUUIDForNAD maps a NAD reference ("<namespace>/<name>") from a workload's networks annotation
// to the UUID of the EVE Network Instance it represents. Only NADs in the eve-kube-app namespace
// named by niNADName() (the per-NI NADs created in ninad.go) are matched.
func (z *zedkube) niUUIDForNAD(namespace, nadName string) (uuid.UUID, bool) {
	var statuses []types.NetworkInstanceStatus
	for _, item := range z.subNetworkInstanceStatus.GetAll() {
		statuses = append(statuses, item.(types.NetworkInstanceStatus))
	}
	return niUUIDForNADStatuses(namespace, nadName, statuses)
}

func niUUIDForNADStatuses(namespace, nadName string,
	statuses []types.NetworkInstanceStatus) (uuid.UUID, bool) {
	if namespace != kubeapi.EVEKubeNameSpace {
		return uuid.UUID{}, false
	}
	for _, status := range statuses {
		if niNADApplicable(status) && niNADName(status) == nadName {
			return status.UUIDandVersion.UUID, true
		}
	}
	return uuid.UUID{}, false
}

// parseNetworksAnnotation parses the Multus "k8s.v1.cni.cncf.io/networks" annotation in either
// supported form: a JSON array of NetworkSelectionElement, or a comma-separated list of
// "[namespace/]name[@interface]" entries.
func parseNetworksAnnotation(val string) []netattdefv1.NetworkSelectionElement {
	val = strings.TrimSpace(val)
	if val == "" {
		return nil
	}
	if strings.HasPrefix(val, "[") {
		var sels []netattdefv1.NetworkSelectionElement
		if err := json.Unmarshal([]byte(val), &sels); err != nil {
			log.Warnf("parseNetworksAnnotation: bad JSON %q: %v", val, err)
			return nil
		}
		return sels
	}
	var sels []netattdefv1.NetworkSelectionElement
	for _, part := range strings.Split(val, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if at := strings.Index(part, "@"); at >= 0 {
			part = part[:at]
		}
		var namespace, name string
		if slash := strings.Index(part, "/"); slash >= 0 {
			namespace, name = part[:slash], part[slash+1:]
		} else {
			name = part
		}
		sels = append(sels, netattdefv1.NetworkSelectionElement{
			Namespace: namespace,
			Name:      name,
		})
	}
	return sels
}

// buildKubeAppACLs returns the ACEs for a synthesized adapter. zedrouter treats an empty ACL
// list as default-DROP, so we always include a permissive allow-all rule (no match => matches
// every IPv4/IPv6 flow; no action => ALLOW) to give the workload connectivity, then append any
// port-maps declared via the portMapAnnotation. Restrictive/deny policies are a future addition.
func buildKubeAppACLs(pod *corev1.Pod) []types.ACE {
	acls := []types.ACE{{
		RuleID:  1,
		Name:    "kubeapp-allow-all",
		Dir:     types.AceDirBoth,
		Matches: []types.ACEMatch{{Type: "ip", Value: "0.0.0.0/0"}},
		// No Actions => default ALLOW. This is the canonical allow-all match controllers use;
		// it covers IPv4 (local NIs are IPv4 here), leaving the implicit default-DROP for IPv6.
	}}
	for i, pm := range parsePortMaps(pod.Annotations[portMapAnnotation]) {
		acls = append(acls, types.ACE{
			RuleID: int32(100 + i),
			Name:   fmt.Sprintf("portmap-%s-%d", pm.Protocol, pm.ExternalPort),
			Dir:    types.AceDirIngress,
			Matches: []types.ACEMatch{
				{Type: "protocol", Value: pm.Protocol},
				{Type: "lport", Value: strconv.Itoa(pm.ExternalPort)},
			},
			Actions: []types.ACEAction{
				{PortMap: true, TargetPort: pm.TargetPort},
			},
		})
	}
	return acls
}

// parsePortMaps parses and validates the portMapAnnotation JSON array.
func parsePortMaps(val string) []portMapSpec {
	val = strings.TrimSpace(val)
	if val == "" {
		return nil
	}
	var pms []portMapSpec
	if err := json.Unmarshal([]byte(val), &pms); err != nil {
		log.Warnf("parsePortMaps: bad JSON %q: %v", val, err)
		return nil
	}
	var out []portMapSpec
	for _, pm := range pms {
		pm.Protocol = strings.ToLower(strings.TrimSpace(pm.Protocol))
		if (pm.Protocol != "tcp" && pm.Protocol != "udp") ||
			pm.ExternalPort <= 0 || pm.ExternalPort > 65535 ||
			pm.TargetPort <= 0 || pm.TargetPort > 65535 {
			log.Warnf("parsePortMaps: skipping invalid portmap %+v", pm)
			continue
		}
		out = append(out, pm)
	}
	return out
}

// kubeAppMarkerName is the marker filename (under kubeAppMarkerDir) for a managed pod.
func kubeAppMarkerName(namespace, podName string) string {
	return namespace + "_" + podName
}

// reconcileKubeAppMarkers writes one empty marker file per currently-managed pod and removes
// markers for pods that are no longer managed on this node. eve-bridge reads these to classify
// native ZKS workloads and preserve the primary eth0 default route outside the eve-kube-app
// namespace.
func reconcileKubeAppMarkers(desired map[string]bool) {
	if err := os.MkdirAll(kubeAppMarkerDir, 0755); err != nil {
		log.Errorf("reconcileKubeAppMarkers: mkdir %s: %v", kubeAppMarkerDir, err)
		return
	}
	for name := range desired {
		path := filepath.Join(kubeAppMarkerDir, name)
		if err := os.WriteFile(path, nil, 0644); err != nil {
			log.Errorf("reconcileKubeAppMarkers: write %s: %v", path, err)
		}
	}
	entries, err := os.ReadDir(kubeAppMarkerDir)
	if err != nil {
		log.Errorf("reconcileKubeAppMarkers: read %s: %v", kubeAppMarkerDir, err)
		return
	}
	for _, e := range entries {
		if !desired[e.Name()] {
			if err := os.Remove(filepath.Join(kubeAppMarkerDir, e.Name())); err != nil {
				log.Errorf("reconcileKubeAppMarkers: remove %s: %v", e.Name(), err)
			}
		}
	}
}
