// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"k8s.io/client-go/kubernetes"
)

func disabledNativeOrchestrationConfig() types.EdgeNodeClusterConfig {
	return types.EdgeNodeClusterConfig{
		ClusterType: types.ClusterTypeReplicatedStorage,
	}
}

func TestReconcileKubeAppNetworksDisabledDoesNotAcquireClient(t *testing.T) {
	z := &zedkube{
		nodeName:      "edge-node-1",
		clusterConfig: disabledNativeOrchestrationConfig(),
	}
	clientRequested := false
	z.reconcileKubeAppNetworksWithClient(func() (*kubernetes.Clientset, error) {
		clientRequested = true
		return nil, nil
	})
	if clientRequested {
		t.Fatal("disabled native orchestration acquired a Kubernetes client")
	}
}

func TestReconcileNINADDisabledDoesNotWrite(t *testing.T) {
	z := &zedkube{clusterConfig: disabledNativeOrchestrationConfig()}
	z.isKubeStatsLeader.Store(true)
	writeCalled := false
	z.reconcileNINADWithWriter(types.NetworkInstanceStatus{
		NetworkInstanceConfig: types.NetworkInstanceConfig{
			Type: types.NetworkInstanceTypeLocal,
		},
	}, func(_, _ string) error {
		writeCalled = true
		return nil
	})
	if writeCalled {
		t.Fatal("disabled native orchestration wrote a per-NI NAD")
	}
}

func TestRemoveNINADDisabledDoesNotDelete(t *testing.T) {
	z := &zedkube{clusterConfig: disabledNativeOrchestrationConfig()}
	z.isKubeStatsLeader.Store(true)
	deleteCalled := false
	z.removeNINADWithWriter(types.NetworkInstanceStatus{
		NetworkInstanceConfig: types.NetworkInstanceConfig{
			Type: types.NetworkInstanceTypeSwitch,
		},
	}, func(_ string) error {
		deleteCalled = true
		return nil
	})
	if deleteCalled {
		t.Fatal("disabled native orchestration deleted a per-NI NAD")
	}
}

func enabledNativeOrchestrationConfig() types.EdgeNodeClusterConfig {
	return types.EdgeNodeClusterConfig{
		ClusterType:                  types.ClusterTypeReplicatedStorage,
		EnableNativeK8SOrchestration: true,
	}
}

func TestReconcileNINADNotClusterWideDoesNotWrite(t *testing.T) {
	z := &zedkube{clusterConfig: enabledNativeOrchestrationConfig()}
	z.isKubeStatsLeader.Store(true)
	writeCalled := false
	z.reconcileNINADWithWriter(types.NetworkInstanceStatus{
		NetworkInstanceConfig: types.NetworkInstanceConfig{
			Type:        types.NetworkInstanceTypeLocal,
			ClusterWide: false,
		},
	}, func(_, _ string) error {
		writeCalled = true
		return nil
	})
	if writeCalled {
		t.Fatal("device-local (non cluster-wide) NI wrote a per-NI NAD")
	}
}

func TestReconcileNINADClusterWideWrites(t *testing.T) {
	z := &zedkube{clusterConfig: enabledNativeOrchestrationConfig()}
	z.isKubeStatsLeader.Store(true)
	writeCalled := false
	z.reconcileNINADWithWriter(types.NetworkInstanceStatus{
		NetworkInstanceConfig: types.NetworkInstanceConfig{
			Type:        types.NetworkInstanceTypeLocal,
			ClusterWide: true,
		},
	}, func(_, _ string) error {
		writeCalled = true
		return nil
	})
	if !writeCalled {
		t.Fatal("cluster-wide NI did not write a per-NI NAD")
	}
}
