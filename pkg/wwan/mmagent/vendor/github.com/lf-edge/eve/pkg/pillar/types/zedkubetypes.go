// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

type KubeNodeStatus int8

const (
	KubeNodeStatusUnknown KubeNodeStatus = iota
	KubeNodeStatusReady
	KubeNodeStatusNotReady
	KubeNodeStatusNotReachable
)

type KubeNodeInfo struct {
	Name               string
	Status             KubeNodeStatus
	IsMaster           bool
	IsEtcd             bool
	CreationTime       time.Time
	LastTransitionTime time.Time
	KubeletVersion     string
	InternalIP         string
	ExternalIP         string
	Schedulable        bool
}

type KubePodStatus int8

const (
	KubePodStatusUnknown KubePodStatus = iota
	KubePodStatusPending
	KubePodStatusRunning
	KubePodStatusSucceeded
	KubePodStatusFailed
)

type KubePodInfo struct {
	Name              string
	Status            KubePodStatus
	RestartCount      int32
	RestartTimestamp  time.Time
	CreationTimestamp time.Time
	PodIP             string
	NodeName          string
}

type KubeVMIStatus int8

const (
	KubeVMIStatusUnset KubeVMIStatus = iota
	KubeVMIStatusPending
	KubeVMIStatusScheduling
	KubeVMIStatusScheduled
	KubeVMIStatusRunning
	KubeVMIStatusSucceeded
	KubeVMIStatusFailed
	KubeVMIStatusUnknown
)

type KubeVMIInfo struct {
	Name               string
	Status             KubeVMIStatus
	CreationTime       time.Time
	LastTransitionTime time.Time
	IsReady            bool
	NodeName           string
}

type KubeClusterInfo struct {
	Nodes   []KubeNodeInfo  // List of nodes in the cluster
	AppPods []KubePodInfo   // List of EVE application pods
	AppVMIs []KubeVMIInfo   // List of VirtualMachineInstance
	Storage KubeStorageInfo // Distributed storage info
}

type StorageHealthStatus uint8

const (
	StorageHealthStatusUnknown StorageHealthStatus = iota
	StorageHealthStatusHealthy
	StorageHealthStatusDegraded2ReplicaAvailableReplicating //replicating to third replica
	StorageHealthStatusDegraded2ReplicaAvailableNotReplicating
	StorageHealthStatusDegraded1ReplicaAvailableReplicating //replicating to one or two replicas
	StorageHealthStatusDegraded1ReplicaAvailableNotReplicating
	StorageHealthStatusFailed
)

type StorageVolumeState uint8

const (
	StorageVolumeState_Unknown StorageVolumeState = iota
	StorageVolumeState_Creating
	StorageVolumeState_Attached
	StorageVolumeState_Detached
	StorageVolumeState_Attaching
	StorageVolumeState_Detaching
	StorageVolumeState_Deleting
)

type StorageVolumeRobustness uint8

const (
	StorageVolumeRobustness_Unknown StorageVolumeRobustness = iota
	StorageVolumeRobustness_Healthy
	StorageVolumeRobustness_Degraded
	StorageVolumeRobustness_Faulted
)

type StorageVolumePvcStatus uint8

const (
	StorageVolumePvcStatus_Unknown StorageVolumePvcStatus = iota
	StorageVolumePvcStatus_Bound
	StorageVolumePvcStatus_Pending
	StorageVolumePvcStatus_Available
	StorageVolumePvcStatus_Released
	StorageVolumePvcStatus_Faulted
)

type StorageVolumeReplicaStatus uint8

const (
	StorageVolumeReplicaStatus_Unknown StorageVolumeReplicaStatus = iota
	StorageVolumeReplicaStatus_Rebuilding
	StorageVolumeReplicaStatus_Online
	StorageVolumeReplicaStatus_Failed
	StorageVolumeReplicaStatus_Offline
	StorageVolumeReplicaStatus_Starting
	StorageVolumeReplicaStatus_Stopping
)

type KubeVolumeReplicaInfo struct {
	Name                      string
	OwnerNode                 string
	RebuildProgressPercentage uint8
	Status                    StorageVolumeReplicaStatus
}
type KubeVolumeInfo struct {
	Name               string
	State              StorageVolumeState
	Robustness         StorageVolumeRobustness
	CreatedAt          time.Time
	ProvisionedBytes   uint64
	AllocatedBytes     uint64
	PvcStatus          StorageVolumePvcStatus
	Replicas           []KubeVolumeReplicaInfo
	RobustnessSubstate StorageHealthStatus
}

type ServiceStatus int8

const (
	ServiceStatusUnset ServiceStatus = iota
	ServiceStatusFailed
	ServiceStatusDegraded
	ServiceStatusHealthy
)

type KubeStorageInfo struct {
	Health         ServiceStatus
	TransitionTime time.Time
	Volumes        []KubeVolumeInfo
}
