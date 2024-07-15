package kubeapi

import "time"

type DrainStatus uint8

const (
	UNKNOWN       DrainStatus = iota + 0 // UNKNOWN Unable to determine
	NOTSUPPORTED                         // NOTSUPPORTED System not (HV=kubevirt and clustered)
	NOTREQUESTED                         // NOTREQUESTED Not yet requested
	REQUESTED                            // REQUESTED From zedagent device operation or baseosmgr new update
	STARTING                             // STARTING Zedkube go routine started, not yet cordoned
	CORDONED                             // CORDONED Node Unschedulable set
	FAILEDCORDON                         // FAILEDCORDON Node modification unable to apply
	DRAINRETRYING                        // DRAINRETRYING Drain retry in progress, could be retried replica rebuild
	FAILEDDRAIN                          // FAILEDDRAIN Could be retried replica rebuild
	COMPLETE                             // COMPLETE All node workloads removed from system
)

type NodeDrainRequest struct {
	Hostname    string
	RequestedAt time.Time
}

type NodeDrainStatus struct {
	Status DrainStatus
}
