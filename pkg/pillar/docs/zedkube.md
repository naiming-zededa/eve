# Clustered eve nodes (aka zedkube)

## Overview

## Components

### kubenodeop

kubenodeop handles cordoning, uncordoning, and draining of clustered eve-os nodes.  Any given node could be hosting
one or more longhorn volume replicas and thus could be the rebuild source for other node replicas.  A drain operation should be
performed before any Node Operation / Node Command which can cause an extended outage of a node such as a reboot, shutdown, reset.
kubenodeop handles NodeDrainRequest objects which zedkube subscribes to, initiates the drain, and publishes NodeDrainStatus objects.

### Drain PubSub setup (node reboot/shutdown)

1. zedagent/handlenodedrain.go:initNodeDrainPubSub()
    subscribes to NodeDrainStatus from zedkube
    creates publication of NodeDrainRequest
1. nodeagent/handlenodedrain.go:initNodeDrainPubSub()
    subscribe to NodeDrainStatus from zedkube

### Drain Request path (node reboot/shutdown)

1. zedagent/parseconfig.go:scheduleDeviceOperation()
    call GetNodeDrainStatus() to determine if system supports drain
        systems not HV=kubevirt will return NOTSUPPORTED
        HV=kubevirt will return:
            NOTSUPPORTED if in single node.
            NOTREQUESTED if in cluster mode
    NodeDrainStatus == NOTREQUESTED:
        - kubeapi.RequestNodeDrain
        - then set appropriate reboot or shutdown cmd deferred state in zedagentContext struct
    NodeDrainStatus == REQUESTED: then set appropriate reboot or shutdown cmd deferred state in zedagentContext struct

### Drain Status Handler (node reboot/shutdown)

1. zedagent/handlenodedrain.go:handleNodeDrainStatusImpl()
    if drain status FAILEDCORDON or FAILEDDRAIN, unpublish NodeDrainRequest
1. zedagent/zedagent.go:handleNodeAgentStatusImpl()
    drainInProgress = getConfigContext.drainInProgress
    getConfigContext.drainInProgress = NodeAgentStatus.DrainInProgress
    if NodeAgentStatus DrainInProgress cleared then allow deferred reboot/shutdown
1. nodeagent/nodeagent.go:handleNodeDrainStatusImplNA
    NodeDrainStatus == REQUESTED
    NodeDrainStatus == STARTING
        republish nodeagentstatus with drainInProgress set
    NodeDrainStatus == COMPLETE
        republish nodeagentstatus with drainInProgress cleared

### Drain PubSub setup (node eveimage-update)

1. baseosmgr/baseosmgr.go:setupKubePubSub()
    subscribe to NodeDrainStatus from zedkube
    setup publication to NodeDrainRequest

### Drain Request path (node eveimage-update)

1. baseosmgr/handlebaseos.go:baseOsHandleStatusUpdateUUID()
    New BaseImage coming down, if State == LOADING or LOADED (past verification, so edge-node is ready for it)
        if shouldDeferForNodeDrain() return, later NodeDrainStatus will complete this id.
1. baseosmgr/handlenodedrain.go:shouldDeferForNodeDrain()
    NodeDrainStatus == NOTREQUESTED: RequestNodeDrain
    NodeDrainStatus == REQUESTED-FAILEDDRAIN: defer
    NodeDrainStatus == COMPLETE: don't defer

### Drain Status Handler (node eve-image update)

1. baseosmgr/handlenodedrain.go:handleNodeDrainStatusImpl()
    NodeDrainStatus == FAILEDCORDON or FAILEDDRAIN: unpublish NodeDrainRequest
    NodeDrainStatus == COMPLETE: complete deferred id to baseOsHandleStatusUpdateUUID

### General DrainRequest Processing

1. zedkube/zedkube.go:Run()
    sub to NodeDrainRequest from zedagent and baseosmgr
    new publication of NodeDrainStatus
    Init NodeDrainStatus to NOTSUPPORTED
1. zedkube/zedkube.go:handleEdgeNodeClusterComfigImpl()
    On cluster config:
        NodeDrainStatus -> NOTREQUESTED
1. zedkube/handlenodedrain.go:handleNodeDrainRequestImpl()
    NodeDrainStatus -> REQUESTED
1. zedkube/kubenodeop.go:cordonAndDrainNode()
    NodeDrainStatus -> STARTING
    Retry Cordon up to 10 times (in case k8s api states object changed)
        else NodeDrainStatus -> FAILEDCORDON
    NodeDrainStatus -> CORDONED
    Retry Drain up to 5 times
        between tries: NodeDrainStatus -> DRAINRETRYING
        on failure: NodeDrainStatus -> FAILEDDRAIN
    NodeDrainStatus -> COMPLETE

## Debugging

### PubSub NodeDrainRequest/NodeDrainStatus

/run/zedagent/NodeDrainRequest/global.json
/run/baseosmgr/NodeDrainRequest/global.json
/run/zedkube/NodeDrainStatus/global.json

The current node drain progress is available from the global NodeDrainStatus object found at
`cat /run/zedkube/NodeDrainStatus/global.json | jq`.

### NodeDrainRequest/NodeDrainStatus log strings

- NodeDrainRequest
- NodeDrainStatus
- cordonNode
- cordonAndDrainNode
- scheduleDeviceOperation
- baseOsHandleStatusUpdateUUID
- nodedrain-step
