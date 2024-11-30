package zedmanager

import "github.com/lf-edge/eve/pkg/pillar/types"

func handleENClusterAppStatusCreate(ctxArg interface{}, key string, configArg interface{}) {
	log.Noticef("handleENClusterAppStatusCreate(%s)", key)
	ctx := ctxArg.(*zedmanagerContext)
	status := configArg.(types.ENClusterAppStatus)
	handleENClusterAppStatusImpl(ctx, key, &status)
}

func handleENClusterAppStatusModify(ctxArg interface{}, key string, configArg interface{}, oldConfigArg interface{}) {
	log.Noticef("handleENClusterAppStatusModify(%s)", key)
	ctx := ctxArg.(*zedmanagerContext)
	status := configArg.(types.ENClusterAppStatus)
	handleENClusterAppStatusImpl(ctx, key, &status)
}

func handleENClusterAppStatusDelete(ctxArg interface{}, key string, configArg interface{}) {
	log.Noticef("handleENClusterAppStatusDelete(%s)", key)
	ctx := ctxArg.(*zedmanagerContext)
	status := configArg.(types.ENClusterAppStatus)
	handleENClusterAppStatusImpl(ctx, key, &status)
}

func handleENClusterAppStatusImpl(ctx *zedmanagerContext, key string, status *types.ENClusterAppStatus) {

	aiStatus := lookupAppInstanceStatus(ctx, key)
	log.Noticef("handleENClusterAppStatusImpl(%s) for app-status %v aiStatus %v", key, status, aiStatus)

	if status.ScheduledOnThisNode {
		if aiStatus == nil {
			// This could happen if app failover to other node and failing back to this designated node.
			// One scenario is node reboot. Kubernetes told us that app is scheduled on this node.
			aiConfig := lookupAppInstanceConfig(ctx, key, false)
			if aiConfig == nil {
				log.Errorf("handleENClusterAppStatusImpl(%s) AppInstanceConfig missing for app", key)
				return
			}
			handleCreateAppInstanceStatus(ctx, *aiConfig)
		} else {
			updateAIStatusUUID(ctx, aiStatus.UUIDandVersion.UUID.String())
		}
	} else { // not scheduled here. Check if we are stopping, if so delete the appinstancestatus
		if aiStatus != nil {
			//if status.StatusStopped {
			//Set app instance state activated to false and publish
			// that will make sure device will tell controller that app is not running on this device.
			aiStatus.Activated = false
			aiStatus.ActivateInprogress = false
			publishAppInstanceStatus(ctx, aiStatus)
			//removeAIStatus(ctx, aiStatus)
			//	}
		}
	}

}
