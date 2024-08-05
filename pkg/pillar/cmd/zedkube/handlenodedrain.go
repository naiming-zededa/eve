// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package zedkube

import "github.com/lf-edge/eve/pkg/pillar/kubeapi"

func publishNodeDrainStatus(ctx *zedkubeContext, status kubeapi.DrainStatus) {
	drainStatus := kubeapi.NodeDrainStatus{
		Status: status,
	}
	err := ctx.pubNodeDrainStatus.Publish("global", drainStatus)
	if err != nil {
		log.Errorf("publishNodeDrainStatus unable to publish drainStatus:%v err:%v", drainStatus, err)
	}
}

func handleNodeDrainRequestCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	handleNodeDrainRequestImpl(ctxArg, key, configArg, nil)
}

func handleNodeDrainRequestModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	handleNodeDrainRequestImpl(ctxArg, key, configArg, oldConfigArg)
}

func handleNodeDrainRequestImpl(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	ctx, ok := ctxArg.(*zedkubeContext)
	if !ok {
		log.Fatalf("handleNodeDrainRequestImpl invalid type in ctxArg: %v", ctxArg)
	}
	req, ok := configArg.(kubeapi.NodeDrainRequest)
	if !ok {
		log.Fatalf("handleNodeDrainRequestImpl invalid type in configArg: %v", configArg)
	}
	ccList := ctx.subEdgeNodeClusterConfig.GetAll()
	if len(ccList) == 0 {
		log.Noticef("handleNodeDrainRequestImpl drain request for single node (not cluster), dropping.")
		publishNodeDrainStatus(ctx, kubeapi.NOTSUPPORTED)
		return
	}

	publishNodeDrainStatus(ctx, kubeapi.REQUESTED)

	log.Noticef("handleNodeDrainRequestImpl nodedrain-step:drain-request-handle request:%v", req)
	go cordonAndDrainNode(ctx)
}

func handleNodeDrainRequestDelete(_ interface{}, _ string,
	_ interface{}) {
	log.Function("handleNodeDrainRequestDelete")
}
