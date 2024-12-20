// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package zedkube

import (
	"context"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

func handleLeaderElection(ctx *zedkubeContext) {
	var cancelFunc context.CancelFunc
	for {
		log.Noticef("handleLeaderElection: Waiting for signal") // XXX
		select {
		case <-ctx.electionStartCh:

			// Create a cancellable context
			baseCtx, cancel := context.WithCancel(context.Background())
			cancelFunc = cancel

			clientset, err := getKubeClientSet()
			if err != nil {
				ctx.inKubeLeaderElection.Store(false)
				log.Errorf("handleLeaderElection: can't get clientset %v", err)
				return
			}

			err = getnodeNameAndUUID(ctx)
			if err != nil {
				ctx.inKubeLeaderElection.Store(false)
				log.Errorf("handleLeaderElection: can't get nodeName and UUID %v", err)
				return
			}

			// Create a new lease lock
			lock := &resourcelock.LeaseLock{
				LeaseMeta: metav1.ObjectMeta{
					Name:      "eve-kube-stats-leader",
					Namespace: kubeapi.EVEKubeNameSpace,
				},
				Client: clientset.CoordinationV1(),
				LockConfig: resourcelock.ResourceLockConfig{
					Identity: ctx.nodeName,
				},
			}

			// Define the leader election configuration
			// Typical EVE deployments:
			// - should not see rapidly changing environments
			// - can be on lower resource boxes
			//
			// Due to these constraints I believe in setting lease parameters to meet a few goals:
			// - less k8s API calls -> less etcd transactions
			// - longer lease to allow multiple consecutive stats runs on a given node
			//              this will keep calls out of the k8s api cache (local node fs) instead of
			//      bouncing node to node and re-priming the k8s cache (unnecessary IO)
			lec := leaderelection.LeaderElectionConfig{
				Lock:            lock,
				LeaseDuration:   24 * time.Hour,
				RenewDeadline:   60 * time.Second,
				RetryPeriod:     5 * time.Second,
				ReleaseOnCancel: true,
				Callbacks: leaderelection.LeaderCallbacks{
					OnStartedLeading: func(baseCtx context.Context) {
						ctx.isKubeStatsLeader.Store(true)
						log.Noticef("handleLeaderElection: Started leading")
					},
					OnStoppedLeading: func() {
						ctx.isKubeStatsLeader.Store(false)
						log.Noticef("handleLeaderElection: Stopped leading")
					},
					OnNewLeader: func(identity string) {
						log.Noticef("handleLeaderElection: New leader elected: %s", identity)
					},
				},
			}

			// Start the leader election in a separate goroutine
			go leaderelection.RunOrDie(baseCtx, lec)
			log.Noticef("handleLeaderElection: Started leader election for %s", ctx.nodeName)

		case <-ctx.electionStopCh:
			ctx.isKubeStatsLeader.Store(false)
			ctx.inKubeLeaderElection.Store(false)
			log.Noticef("handleLeaderElection: Stopped leading signal received")
			if cancelFunc != nil {
				cancelFunc()
				cancelFunc = nil
			}
		}
	}
}

// Function to signal the start of leader election
func SignalStartLeaderElection(ctx *zedkubeContext) {
	ctx.inKubeLeaderElection.Store(true)
	select {
	case ctx.electionStartCh <- struct{}{}:
		log.Noticef("SignalStartLeaderElection: Signal sent successfully")
	default:
		log.Warningf("SignalStartLeaderElection: Channel is full, signal not sent")
	}
}

// Function to signal the stop of leader election
func SignalStopLeaderElection(ctx *zedkubeContext) {
	select {
	case ctx.electionStopCh <- struct{}{}:
		log.Noticef("SignalStopLeaderElection: Signal sent successfully")
	default:
		log.Warningf("SignalStopLeaderElection: Channel is full, signal not sent")
	}
}

func handleControllerStatusChange(ctx *zedkubeContext, status *types.ZedAgentStatus) {
	configStatus := status.ConfigGetStatus

	log.Functionf("handleControllerStatusChange: Leader enter, status %v", configStatus)
	switch configStatus {
	case types.ConfigGetSuccess, types.ConfigGetReadSaved: // either read success or read from saved config
		if !ctx.inKubeLeaderElection.Load() {
			SignalStartLeaderElection(ctx)
		}
	default:
		if ctx.inKubeLeaderElection.Load() {
			SignalStopLeaderElection(ctx)
		}
	}
}
