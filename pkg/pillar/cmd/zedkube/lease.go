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
	// If we can not perform the leader election, due to kubernetes connection issues
	// at the moment, we will retry in 5 minutes
	retryTimer := time.NewTimer(0)
	retryTimer.Stop() // Ensure the timer is stopped initially
	retryTimerStarted := false

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
				publishLeaseElectionChange(ctx)
				log.Errorf("handleLeaderElection: can't get clientset %v, retry in 5 min", err)
				retryTimer.Reset(5 * time.Minute)
				retryTimerStarted = true
				continue
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
				LeaseDuration:   300 * time.Second,
				RenewDeadline:   60 * time.Second,
				RetryPeriod:     15 * time.Second,
				ReleaseOnCancel: true,
				Callbacks: leaderelection.LeaderCallbacks{
					OnStartedLeading: func(baseCtx context.Context) {
						ctx.isKubeStatsLeader.Store(true)
						publishLeaseElectionChange(ctx)
						log.Noticef("handleLeaderElection: Callback Started leading")
					},
					OnStoppedLeading: func() {
						ctx.isKubeStatsLeader.Store(false)
						publishLeaseElectionChange(ctx)
						log.Noticef("handleLeaderElection: Callback Stopped leading")
					},
					OnNewLeader: func(identity string) {
						ctx.leaderIdentity = identity
						publishLeaseElectionChange(ctx)
						log.Noticef("handleLeaderElection: Callback New leader elected: %s", identity)
					},
				},
			}

			publishLeaseElectionChange(ctx)
			// Start the leader election in a separate goroutine
			go func() {
				leaderelection.RunOrDie(baseCtx, lec)
				log.Noticef("handleLeaderElection: Leader election routine exited")
			}()
			log.Noticef("handleLeaderElection: Started leader election routine for %s", ctx.nodeName)

		case <-ctx.electionStopCh:
			ctx.isKubeStatsLeader.Store(false)
			ctx.inKubeLeaderElection.Store(false)
			ctx.leaderIdentity = ""
			publishLeaseElectionChange(ctx)
			log.Noticef("handleLeaderElection: Stopped leading signal received")
			if retryTimerStarted {
				retryTimer.Stop()
				retryTimerStarted = false
			}

			if cancelFunc != nil {
				log.Noticef("handleLeaderElection: Stopped. cancelling leader election")
				cancelFunc()
				cancelFunc = nil
			}

		case <-retryTimer.C:
			log.Noticef("Retrying failed leader election")
			sub := ctx.subZedAgentStatus
			items := sub.GetAll()
			for _, item := range items {
				status := item.(types.ZedAgentStatus)
				handleControllerStatusChange(ctx, &status)
				break
			}
			retryTimerStarted = false
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

	log.Noticef("handleControllerStatusChange: Leader enter, status %v", configStatus)
	switch configStatus {
	case types.ConfigGetSuccess, types.ConfigGetReadSaved: // either read success or read from saved config
		if !ctx.inKubeLeaderElection.Load() {
			SignalStartLeaderElection(ctx)
		} else {
			log.Noticef("handleControllerStatusChange: start. Already in leader election, skip")
		}
	default:
		if ctx.inKubeLeaderElection.Load() {
			SignalStopLeaderElection(ctx)
		} else {
			log.Noticef("handleControllerStatusChange: default stop. Not in leader election, skip")
		}
	}
}

func publishLeaseElectionChange(ctx *zedkubeContext) {
	// Publish the change in leader
	leaseinfo := types.KubeLeaseInfo{
		InLeaseElection: ctx.inKubeLeaderElection.Load(),
		IsStatsLeader:   ctx.isKubeStatsLeader.Load(),
		LeaderIdentity:  ctx.leaderIdentity,
		LatestChange:    time.Now(),
	}
	ctx.pubLeaseLeaderInfo.Publish("global", leaseinfo)
}
