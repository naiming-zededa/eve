// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package kubeapi

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
)

// RequestNodeDrain generates the NodeDrainRequest object and publishes it
func RequestNodeDrain(pubNodeDrainRequest pubsub.Publication) error {
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("RequestNodeDrain: can't get hostname %v", err)
	}
	drainReq := NodeDrainRequest{
		Hostname:    hostname,
		RequestedAt: time.Now(),
	}
	err = pubNodeDrainRequest.Publish("global", drainReq)
	if err != nil {
		return fmt.Errorf("RequestNodeDrain: error publishing drain request: %v", err)
	}
	return nil
}

// GetNodeDrainStatus is a wrapper to either return latest NodeDrainStatus
// return a forced status from /persist/force-NodeDrainStatus-global.dat
func GetNodeDrainStatus(subNodeDrainStatus pubsub.Subscription) *NodeDrainStatus {
	// An alternate path to force a drain status in the event of a drain issue.
	forceNodeDrainPath := "/persist/force-NodeDrainStatus-global.dat"
	if _, err := os.Stat(forceNodeDrainPath); err == nil {
		b, err := os.ReadFile(forceNodeDrainPath)
		if err == nil {
			cfg := NodeDrainStatus{}
			err = json.Unmarshal(b, &cfg)
			if err == nil {
				return &cfg
			}
		}
	}

	items := subNodeDrainStatus.GetAll()
	glbStatus, ok := items["global"].(NodeDrainStatus)
	if !ok {
		// This should only be expected on an HV=kubevirt build
		// and only very early in boot (before zedkube starts)
		return &NodeDrainStatus{Status: UNKNOWN}
	}
	return &glbStatus
}
