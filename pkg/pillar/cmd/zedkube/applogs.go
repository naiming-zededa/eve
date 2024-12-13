// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package zedkube

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func collectAppLogs(ctx *zedkubeContext) {
	sub := ctx.subAppInstanceConfig
	items := sub.GetAll()
	if len(items) == 0 {
		return
	}

	clientset, err := getKubeClientSet()
	if err != nil {
		log.Errorf("collectAppLogs: can't get clientset %v", err)
		return
	}

	err = getnodeNameAndUUID(ctx)
	if err != nil {
		log.Errorf("collectAppLogs: can't get edgeNodeInfo %v", err)
		return
	}

	err = getnodeNameAndUUID(ctx)
	if err != nil {
		log.Errorf("collectAppLogs: can't get edgeNodeInfo %v", err)
		return
	}

	// "Thu Aug 17 05:39:04 UTC 2023"
	timestampRegex := regexp.MustCompile(`(\w{3} \w{3} \d{2} \d{2}:\d{2}:\d{2} \w+ \d{4})`)
	nowStr := time.Now().String()

	var sinceSec int64
	sinceSec = logcollectInterval
	for _, item := range items {
		aiconfig := item.(types.AppInstanceConfig)
		if aiconfig.FixedResources.VirtualizationMode != types.NOHYPER {
			continue
		}
		if !aiconfig.IsDesignatedNodeID { // For now, only check DNiD, need to add migration part
			continue
		}
		kubeName := base.GetAppKubeName(aiconfig.DisplayName, aiconfig.UUIDandVersion.UUID)
		contName := kubeName
		opt := &corev1.PodLogOptions{}
		if ctx.appLogStarted {
			opt = &corev1.PodLogOptions{
				SinceSeconds: &sinceSec,
			}
		} else {
			ctx.appLogStarted = true
		}

		pods, err := clientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: fmt.Sprintf("app=%s", kubeName),
		})
		if err != nil {
			logrus.Errorf("checkReplicaSetMetrics: can't get pod %v", err)
			continue
		}
		for _, pod := range pods.Items {
			if strings.HasPrefix(pod.ObjectMeta.Name, kubeName) {
				contName = pod.ObjectMeta.Name
				break
			}
		}
		req := clientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).GetLogs(contName, opt)
		podLogs, err := req.Stream(context.Background())
		if err != nil {
			log.Errorf("collectAppLogs: pod %s, log error %v", contName, err)
			continue
		}
		defer podLogs.Close()

		scanner := bufio.NewScanner(podLogs)
		for scanner.Scan() {
			logLine := scanner.Text()

			matches := timestampRegex.FindStringSubmatch(logLine)
			var timeStr string
			if len(matches) > 0 {
				timeStr = matches[0]
				ts := strings.Split(logLine, timeStr)
				if len(ts) > 1 {
					logLine = ts[0]
				}
			} else {
				timeStr = nowStr
			}
			// Process and print the log line here
			aiLogger := ctx.appContainerLogger.WithFields(logrus.Fields{
				"appuuid":       aiconfig.UUIDandVersion.UUID.String(),
				"containername": contName,
				"eventtime":     timeStr,
			})
			aiLogger.Infof("%s", logLine)
		}
		if scanner.Err() != nil {
			if scanner.Err() == io.EOF {
				break // Break out of the loop when EOF is reached
			}
		}
	}
}

func checkAppsStatus(ctx *zedkubeContext) {
	sub := ctx.subAppInstanceConfig
	items := sub.GetAll()
	if len(items) == 0 {
		return
	}

	err := getnodeNameAndUUID(ctx)
	if err != nil {
		log.Errorf("checkAppsStatus: can't get edgeNodeInfo %v", err)
		return
	}

	clientset, err := getKubeClientSet()
	if err != nil {
		log.Errorf("checkAppsStatus: can't get clientset %v", err)
		return
	}

	pub := ctx.pubENClusterAppStatus
	stItems := pub.GetAll()

	pods, err := clientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("checkAppsStatus: can't get pods %v", err)
		// If we can't get pods, process the error and return
		handleKubePodsGetError(ctx, items, stItems)
		return
	}

	ctx.getKubePodsError.getKubePodsErrorTime = nil
	ctx.getKubePodsError.processedErrorCondition = false

	// Iterate appinstance config
	for _, item := range items {
		var oldStatus *types.ENClusterAppStatus
		var foundPod bool
		aiconfig := item.(types.AppInstanceConfig)

		encAppStatus := types.ENClusterAppStatus{
			AppUUID: aiconfig.UUIDandVersion.UUID,
			IsDNSet: aiconfig.IsDesignatedNodeID,
		}
		contName := base.GetAppKubeName(aiconfig.DisplayName, aiconfig.UUIDandVersion.UUID)

		// Iterate pods of this app
		for _, pod := range pods.Items {
			contVMIName := "virt-launcher-" + contName
			log.Noticef("PRAMOD checkAppsStatus: pod %s, cont %s Phase %s", pod.Name, contName, pod.Status.Phase)
			if strings.HasPrefix(pod.Name, contName) || strings.HasPrefix(pod.Name, contVMIName) {
				if pod.Spec.NodeName == ctx.nodeName {
					encAppStatus.ScheduledOnThisNode = true
				}

				if pod.Status.Phase == corev1.PodRunning {
					encAppStatus.StatusRunning = true
				}
				foundPod = true
				break
			}
		}

		// Iterate over ENClusterAppStatus and see if we already published and store it as oldstatus
		for _, st := range stItems {
			aiStatus := st.(types.ENClusterAppStatus)
			if aiStatus.AppUUID == aiconfig.UUIDandVersion.UUID {
				oldStatus = &aiStatus
				break
			}
		}

		log.Noticef("checkAppsStatus: devname %s, pod (%d) status %+v, old %+v, found %v", ctx.nodeName, len(pods.Items), encAppStatus, oldStatus, foundPod)

		// If this is first time after zedkube started (oldstatus is nil) and I am DNid and the app is not shceduled
		// on this node. This condition is seen for two reasons
		// 1) We just got appinstanceconfig and domainmgr did not get chance to start it yet, timing issue, zedkube checked first
		// 2) We are checking after app failover to other node, either this node network failed and came back or this just got rebooted

		if oldStatus == nil && !encAppStatus.ScheduledOnThisNode && encAppStatus.IsDNSet {
			log.Noticef("checkAppsStatus: app not yet scheduled on this node %v", encAppStatus)
			continue
		}

		// Publish if there is a status change
		if oldStatus == nil || oldStatus.ScheduledOnThisNode != encAppStatus.ScheduledOnThisNode ||
			oldStatus.StatusRunning != encAppStatus.StatusRunning {
			log.Noticef("checkAppsStatus: status differ, publish")
			// If app scheduled on this node, could happen for 3 reasons.
			// 1) I am designated node.
			// 2) I am not designated node but failover happened.
			// 3) I am deisgnated node but this is failback after failover.
			// Get the list of volumes referenced by this app and delete the volume attachments from previous node.
			// We need to do that becasue longhorn volumes are RWO and only one node can attach to those volumes.
			// This will ensure at any given time only one node can write to those volumes, avoids corruptions.
			// Basically if app is scheduled on this node, no other node should have volumeattachments.
			if encAppStatus.ScheduledOnThisNode {
				for _, vol := range aiconfig.VolumeRefConfigList {
					pvcName := fmt.Sprintf("%s-pvc-%d", vol.VolumeID.String(), vol.GenerationCounter)
					// Get the PV name for this PVC
					pv, err := kubeapi.GetPVFromPVC(pvcName, log)
					if err != nil {
						log.Errorf("Error getting PV from PVC %v", err)
						continue
					}

					va, remoteNodeName, err := kubeapi.GetVolumeAttachmentFromPV(pv, log)
					if err != nil {
						log.Errorf("Error getting volumeattachment PV %s err %v", pv, err)
						continue
					}
					// If no volumeattachment found, continue
					if va == "" {
						continue
					}

					// Delete the attachment if not on this node.
					if remoteNodeName != ctx.nodeName {
						log.Noticef("Deleting volumeattachment %s on remote node %s", va, remoteNodeName)
						err = kubeapi.DeleteVolumeAttachment(va, log)
						if err != nil {
							log.Errorf("Error deleting volumeattachment %s from PV %v", va, err)
							continue
						}
					}

				}
			}
			ctx.pubENClusterAppStatus.Publish(aiconfig.Key(), encAppStatus)
		}

	}
}

func getnodeNameAndUUID(ctx *zedkubeContext) error {
	if ctx.nodeuuid == "" || ctx.nodeName == "" {
		NodeInfo, err := ctx.subEdgeNodeInfo.Get("global")
		if err != nil {
			log.Errorf("getnodeNameAndUUID: can't get edgeNodeInfo %v", err)
			return err
		}
		enInfo := NodeInfo.(types.EdgeNodeInfo)
		ctx.nodeName = strings.ToLower(enInfo.DeviceName)
		ctx.nodeuuid = enInfo.DeviceID.String()
	}
	return nil
}

func handleKubePodsGetError(ctx *zedkubeContext, items, stItems map[string]interface{}) {
	if ctx.getKubePodsError.getKubePodsErrorTime == nil {
		now := time.Now()
		ctx.getKubePodsError.getKubePodsErrorTime = &now
		log.Noticef("handleKubePodsGetError: can't get pods, set error time")
	} else if time.Since(*ctx.getKubePodsError.getKubePodsErrorTime) > 2*time.Minute {
		if ctx.getKubePodsError.processedErrorCondition == false {
			ctx.getKubePodsError.processedErrorCondition = true
			for _, item := range items {
				aiconfig := item.(types.AppInstanceConfig)
				for _, st := range stItems {
					aiStatus := st.(types.ENClusterAppStatus)
					if aiStatus.AppUUID == aiconfig.UUIDandVersion.UUID {
						// if we used to publish the status, of this app is scheduled on this node
						// need to reset this, since we have lost the connection to the kubernetes
						// for longer time than the app is to be migrated to other node
						if aiStatus.ScheduledOnThisNode {
							aiStatus.ScheduledOnThisNode = false
							ctx.pubENClusterAppStatus.Publish(aiconfig.Key(), aiStatus)
							log.Noticef("handleKubePodsGetError: can't get pods set ScheduledOnThisNode off for %s, ", aiconfig.DisplayName)
						}
					}
				}
			}
		}
	}
}
