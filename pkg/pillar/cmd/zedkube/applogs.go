// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package zedkube

import (
	"bufio"
	"context"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func collectAppLogs(ctx *zedkubeContext) {
	sub := ctx.subAppInstanceConfig
	items := sub.GetAll()
	if len(items) == 0 {
		return
	}

	if ctx.config == nil {
		config, err := kubeapi.GetKubeConfig()
		if err != nil {
			return
		}
		ctx.config = config
	}

	clientset, err := kubernetes.NewForConfig(ctx.config)
	if err != nil {
		log.Errorf("collectAppLogs: can't get clientset %v", err)
		return
	}

	// "Thu Aug 17 05:39:04 UTC 2023"
	timestampRegex := regexp.MustCompile(`(\w{3} \w{3} \d{2} \d{2}:\d{2}:\d{2} \w+ \d{4})`)
	nowStr := time.Now().String()

	var sinceSec int64
	sinceSec = logcollectInterval
	for _, item := range items {
		aiconfig := item.(types.AppInstanceConfig)
		if aiconfig.DesignatedNodeID != uuid.Nil && aiconfig.DesignatedNodeID.String() != ctx.nodeuuid { // For now, only check DNiD, need to add migration part
			continue
		}
		contName := base.GetAppKubeName(aiconfig.DisplayName, aiconfig.UUIDandVersion.UUID)

		opt := &corev1.PodLogOptions{}
		if ctx.appLogStarted {
			opt = &corev1.PodLogOptions{
				SinceSeconds: &sinceSec,
			}
		} else {
			ctx.appLogStarted = true
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

	if ctx.config == nil {
		config, err := kubeapi.GetKubeConfig()
		if err != nil {
			log.Errorf("checkAppsStatus: can't get kubeconfig %v", err)
			return
		}
		ctx.config = config
	}

	clientset, err := kubernetes.NewForConfig(ctx.config)
	if err != nil {
		log.Errorf("checkAppsStatus: can't get clientset %v", err)
		return
	}

	labelSelector := metav1.LabelSelector{MatchLabels: map[string]string{"node-uuid": ctx.nodeuuid}}
	options := metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(&labelSelector)}
	pods, err := clientset.CoreV1().Pods(kubeapi.EVEKubeNameSpace).List(context.Background(), options)
	if err != nil {
		log.Errorf("checkAppsStatus: can't get pods %v", err)
		return
	}

	pub := ctx.pubENClusterAppStatus
	stItmes := pub.GetAll()
	var oldStatus *types.ENClusterAppStatus
	for _, item := range items {
		aiconfig := item.(types.AppInstanceConfig)
		if aiconfig.DesignatedNodeID != uuid.Nil { // if not for cluster app, skip
			continue
		}
		encAppStatus := types.ENClusterAppStatus{
			AppUUID: aiconfig.UUIDandVersion.UUID,
			IsDNSet: aiconfig.DesignatedNodeID.String() == ctx.nodeuuid,
		}
		contName := base.GetAppKubeName(aiconfig.DisplayName, aiconfig.UUIDandVersion.UUID)

		for _, pod := range pods.Items {
			contVMIName := "virt-launcher-" + contName
			if pod.Name == contName || pod.Name == contVMIName {
				encAppStatus.ScheduledOnThisNode = true
				if pod.Status.Phase == corev1.PodRunning {
					encAppStatus.StatusRunning = true
				}
				break
			}
		}

		for _, st := range stItmes {
			aiStatus := st.(types.ENClusterAppStatus)
			if aiStatus.AppUUID == aiconfig.UUIDandVersion.UUID {
				oldStatus = &aiStatus
				break
			}
		}
		log.Noticef("checkAppsStatus: pod status %+v, old %+v", encAppStatus, oldStatus)

		if oldStatus == nil || oldStatus.IsDNSet != encAppStatus.IsDNSet ||
			oldStatus.ScheduledOnThisNode != encAppStatus.ScheduledOnThisNode || oldStatus.StatusRunning != encAppStatus.StatusRunning {
			log.Noticef("checkAppsStatus: status differ, publish")
			ctx.pubENClusterAppStatus.Publish(aiconfig.Key(), encAppStatus)
		}
	}
}
