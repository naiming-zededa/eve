// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package kubeapi

import (
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// XXX current used module version has int32, latest has uint64
func device_major(stat syscall.Stat_t) int32 {
	return int32((stat.Rdev >> 8) & 0xfff)
}
func device_minor(stat syscall.Stat_t) int32 {
	return int32((stat.Rdev & 0xff) | ((stat.Rdev >> 12) & 0xfff00))
}
func getMajorMinor(stat syscall.Stat_t) string {
	major := device_major(stat)
	minor := device_minor(stat)
	return fmt.Sprintf("%d:%d", major, minor)
}

func Longhorn_PVCs_Exist() bool {
	LonghornDevPath := "/dev/longhorn"
	if _, err := os.Stat(LonghornDevPath); err != nil {
		return false
	}
	return true
}

func isPvMountedOnThisNode(pv string) bool {
	if _, err := os.Stat("/dev/longhorn/" + pv); err != nil {
		return false
	}
	return true
}
func isBlockDeviceMountedOnThisNode(dev string) bool {
	if _, err := os.Stat("/dev/" + dev); err != nil {
		return false
	}
	return true
}

func CleanupUnmountedDiskMetrics(pubDiskMetric pubsub.Publication, pvcToPvMap map[string]string) {
	existingMetrics := pubDiskMetric.GetAll()

	for id := range existingMetrics {
		if strings.HasPrefix(id, "pvc-") {
			pvName, ok := pvcToPvMap[id]
			if ok {
				if !isPvMountedOnThisNode(pvName) {
					pubDiskMetric.Unpublish(id)
				}
			}
		} else {
			if !isBlockDeviceMountedOnThisNode(id) {
				pubDiskMetric.Unpublish(id)
			}
		}
	}
}

// Longhorn volume devices don't show up in /proc/diskstats
// as their /dev/longhorn/<pv-name> path, only as the sdX path.
// Its up to us to match them via their major:minor nexus
// first map - maj:min -> kube-pv-name/lh-volume-name
// second map - kube-pv-name/lh-volume-name -> maj:min
func Longhorn_GetMajorMinorMaps() (map[string]string, map[string]string, error) {
	lhMajMinToNameMap := make(map[string]string) // maj:min -> kube-pv-name/lh-volume-name
	lhNameToMajMinMap := make(map[string]string) // kube-pv-name/lh-volume-name -> maj:min

	LonghornDevPath := "/dev/longhorn"
	if _, err := os.Stat(LonghornDevPath); err != nil {
		return lhMajMinToNameMap, lhNameToMajMinMap, fmt.Errorf("longhorn dev path missing")
	}

	lhPvcList, err := os.ReadDir(LonghornDevPath)
	if err != nil {
		return lhMajMinToNameMap, lhNameToMajMinMap, fmt.Errorf("unable to read longhorn devs")
	}

	// build two maps:
	// sdX -> major:minor
	// major:minor -> lhpath
	for _, lhDirEnt := range lhPvcList {
		// get the lh device major:minor nexus
		var lhStat syscall.Stat_t
		err := syscall.Stat(LonghornDevPath+"/"+lhDirEnt.Name(), &lhStat)

		if err != nil {
			continue
		}
		majMinKey := getMajorMinor(lhStat)
		lhMajMinToNameMap[majMinKey] = lhDirEnt.Name()
		lhNameToMajMinMap[lhDirEnt.Name()] = majMinKey

	}
	return lhMajMinToNameMap, lhNameToMajMinMap, nil
}

// First map: maj:min -> sdX
// Second map: sdX -> maj:min
func SCSI_GetMajMinMaps() (map[string]string, map[string]string, error) {
	sdMajMinToNameMap := make(map[string]string) // maj:min -> sdX
	sdNameToMajMinMap := make(map[string]string) // sdX -> maj:min

	blockDevs, err := os.ReadDir("/sys/class/block/")
	if err != nil {
		return sdMajMinToNameMap, sdNameToMajMinMap, fmt.Errorf("unable to read sd devs")
	}

	for _, devEnt := range blockDevs {
		if !strings.HasPrefix(devEnt.Name(), "sd") {
			continue
		}

		var blockStat syscall.Stat_t
		err := syscall.Stat("/dev/"+devEnt.Name(), &blockStat)
		if err != nil {
			continue
		}
		majMinVal := getMajorMinor(blockStat)
		sdMajMinToNameMap[majMinVal] = devEnt.Name()
		sdNameToMajMinMap[devEnt.Name()] = majMinVal
	}
	return sdMajMinToNameMap, sdNameToMajMinMap, nil
}

// return two maps of pv-name/longhorn-name -> pvc-name
// and pvc-name -> pv-name/longhorn-name
func PvPvcMaps() (map[string]string, map[string]string, error) {
	pvsMap := make(map[string]string)
	pvcsMap := make(map[string]string)

	clientset, err := GetClientSet()
	if err != nil {
		return pvsMap, pvcsMap, fmt.Errorf("PvToPvc_Map: can't get clientset %v", err)
	}

	pvcs, err := clientset.CoreV1().PersistentVolumeClaims(EVEKubeNameSpace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return pvsMap, pvcsMap, fmt.Errorf("get pvcs:%v", err)
	}
	for _, pvc := range pvcs.Items {
		pvsMap[pvc.Spec.VolumeName] = pvc.ObjectMeta.Name
		pvcsMap[pvc.ObjectMeta.Name] = pvc.Spec.VolumeName
	}
	return pvsMap, pvcsMap, nil
}
