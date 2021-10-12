// Copyright (c) 2018,2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"io/ioutil"
	"strconv"
	"strings"
)

// GetEveMemoryLimitInBytes returns memory limit
// reserved for eve in bytes
func GetEveMemoryLimitInBytes() (uint64, error) {
	return readUint64File(EveMemoryLimitFile)
}

// GetEveMemoryUsageInBytes returns memory limit
// reserved for eve in bytes
func GetEveMemoryUsageInBytes() (uint64, error) {
	return readUint64File(EveMemoryUsageFile)
}

// GetEveKmemUsageInBytes returns memory limit
// reserved for eve in bytes
func GetEveKmemUsageInBytes() (uint64, error) {
	return readUint64File(EveKmemUsageFile)
}

func readUint64File(filename string) (uint64, error) {
	dataBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return 0, err
	}
	dataString := strings.TrimSpace(string(dataBytes))
	dataUint64, err := strconv.ParseUint(dataString, 10, 64)
	return dataUint64, err
}
