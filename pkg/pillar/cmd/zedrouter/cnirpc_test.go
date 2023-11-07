// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter_test

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cmd/zedrouter"
)

func TestGetAppNameFromPodName(t *testing.T) {
	tests := []struct {
		podName        string
		expectedName   string
		expectedPrefix string
		expectedError  string
	}{
		{"my-app-31ee4", "my-app", "31ee4", ""},
		{"myapp-31ee4", "myapp", "31ee4", ""},
		{"virt-launcher-my-app-31ee4-6cr98", "my-app", "31ee4", ""},
		{"virt-launcher-myapp-31ee4-6cr98", "myapp", "31ee4", ""},
		{"virt-launcher-notevepod", "", "",
			"unexpected pod name generated for VMI: virt-launcher-notevepod"},
		{"notevepod", "", "",
			"pod name without dash separator: notevepod"},
	}
	handler := zedrouter.ZedrouterRPCHandler{}
	for _, test := range tests {
		name, uuidPrefix, err := handler.GetAppNameFromPodName(test.podName)
		if test.expectedError != "" {
			if err == nil || err.Error() != test.expectedError {
				t.Errorf("want error %s, but got %v", test.expectedError, err)
			}
		} else {
			if err != nil || name != test.expectedName ||
				uuidPrefix != test.expectedPrefix {
				t.Errorf("want %s/%s/%v, but got %s/%s/%v",
					test.expectedName, test.expectedPrefix, test.expectedError,
					name, uuidPrefix, err)
			}
		}
	}
}
