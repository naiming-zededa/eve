// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
)

func TestIsControllerEVEApp(t *testing.T) {
	tests := []struct {
		name, namespace, podName string
		isVMI, isNativeKubeApp   bool
		want                     bool
	}{
		{"ordinary Kubernetes", "default", "web-abc", false, false, false},
		{"controller EVE app", eveKubeNamespace, "eve-app-abc", false, false, true},
		{"native ZKS outside EVE namespace", "default", "web-abc", false, true, false},
		{"native ZKS inside EVE namespace", eveKubeNamespace, "web-abc", false, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isControllerEVEApp(tc.namespace, tc.podName,
				tc.isVMI, tc.isNativeKubeApp); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPrepareStdinForBridgeDelegateDefaultRoutePolicy(t *testing.T) {
	tests := []struct {
		name                  string
		controllerEVEApp      bool
		wantDefaultGateway    bool
		wantRouteDestinations []string
	}{
		{"native or ordinary workload", false, true, []string{"10.42.0.0/16"}},
		{"controller EVE application", true, false,
			[]string{"10.42.0.0/16", clusterSvcIPRange, "10.244.244.1/28"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := rawJSONStruct{
				"nodeIP": "10.244.244.1/28",
				"ipam": rawJSONStruct{"routes": []interface{}{
					rawJSONStruct{"dst": "10.42.0.0/16"},
				}},
			}
			raw, err := prepareStdinForBridgeDelegate(input, tc.controllerEVEApp)
			if err != nil {
				t.Fatal(err)
			}
			var got rawJSONStruct
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			if got["isDefaultGateway"] != tc.wantDefaultGateway {
				t.Fatalf("isDefaultGateway=%v, want %v", got["isDefaultGateway"],
					tc.wantDefaultGateway)
			}
			if routeDestinations := bridgeRouteDestinations(t, got); !reflect.DeepEqual(
				routeDestinations, tc.wantRouteDestinations) {
				t.Fatalf("route destinations=%v, want %v", routeDestinations,
					tc.wantRouteDestinations)
			}
		})
	}
}

func TestMarkedNativeKubeAppKeepsPrimaryDefaultRouteInEVEKubeNamespace(t *testing.T) {
	originalMarkerDir := kubeAppMarkerDir
	kubeAppMarkerDir = t.TempDir()
	t.Cleanup(func() { kubeAppMarkerDir = originalMarkerDir })

	namespace := eveKubeNamespace
	podName := "native-zks-test"
	markerPath := filepath.Join(kubeAppMarkerDir, namespace+"_"+podName)
	if err := os.WriteFile(markerPath, nil, 0o600); err != nil {
		t.Fatalf("failed to create marker: %v", err)
	}

	if !isKubeAppNIPod(namespace, podName) {
		t.Fatal("created marker was not detected")
	}
	stdinData := []byte(`{"cniVersion":"0.3.1","name":"test","type":"eve-bridge","nodeIP":"10.244.244.1/28","ipam":{"routes":[{"dst":"10.42.0.0/16"}]}}`)
	stdinArgs, _, gotPodName, gotNamespace, _, _, _, isEveApp, err := parseArgs(&skel.CmdArgs{
		Args:      "K8S_POD_NAME=" + podName + ";K8S_POD_NAMESPACE=" + namespace,
		StdinData: stdinData,
	})
	if err != nil {
		t.Fatalf("parseArgs failed: %v", err)
	}
	if gotPodName != podName || gotNamespace != namespace {
		t.Fatalf("parsed pod identity=%q/%q, want %q/%q", gotNamespace, gotPodName,
			namespace, podName)
	}
	if isEveApp {
		t.Fatal("marked native workload in eve-kube-app was classified as controller-managed")
	}

	raw, err := prepareStdinForBridgeDelegate(stdinArgs, isEveApp)
	if err != nil {
		t.Fatalf("prepareStdinForBridgeDelegate failed: %v", err)
	}
	var got rawJSONStruct
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("failed to decode bridge delegate config: %v", err)
	}
	if got["isDefaultGateway"] != true {
		t.Fatalf("isDefaultGateway=%v, want true", got["isDefaultGateway"])
	}
	if routeDestinations := bridgeRouteDestinations(t, got); !reflect.DeepEqual(
		routeDestinations, []string{"10.42.0.0/16"}) {
		t.Fatalf("route destinations=%v, want [10.42.0.0/16]", routeDestinations)
	}
}

func bridgeRouteDestinations(t *testing.T, stdinArgs rawJSONStruct) []string {
	t.Helper()
	ipamArgs, ok := stdinArgs["ipam"].(map[string]interface{})
	if !ok {
		t.Fatalf("ipam=%T, want object", stdinArgs["ipam"])
	}
	routes, ok := ipamArgs["routes"].([]interface{})
	if !ok {
		t.Fatalf("routes=%T, want array", ipamArgs["routes"])
	}
	destinations := make([]string, 0, len(routes))
	for _, route := range routes {
		routeArgs, ok := route.(map[string]interface{})
		if !ok {
			t.Fatalf("route=%T, want object", route)
		}
		destination, ok := routeArgs["dst"].(string)
		if !ok {
			t.Fatalf("route destination=%T, want string", routeArgs["dst"])
		}
		destinations = append(destinations, destination)
	}
	return destinations
}

func TestPrepareStdinForDhcpDelegateUsesStableMACClientID(t *testing.T) {
	stdinArgs := rawJSONStruct{
		"cniVersion": "0.3.1",
		"name":       "ni-cluster-switch-ni",
		"type":       "eve-bridge",
	}
	mac := net.HardwareAddr{0x02, 0x16, 0x3e, 0x83, 0x6f, 0xb1}

	dhcpArgs, err := prepareStdinForDhcpDelegate(stdinArgs, mac)
	if err != nil {
		t.Fatalf("prepareStdinForDhcpDelegate failed: %v", err)
	}
	var got struct {
		IPAM struct {
			Type    string `json:"type"`
			Provide []struct {
				Option string `json:"option"`
				Value  string `json:"value"`
			} `json:"provide"`
		} `json:"ipam"`
	}
	if err := json.Unmarshal(dhcpArgs, &got); err != nil {
		t.Fatalf("failed to decode DHCP delegate config: %v", err)
	}
	if got.IPAM.Type != "dhcp" {
		t.Fatalf("unexpected IPAM type %q", got.IPAM.Type)
	}
	if len(got.IPAM.Provide) != 1 {
		t.Fatalf("expected one provided DHCP option, got %+v", got.IPAM.Provide)
	}
	if got.IPAM.Provide[0].Option != "dhcp-client-identifier" {
		t.Fatalf("unexpected provided DHCP option %q", got.IPAM.Provide[0].Option)
	}
	wantClientID := "\x00eve-mac-02163e836fb1"
	if got.IPAM.Provide[0].Value != wantClientID {
		t.Fatalf("unexpected DHCP client ID %q, want %q",
			got.IPAM.Provide[0].Value, wantClientID)
	}
}
