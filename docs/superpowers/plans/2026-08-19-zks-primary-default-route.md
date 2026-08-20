# ZKS Primary Default Route Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep `eth0` as the default route for native ZKS workloads attached through cluster-wide EVE NI NADs while preserving controller-managed EVE application routing.

**Architecture:** Zedkube defensively applies the same cluster-wide/type predicate when resolving a NAD back to a Network Instance that it already applies when provisioning the NAD. Eve-bridge treats the resulting per-pod marker as a native-ZKS classification override, so marked workloads retain ordinary Kubernetes `eth0` routing even inside `eve-kube-app`; unmarked controller applications retain the existing EVE route treatment.

**Tech Stack:** Go, CNI, Multus NetworkAttachmentDefinition API, Pillar zedkube, eve-bridge, Go unit tests.

**Spec:** `docs/superpowers/specs/2026-08-19-zks-primary-default-route-design.md`

## Global Constraints

- The routing behavior applies only to workloads resolved through applicable cluster-wide EVE NI NADs.
- Native ZKS workloads always keep `eth0` as default; there is no NI default-route override.
- Controller-managed EVE applications keep their current `eth0` suppression and Kubernetes service/node routes.
- Secondary NI DHCP processing and zedrouter route installation remain unchanged.
- Preserve all unrelated modifications already present in the dirty worktree; stage only task-specific hunks.
- Pillar verification runs in Docker through top-level targets, never directly on macOS.

---

### Task 1: Restrict workload discovery to applicable cluster-wide NI NADs

**Files:**
- Modify: `pkg/pillar/cmd/zedkube/kubeappnetwork.go:247-264`
- Test: `pkg/pillar/cmd/zedkube/kubeappnetwork_identity_test.go`

**Interfaces:**
- Consumes: `niNADApplicable(status types.NetworkInstanceStatus) bool` and `niNADName(status types.NetworkInstanceStatus) string` from `ninad.go`.
- Produces: `niUUIDForNADStatuses(namespace, nadName string, statuses []types.NetworkInstanceStatus) (uuid.UUID, bool)`, used by `(*zedkube).niUUIDForNAD` and directly unit tested.

- [ ] **Step 1: Write the failing cluster-wide lookup test**

Add imports for Pillar `types` and `github.com/satori/go.uuid`, then add a table-driven test:

```go
func TestNIUUIDForNADStatusesRequiresApplicableClusterWideNI(t *testing.T) {
	clusterLocalID := uuid.NewV4()
	deviceLocalID := uuid.NewV4()
	clusterCloudID := uuid.NewV4()
	statuses := []types.NetworkInstanceStatus{
		{NetworkInstanceConfig: types.NetworkInstanceConfig{
			UUIDandVersion: types.UUIDandVersion{UUID: clusterLocalID},
			DisplayName: "cluster-local", Type: types.NetworkInstanceTypeLocal,
			ClusterWide: true,
		}},
		{NetworkInstanceConfig: types.NetworkInstanceConfig{
			UUIDandVersion: types.UUIDandVersion{UUID: deviceLocalID},
			DisplayName: "device-local", Type: types.NetworkInstanceTypeLocal,
			ClusterWide: false,
		}},
		{NetworkInstanceConfig: types.NetworkInstanceConfig{
			UUIDandVersion: types.UUIDandVersion{UUID: clusterCloudID},
			DisplayName: "cluster-cloud", Type: types.NetworkInstanceTypeCloud,
			ClusterWide: true,
		}},
	}

	tests := []struct {
		name      string
		namespace string
		nadName   string
		wantUUID  uuid.UUID
		wantOK    bool
	}{
		{"cluster-wide local", kubeapi.EVEKubeNameSpace, "ni-cluster-local", clusterLocalID, true},
		{"device-local rejected", kubeapi.EVEKubeNameSpace, "ni-device-local", uuid.UUID{}, false},
		{"unsupported type rejected", kubeapi.EVEKubeNameSpace, "ni-cluster-cloud", uuid.UUID{}, false},
		{"wrong namespace rejected", "default", "ni-cluster-local", uuid.UUID{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := niUUIDForNADStatuses(tc.namespace, tc.nadName, statuses)
			if ok != tc.wantOK || got != tc.wantUUID {
				t.Fatalf("got UUID/ok %s/%v, want %s/%v", got, ok, tc.wantUUID, tc.wantOK)
			}
		})
	}
}
```

Also import `github.com/lf-edge/eve/pkg/pillar/kubeapi` for the namespace constant.

- [ ] **Step 2: Run the targeted test and verify it fails**

Run inside the existing Linux Go builder:

```bash
go test -tags k ./cmd/zedkube -run TestNIUUIDForNADStatusesRequiresApplicableClusterWideNI -v
```

Expected: build failure because `niUUIDForNADStatuses` is undefined.

- [ ] **Step 3: Implement the pure lookup and delegate the subscription method to it**

Replace the lookup body with:

```go
func (z *zedkube) niUUIDForNAD(namespace, nadName string) (uuid.UUID, bool) {
	var statuses []types.NetworkInstanceStatus
	for _, item := range z.subNetworkInstanceStatus.GetAll() {
		statuses = append(statuses, item.(types.NetworkInstanceStatus))
	}
	return niUUIDForNADStatuses(namespace, nadName, statuses)
}

func niUUIDForNADStatuses(namespace, nadName string,
	statuses []types.NetworkInstanceStatus) (uuid.UUID, bool) {
	if namespace != kubeapi.EVEKubeNameSpace {
		return uuid.UUID{}, false
	}
	for _, status := range statuses {
		if niNADApplicable(status) && niNADName(status) == nadName {
			return status.UUIDandVersion.UUID, true
		}
	}
	return uuid.UUID{}, false
}
```

- [ ] **Step 4: Run the targeted test and verify it passes**

Run:

```bash
go test -tags k ./cmd/zedkube -run TestNIUUIDForNADStatusesRequiresApplicableClusterWideNI -v
```

Expected: PASS for all four cases.

- [ ] **Step 5: Commit only the cluster-wide lookup hunks**

```bash
git add -p pkg/pillar/cmd/zedkube/kubeappnetwork.go pkg/pillar/cmd/zedkube/kubeappnetwork_identity_test.go
git commit -s -S -m "fix(zedkube): restrict NI NAD lookup to cluster scope"
```

### Task 2: Preserve the primary default route for marked native ZKS workloads

**Files:**
- Modify: `pkg/kube/eve-bridge/eve-bridge.go:89-118`
- Test: `pkg/kube/eve-bridge/eve-bridge_test.go`

**Interfaces:**
- Consumes: `isKubeAppNIPod(namespace, podName string) bool`, whose marker is created only after Task 1 resolves an applicable cluster-wide NI NAD.
- Produces: `isControllerEVEApp(namespace, podName string, isVMI, isNativeKubeApp bool) bool`, called by `parseArgs` to select traditional EVE routing.

- [ ] **Step 1: Write failing workload-classification tests**

Add the following table-driven test:

```go
func TestIsControllerEVEApp(t *testing.T) {
	tests := []struct {
		name, namespace, podName string
		isVMI, isNativeKubeApp   bool
		want                       bool
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
```

Add a route-argument test that constructs fresh input for each case:

```go
func TestPrepareStdinForBridgeDelegateDefaultRoutePolicy(t *testing.T) {
	tests := []struct {
		name                 string
		controllerEVEApp     bool
		wantDefaultGateway   bool
		wantRouteCount       int
	}{
		{"native or ordinary workload", false, true, 1},
		{"controller EVE application", true, false, 3},
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
				t.Fatalf("isDefaultGateway=%v, want %v", got["isDefaultGateway"], tc.wantDefaultGateway)
			}
			routes := got["ipam"].(map[string]interface{})["routes"].([]interface{})
			if len(routes) != tc.wantRouteCount {
				t.Fatalf("got %d routes, want %d", len(routes), tc.wantRouteCount)
			}
		})
	}
}
```

- [ ] **Step 2: Run the eve-bridge tests and verify the classification test fails**

Run in a Linux container from `pkg/kube/eve-bridge` using the vendored module:

```bash
go test -mod=vendor ./... -run 'TestIsControllerEVEApp|TestPrepareStdinForBridgeDelegateDefaultRoutePolicy' -v
```

Expected: build failure because `isControllerEVEApp` is undefined.

- [ ] **Step 3: Implement controller/native classification and update `parseArgs`**

Add:

```go
func isControllerEVEApp(namespace, podName string,
	isVMI, isNativeKubeApp bool) bool {
	if isNativeKubeApp || namespace != eveKubeNamespace {
		return false
	}
	if !isVMI && strings.HasPrefix(podName, "cdi-upload-") &&
		strings.Contains(podName, "-pvc-") {
		return false
	}
	return true
}
```

Replace the current namespace/marker block in `parseArgs` with:

```go
	isNativeKubeApp := isKubeAppNIPod(namespace, podName)
	isEveApp = isControllerEVEApp(namespace, podName, isVMI, isNativeKubeApp)
```

Update the marker comments in eve-bridge and zedkube to state that marker presence classifies a workload as native ZKS and therefore preserves the primary `eth0` default route. Do not change marker contents or secondary-interface processing.

- [ ] **Step 4: Run the targeted eve-bridge tests and verify they pass**

Run:

```bash
go test -mod=vendor ./... -run 'TestIsControllerEVEApp|TestPrepareStdinForBridgeDelegateDefaultRoutePolicy|TestPrepareStdinForDhcpDelegateUsesStableMACClientID' -v
```

Expected: PASS for classification, route policy, and the pre-existing stable DHCP client-ID behavior.

- [ ] **Step 5: Commit only the route-classification hunks**

```bash
git add -p pkg/kube/eve-bridge/eve-bridge.go pkg/kube/eve-bridge/eve-bridge_test.go pkg/pillar/cmd/zedkube/kubeappnetwork.go
git commit -s -S -m "fix(kube): keep primary route for native ZKS apps"
```

### Task 3: Run repository-level verification

**Files:**
- Verify only; no planned source changes.

**Interfaces:**
- Consumes: Task 1 cluster-wide NAD lookup and Task 2 eve-bridge routing classification.
- Produces: compilation, formatting, and targeted-test evidence for handoff.

- [ ] **Step 1: Format only touched Go files**

```bash
gofmt -w pkg/pillar/cmd/zedkube/kubeappnetwork.go pkg/pillar/cmd/zedkube/kubeappnetwork_identity_test.go pkg/kube/eve-bridge/eve-bridge.go pkg/kube/eve-bridge/eve-bridge_test.go
```

- [ ] **Step 2: Run Pillar formatting and static checks in Docker**

```bash
make pillar-fmt-check
make pillar-vet
```

Expected: both commands exit 0. If the repository's pinned Go builder image is unavailable remotely, reuse the existing local builder with `BUILD=local` and report that environment limitation.

- [ ] **Step 3: Re-run both targeted Linux test groups**

Run the zedkube test with `-tags k` from the Pillar module and the eve-bridge test from its module using the same Linux builder used by `pillar-vet`:

```bash
go test -tags k ./cmd/zedkube -run TestNIUUIDForNADStatusesRequiresApplicableClusterWideNI -v
go test -mod=vendor ./... -run 'TestIsControllerEVEApp|TestPrepareStdinForBridgeDelegateDefaultRoutePolicy|TestPrepareStdinForDhcpDelegateUsesStableMACClientID' -v
```

Expected: both commands exit 0.

- [ ] **Step 4: Audit the final diff for scope and worktree preservation**

```bash
git diff --check
git status --short
git diff -- pkg/pillar/cmd/zedkube/kubeappnetwork.go pkg/pillar/cmd/zedkube/kubeappnetwork_identity_test.go pkg/kube/eve-bridge/eve-bridge.go pkg/kube/eve-bridge/eve-bridge_test.go
```

Confirm that the new behavior is gated by `niNADApplicable`, that no Multus default-route override was added, and that no unrelated dirty-worktree content was staged or altered.
