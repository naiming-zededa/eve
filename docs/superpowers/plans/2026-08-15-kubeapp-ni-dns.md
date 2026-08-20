# Native Kubernetes NI DNS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish native-Kubernetes zedrouter allocations per NI and expose them through CoreDNS only when ENCC native orchestration is enabled.

**Architecture:** zedrouter carries Kubernetes identity into `AppNetworkStatus`; node-local zedkube instances merge their allocations into per-NI ConfigMaps; the elected leader renders one deterministic CoreDNS custom server block and rolls CoreDNS only on content changes.

**Tech Stack:** Go, pillar pubsub, Kubernetes client-go, K3s `coredns-custom`, CoreDNS `hosts` plugin.

**Spec:** `docs/superpowers/plans/2026-08-15-kubeapp-ni-dns-design.md`

## Global Constraints

- Run only when `EdgeNodeClusterConfig.NativeK8sOrchestrationEnabled()` is true.
- Preserve unrelated dirty-worktree changes and unrelated ConfigMap data.
- Canonical DNS name is `<app>.<namespace>.<ni-display-name>.internal`.
- Restart CoreDNS only when generated DNS content changes.
- Use dockerized pillar vet/fmt verification; do not run native macOS pillar tests.

---

### Task 1: Carry Kubernetes identity in allocation status

**Files:**
- Modify: `pkg/pillar/types/zedroutertypes.go`
- Modify: `pkg/pillar/cmd/zedrouter/appnetwork.go`
- Test: `pkg/pillar/types/zedroutertypes_test.go`

**Interfaces:**
- Produces: `AppNetworkStatus.KubeApp *KubeAppInfo` for zedkube.

- [ ] Add a failing copy-contract test proving native identity survives config-to-status synchronization.
- [ ] Run pillar vet and confirm the missing field/copy fails compilation or the assertion fails in Linux test execution.
- [ ] Add `KubeApp` to status and copy a value snapshot in `doCopyAppNetworkConfigToStatus`.
- [ ] Re-run pillar vet/fmt.

### Task 2: Extract and render NI DNS allocations

**Files:**
- Create: `pkg/pillar/cmd/zedkube/kubeappdns.go`
- Create: `pkg/pillar/cmd/zedkube/kubeappdns_test.go`

**Interfaces:**
- Produces: `kubeAppNIAllocation`, `allocationsForStatus`, `renderKubeAppDNS`.

- [ ] Add failing table tests for disabled ENCC, pending/inactive/error states, MAC-only switch state, IPv4/IPv6, invalid NI display names, and alias collisions.
- [ ] Run pillar vet and observe undefined production interfaces.
- [ ] Implement minimal extraction, validation, stable sorting, and CoreDNS rendering.
- [ ] Re-run pillar vet/fmt.

### Task 3: Reconcile allocation and CoreDNS ConfigMaps

**Files:**
- Modify: `pkg/pillar/cmd/zedkube/kubeappdns.go`
- Modify: `pkg/pillar/cmd/zedkube/kubeappdns_test.go`

**Interfaces:**
- Produces: `reconcileNodeNIAllocations(context.Context, kubernetes.Interface, ...)` and `reconcileCoreDNS(context.Context, kubernetes.Interface, ...)`.

- [ ] Add failing fake-client tests proving per-node merge/removal ownership, preservation of foreign data, idempotency, leader gating, and rollout only on content changes.
- [ ] Run pillar vet and observe undefined reconciler failures.
- [ ] Implement ConfigMap create/update with conflict retry and CoreDNS Deployment hash annotation.
- [ ] Re-run pillar vet/fmt.

### Task 4: Wire pubsub and periodic reconciliation

**Files:**
- Modify: `pkg/pillar/cmd/zedkube/zedkube.go`
- Modify: `pkg/pillar/cmd/zedkube/kubeappdns_test.go`

**Interfaces:**
- Consumes: zedrouter `AppNetworkStatus`, ENCC state, NI status, and stats-leader state.

- [ ] Add a failing gate/orchestration test for native orchestration disabled and follower behavior.
- [ ] Add and activate the zedrouter status subscription, process its events, and invoke DNS reconciliation from the existing bounded ten-second native-app timer.
- [ ] Run gofmt, `make pillar-fmt-check`, and `make pillar-vet` where the environment permits.
- [ ] Review the final diff for unrelated changes; do not commit.
