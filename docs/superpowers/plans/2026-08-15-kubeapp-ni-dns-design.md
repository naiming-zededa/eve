# Native Kubernetes NI DNS design

## Goal

Publish zedrouter-authoritative MAC/IP allocations for directly deployed Kubernetes workloads into one ConfigMap per EVE Network Instance, then expose ready addresses through the K3s CoreDNS `internal` zone. The feature runs only while `EdgeNodeClusterConfig.NativeK8sOrchestrationEnabled()` is true.

## Data flow

1. zedkube synthesizes `AppNetworkConfig` with `KubeAppInfo`.
2. zedrouter allocates the MAC/IP through its normal NI path and copies `KubeAppInfo` into `AppNetworkStatus`.
3. Every node's zedkube merges its ready local statuses into the NI allocation ConfigMap in `eve-kube-app`. Entries carry the node name so a stale node cannot delete a replacement node's entry after migration.
4. The elected zedkube stats leader lists all managed NI allocation ConfigMaps, deterministically renders `kube-system/coredns-custom[data.eve-ni.server]`, and restarts the CoreDNS Deployment only when rendered DNS content changes.

## Names and ownership

- Canonical DNS name: `<app>.<namespace>.<ni-display-name>.internal`.
- Convenience alias: `<app>.internal`, emitted only when the app label is unique across all rendered allocations.
- NI display names must be DNS-1123 labels. zedkube defensively rejects invalid names from DNS publication without changing app connectivity.
- zedkube owns only ConfigMaps bearing its managed label and only the `eve-ni.server` key inside `coredns-custom`; unrelated keys are preserved.

## Readiness and lifecycle

- MAC-only switch-NI allocations are persisted but do not produce a DNS record until an address is learned.
- Pending, failed, inactive, controller-managed, and address-less statuses do not produce DNS records.
- A node removes only records whose `nodeName` equals its own node name. A replacement node overwrites the stable app UUID entry before the old node can remove it.
- Kubernetes API writes use resource-version conflict retries and bounded contexts.
- The leader performs a complete render, making retries and leader handoff idempotent.

## CoreDNS behavior

K3s mounts `coredns-custom` and imports `*.server` keys. The generated server block uses the CoreDNS `hosts` plugin for A/AAAA/PTR data under `internal`. A SHA-256 content annotation on the CoreDNS pod template performs a rolling restart only after the generated content changes; repeated reconciles are no-ops.

## Verification

Pure tests cover readiness extraction, DNS-1123 validation, canonical/alias collision behavior, deterministic rendering, and native-orchestration gating. Fake-client tests cover ConfigMap preservation/idempotency and the content-change-only CoreDNS rollout.
