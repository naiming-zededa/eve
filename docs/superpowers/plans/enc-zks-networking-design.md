# Design: ZKS App Networking on Shared EVE Network Instances

> Companion to [`enc-zks-merge.md`](./enc-zks-merge.md), which captures the original
> requirements and open "Design issues". This document records the design, the decisions
> taken so far, and the still-open issues framed as **Issue → Options → Tradeoffs** for
> collaborative resolution.

## 1. Context

EVE runs eve-k (k3s + KubeVirt) on edge devices. Today **ENC** (EdgeNode Cluster) apps come
from the controller as `AppInstanceConfig` (cluster type `CLUSTER_TYPE_REPLICATED_STORAGE`).
Going forward everything uses `REPLICATED_STORAGE` and **ZKS** becomes an add-on configuration.

ZKS apps are **not** managed by the controller — there is **no `AppInstanceConfig` /
`AppNetworkConfig` in pillar**. They arrive as helm-charts / raw k8s yaml (VMIs or pods) from an
external source. They must reuse the *same* EVE Network Instances (NIs) of type local / switch /
direct-attach that ENC uses, without users defining their own bridges:

- the yaml references a NAD and indicates which NI to use;
- if the yaml omits a static MAC, EVE allocates one; if present, EVE honors it;
- after node reboot, the app gets the same networking provisioning;
- on migration to another node, the app gets the same MAC and (best-effort) the same IP;
- the same node may host both ENC and ZKS apps.

## 2. Why the current pipeline can't serve ZKS as-is (verified in code)

- **NI selection is implicit via MAC.** The singleton NAD `network-instance-attachment` carries
  no NI identity; zedrouter learns the NI by matching the inbound pod MAC to a pre-allocated
  `AppNetAdapterStatus.Mac` (`pkg/pillar/cmd/zedrouter/cni.go:119`). ZKS has no pre-allocated
  adapter, and may have no MAC.
- **The RPC handler hard-fails without an `AppNetworkStatus`** for the pod
  (`pkg/pillar/cmd/zedrouter/cni.go:338-361`).
- **MAC hash inputs** (`pkg/pillar/cmd/zedrouter/ipam.go:60-77`): `appUUID + NI-UUID + adapterNum`,
  with `appNum` *dropped* in `MACGeneratorClusterDeterministic` mode. **No cluster-id** is in the
  hash — cluster-wide MAC stability today comes from the controller-assigned `appUUID` being
  identical on every node. ZKS has no such appUUID.
- **`appNum` is node-local** (`pkg/pillar/cmd/zedrouter/numallocators.go`): 1–255, lowest/highest
  free, persisted per-node — *not* shared across the cluster. IP is
  `AddToIP(DhcpRange.Start, appNum)`, written as a dnsmasq static `dhcp-host` MAC→IP entry.
  **Consequence (confirmed): ENC preserves MAC across migration, but not IP.**

## 3. Decisions taken

1. **IP on migration = best-effort**, not a hard guarantee (matches/exceeds current ENC). No
   cluster-wide IPAM store is mandated by the requirement.
2. **No mutating admission webhook and no mutation of user objects.** ZKS identity is *derived*
   from stable workload metadata, not injected/written anywhere (see §4.2). The MAC reaches the
   guest via the L2 path (see §4.3).
3. **No change to the existing ENC app path.** ENC keeps its singleton NAD + MAC-match flow.
4. **ZKS identity = derived, not stored.** The synthetic appUUID = `hash(namespace + ownerName)`,
   where `ownerName` is the bare ReplicaSet name (or VMI name / bare-pod name), resolved via the
   pod's `ownerReferences`. Every node recomputes the same value from immutable metadata → stable
   across reboot and migration with **nothing to inject, persist, or copy**. **No number
   allocator** — the MAC is the existing ClusterDeterministic wide hash (§4.2). `metadata.uid` is
   *not* used (server-assigned, changes on recreation). Tradeoff: same `namespace+name` → same MAC
   (a recreated workload of the same name reuses its MAC), rather than a fresh identity per
   redeploy; accepted. (An injected random UUID was considered for ENC-parity fresh identity;
   rejected for the label write, RBAC, and recompute-blocking wait it would add.)
5. **ZKS workloads must be bare ReplicaSets, `replicas: 1`.** Deriving from the **RS name** is
   stable only for a bare RS: a Deployment-owned RS name carries a `pod-template-hash` that changes
   on every spec edit (→ MAC would shuffle), and `replicas > 1` share one rsName → one MAC →
   collision. Deployments and multiple stable identities (StatefulSet, per-ordinal UUID) are out of
   scope (see Issue 2).
6. **The per-NI NAD is created by the zedkube leader**; zedkube owns NAD lifecycle, the
   pod→workload mapping it publishes (§4.4), and GC.

## 4. Architecture

### 4.1 Per-NI NAD, created once by the zedkube leader
zedkube creates one NetworkAttachmentDefinition per NI, e.g. `ni-<ni-uuid>`, with CNI config
`{"type":"eve-bridge","networkInstance":"<ni-uuid>"}`, via the idempotent
`kubeapi.CreateOrUpdateNAD` (reused from `pkg/pillar/cmd/zedkube/etherpassthrough.go:78`).
Creation is gated behind `z.isKubeStatsLeader` (`pkg/pillar/cmd/zedkube/leaderelect.go`) so only
one of N master nodes provisions it; idempotence makes it race-safe regardless. The ZKS yaml
references `ni-<uuid>` in its `k8s.v1.cni.cncf.io/networks` annotation. The singleton
`network-instance-attachment` NAD stays in place for ENC back-compat.

### 4.2 ZKS identity: derived from stable workload metadata (the substitute for the missing appUUID)
ENC gets a controller-assigned appUUID identical on every node; ZKS has none. Rather than assign
and store one, EVE **derives** it deterministically so every node recomputes the same value with
**nothing written to user objects**:

- `syntheticUUID = hash(namespace + ownerName)`, where `ownerName` is:
  - **bare ReplicaSet** → the RS name (from the pod's `ownerReferences`);
  - **VMI** (virt-launcher pod) → the VM/VMI name via `base.GetVMINameFromVirtLauncher`;
  - **bare pod** (no controller) → the pod name.
- `metadata.uid` is deliberately **not** used (server-assigned, changes on recreation).

Stability falls out for free: on reboot or migration the RS controller makes a new pod with a new
random name, but the **rsName and namespace are unchanged**, so the recomputed UUID — and thus the
MAC — is identical. Nothing to inject, persist, copy, or block a write on; the Kubernetes object
graph is the only "store", read via `ownerReferences`.

From this UUID:
- **MAC:** `generateAppMac` in **ClusterDeterministic** mode (already selected for
  `withKubeNetworking`) hashes `UUID + NI-UUID + adapterNum`, with `AppNum` omitted. `adapterNum`
  must be derived **deterministically from the interface** (multus net name / sorted NAD order),
  not from config-processing order, or multi-NIC MACs diverge across nodes. Optionally fold in
  `EdgeNodeClusterConfig.ClusterID`, **gated to the ZKS path only** (Issue 4), for cross-cluster
  uniqueness without reshuffling ENC MACs. No number allocator is needed.
- **IP (small space → best-effort):** see Issue 1 in §6. The node-local `appNum` allocator keyed
  on the synthetic UUID yields the same IP on same-node restart, best-effort across migration —
  matching ENC.

Tradeoff: derivation gives **same `namespace+name` → same MAC** (a recreated workload of the same
name reuses its MAC) rather than a fresh identity per redeploy. Accepted (§3.4): it meets the
stability requirement at the lowest complexity — no label, no webhook, no zedkube write, no RBAC
patch, no recompute-blocking wait.

### 4.3 How the MAC reaches the guest (no webhook)
In ENC, EVE authors the spec and pre-bakes the MAC into both the pod annotation `MacRequest`
and `spec.domain.devices.interfaces[].macAddress` (`pkg/pillar/hypervisor/kubevirt.go:395-426`).
ZKS yaml is external and omits the MAC, so the MAC arrives at **network-setup time** instead:

1. On `ConnectPodAtL2`, zedrouter's nireconciler creates the pod-side veth `netX` with the
   computed MAC (`pkg/pillar/nireconciler/linuxitems/vif.go`, `configureVethPeer(..., AppIfMAC,
   ...)`) — the *same* code path ENC uses.
2. eve-bridge reports that MAC in its CNI `Result`.
3. KubeVirt **bridge binding** (`kubevirt.go:412`) delegates the pod-interface MAC (and IP) to
   the guest NIC.

So the guest inherits the nireconciler-programmed MAC even though the VMI spec named none. This
delegation is the documented bridge-mode behavior and is the chosen mechanism. **Validated on
eve-k (see Issue 3):** a bridge-bound multus secondary interface with no `macAddress` produced a
guest NIC whose MAC equalled the CNI-assigned pod-interface MAC exactly.

### 4.4 ZKS pod → app/NI resolution at CNI time
A ZKS pod name carries no UUID prefix (it is `<rsName>-<random>`, user-chosen) and no MAC is
supplied, so neither ENC lookup key works (§2): `getAppByPodName` matches a
`<displayName>-<uuidPrefix>` embedded in the name, and adapter selection matches the supplied MAC.
zedrouter resolves the ZKS pod with three **explicit** inputs instead:

**RPC additions (`cnirpc.CommonCNIRPCArgs`):**
- `Pod.Namespace` *(new)* — eve-bridge already parses `K8S_POD_NAMESPACE` (`eve-bridge.go:88`);
  forward it. `(namespace, podName)` is the unambiguous pod key (pod names aren't unique across
  namespaces).
- `NetworkInstance string` *(new)* — the NI UUID, read by eve-bridge from the NAD's stdin config
  `networkInstance` field (eve-bridge already unmarshals stdin into a map, `eve-bridge.go:71`). Its
  **presence is also the gate** that routes the pod to zedrouter: the existing
  `isEveApp = namespace == "eve-kube-app"` check (`eve-bridge.go:90`) is **false** for ZKS (user
  namespaces), so the `networkInstance` field — not the namespace — is what tells eve-bridge to
  engage zedrouter at all.

**zedkube publishes `KubeAppStatus`** (new pubsub topic): for each observed ZKS pod,
`{namespace, podName, ownerName (rsName/VMI), nodeName}` — the pod→workload mapping zedrouter
cannot compute itself (it is not k8s-aware and does not resolve `ownerReferences`). May also carry
the pre-computed `syntheticUUID`.

**zedrouter ZKS branch** (in `cni.go`, replacing the ENC prefix-match for this path):
1. `(namespace, podName)` → KubeAppStatus → `ownerName` → `syntheticUUID = hash(namespace+ownerName)`
   → the zedkube-synthesized `AppNetworkConfig`/`AppNetworkStatus`.
2. **Adapter by NI:** pick the adapter with `Network == NetworkInstance` (the NI UUID from the RPC).
   If an app has two interfaces on the *same* NI, disambiguate by `PodInterface.Name`.
3. **MAC is an output, not an input:** zedrouter computes it (§4.2) and returns it in
   `ConnectPodAtL2Retval.Interfaces`; eve-bridge surfaces it in the CNI `Result`. (Contrast ENC,
   where the *supplied* MAC selects the adapter.)
4. If KubeAppStatus / the synthesized status isn't present yet (CNI raced ahead of zedkube's
   informer+publish), eve-bridge **waits, bounded** under the kubelet/CNI timeout, then retries —
   a short pod-startup delay. This wait is only about zedkube publish-lag, not recomputability.

### 4.5 Data flow (ZKS, no static MAC)
1. zedkube leader creates the `ni-<uuid>` NAD (with `networkInstance` in its config) from NI config.
2. User RS/VMI yaml references `ni-<uuid>`. zedkube observes the workload, resolves the owner
   (rsName / VMI) via `ownerReferences`, derives `syntheticUUID = hash(namespace+ownerName)`,
   **synthesizes an `AppNetworkConfig`** (NI + that UUID; static MAC if the yaml had one) into
   pubsub, and publishes the pod→workload mapping in `KubeAppStatus`.
3. zedrouter consumes the synthesized config → computes the deterministic MAC, the IP, and the
   dnsmasq static entry → publishes a synthesized `AppNetworkStatus`.
4. Multus → eve-bridge `cmdAdd` for `netX`; eve-bridge forwards `(namespace, podName, ifName,
   networkInstance)` in the RPC.
5. zedrouter resolves the pod (§4.4), computes and returns the MAC; nireconciler programs the veth
   MAC; KubeVirt bridge binding delegates it to the guest; the VM DHCPs and dnsmasq hands it the
   matching IP (§4.3).
6. **Ordering:** if the synthesized status / KubeAppStatus isn't ready, eve-bridge waits (bounded)
   then retries (§4.4).
7. **Reboot / migration:** the RS controller recreates the pod under the same rsName+namespace;
   every node re-derives the same UUID → same MAC (best-effort same IP). Nothing stored or copied.

### 4.6 GC (zedkube-owned)
zedkube watches ZKS workloads; on **workload deletion** it drops the synthesized config so
zedrouter frees node-local state and the dnsmasq entry. GC keys on *workload* deletion, **not**
on CNI DEL / `DisconnectPod` (which also fires during migration, and must not release the app's
networking).

## 5. Answers to the `enc-zks-merge.md` "Design issues"

- **yaml format / which NI:** per-NI NAD named for the NI; NI UUID embedded in the NAD CNI config.
- **eve-bridge changes (`pkg/kube/eve-bridge`):** read `networkInstance` from the stdin config it
  already unmarshals (and use its presence as the ZKS gate, since the `eve-kube-app` namespace
  check excludes ZKS); forward `(namespace, podName, ifName, networkInstance)` in the RPC; surface
  the zedrouter-returned MAC in the CNI `Result`. The veth MAC is programmed by nireconciler (as in
  ENC), and KubeVirt bridge binding delegates it to the guest.
- **zedrouter without `AppNetworkConfig`:** it consumes a zedkube-synthesized `AppNetworkConfig`
  and still publishes `AppNetworkStatus` (load-bearing for nireconciler/nistate). The ZKS pod is
  resolved via `(namespace, podName)` → `KubeAppStatus` → owner → derived UUID, and the adapter via
  the RPC `NetworkInstance` (§4.4); MAC is computed and returned, not matched.
- **direct-attach:** the `host-device` CNI bypasses eve-bridge/zedrouter IPAM; treat as L2
  passthrough (per-NI NAD still applies) with no EVE-managed IP guarantee. Stretch / out of scope.
- **same node hosts ENC + ZKS:** they coexist — ENC's MAC-match branch and ZKS's synthesized,
  identity-keyed branch — with IP-range partitioning to avoid collisions.

## 6. Outstanding issues (Issue → Options → Tradeoffs)

> **MAC is resolved — no allocator.** Earlier drafts considered a scarce cluster-wide ID
> (e.g. [129,254]) feeding both MAC and IP. The MAC needs none of that: ClusterDeterministic
> hashes the **derived** `hash(namespace+ownerName)` UUID into a wide MAC, and at the expected
> scale (≤ ~10–20 interfaces per NI) collisions are negligible even on the 24-bit switch path.
> This issue is therefore **IP-only**, and IP is **best-effort** per decision §3.1.

### Issue 1 — IP allocation for ZKS apps *(IP-only; best-effort)*
A per-NI range is small (the upper half of a /24 ≈ 125 slots), so a **stateless hash collides
quickly** (birthday math: collisions become likely past ~13 apps on one NI). Unlike the MAC
(which uses a wide hash and stays unique), two apps on one NI landing on the same IP is
broken. Given the best-effort decision, Option A is the default; B/C/whereabouts are available
if a hard cluster-wide IP guarantee is later required.

| Option | Guarantee | Cost |
|---|---|---|
| **A. Hash + per-node next-free fallback** | Best-effort; same IP when uncontended, diverges under collision and across nodes | Simplest; stateless |
| **B. Leader allocates + persists on the workload** (label / ConfigMap) | Unique and migration-stable | Reintroduces the persistence the hash approach removed |
| **C. Cluster-wide IPAM store** (CRD or whereabouts-style) | Unique cluster-wide; reusable for ENC later | Heaviest; new subsystem (claim, CAS, GC) |
| **D. Hybrid** — hash as preferred IP, leader persists an override only for the rare collided apps | Unique; mostly stateless | Two code paths |

### Issue 2 — Stable identity for ZKS workloads — **RESOLVED**
**Decision:** **derive** the synthetic appUUID from `hash(namespace + ownerName)` — no injection,
no label, no mutation (§4.2). ZKS requires a **bare ReplicaSet, `replicas: 1`**. zedkube resolves
the pod's owner via `ownerReferences` and publishes the `(namespace, podName) → ownerName` mapping
in `KubeAppStatus` (§4.4); zedrouter derives the same UUID on the read side. Rationale and edge
cases:

- **Why bare RS.** Deriving from the **RS name** is stable only for a bare RS. A Deployment-owned
  RS name carries a `pod-template-hash` that changes on every Deployment spec edit → the derived
  UUID/MAC would shuffle on updates. (And a label-injection alternative fails differently: patching
  a Deployment-owned RS template is reverted — the Deployment controller's `EqualIgnoreHash` finds
  no RS matching its template and rolls to a fresh RS — while patching the Deployment template
  forces a rollout.) If Deployments must be supported later, derive from the **Deployment** name
  instead, or inject via a **mutating admission webhook** — out of current scope.
- **`replicas > 1` unsupported.** All replicas share one rsName → one derived UUID → same MAC →
  collision on the NI. Multiple stable identities → StatefulSet (per-ordinal pod name → per-pod
  UUID), out of scope.
- **VMIs.** Stable VM/VMI name is recovered from the `virt-launcher-<vmname>-<rand>` pod name
  (`base.GetVMINameFromVirtLauncher`).
- **Recreate semantics.** Same `namespace+name` → same MAC (derivation is a pure function); a
  redeploy under the same name reuses its networking. Accepted per §3.4.

### Issue 3 — KubeVirt bridge-binding MAC delegation — **VALIDATED (Option A)**
The design relies on the guest inheriting the CNI-assigned pod-veth MAC when the VMI spec omits
`macAddress`. **Confirmed on eve-k:** a VMI with a bridge-bound multus *secondary* interface and
**no `macAddress`** brought the guest NIC up with the **exact** CNI-assigned MAC.

Evidence (isolated test, generic `bridge` CNI so eve-bridge was not in the loop — the MAC
inheritance is a pure KubeVirt property and transfers to eve-bridge):
- multus `network-status` for the secondary `default/mactest`: `mac = de:43:01:d8:be:ec`
- guest `ip a`: `eth1 link/ether de:43:01:d8:be:ec` — identical.

So **no webhook is needed for VMIs (Option A holds)**. The rejected fallback was **Option B** — a
*stateless* mutating webhook injecting the deterministic `macAddress` (stateless because the MAC is
a pure function of `namespace+ownerName+NI+adapterNum`) — keep only if a future KubeVirt version
regresses. *Action: record the eve-k KubeVirt version this was validated against; re-check on
KubeVirt bumps. Phase-2 (full eve-bridge path + DHCP IP) still pending the ZKS code.*

### Issue 4 — cluster-id in the MAC hash must not disturb ENC
Adding `EdgeNodeClusterConfig.ClusterID` to `generateAppMac` unconditionally would reshuffle
existing ENC MACs.
- **A.** Gate the cluster-id term to the ZKS path only (ENC hash unchanged). *Recommended* —
  honors decision #3.
- **B.** Apply to both, accept a one-time ENC MAC change. *Rejected* per decision #3.

### Issue 5 — DHCP-range exhaustion / scale per NI
The upper-half range caps ZKS apps per NI (~125 on a /24), and ENC + ZKS share the NI subnet.
Define behavior on exhaustion (reject + report vs. spill), confirm the ENC-low / ZKS-high split
is acceptable, and consider larger subnets for clusters expecting many ZKS apps.

## 7. Files to change (implementation outline)

- `pkg/kube/cnirpc/cnirpc.go` — add `NetworkInstance string` to `CommonCNIRPCArgs` and
  `Namespace string` to `AppPod`; make `ConnectPodAtL2Retval.Interfaces` MAC authoritative (MAC is
  an output for ZKS). Additive, backward-compatible.
- `pkg/kube/eve-bridge/eve-bridge.go` — read `networkInstance` from the stdin config (already
  unmarshalled) and use its presence as the ZKS gate (the `eve-kube-app` namespace check excludes
  ZKS); forward `K8S_POD_NAMESPACE` (already parsed) + `networkInstance` in the RPC; surface the
  returned MAC in the CNI `Result`; **bounded wait** (under the CNI/kubelet timeout) for the
  synthesized status / KubeAppStatus before proceeding (§4.4).
- `pkg/pillar/cmd/zedkube/` — new file (e.g. `zksnetwork.go`): leader-gated per-NI NAD
  create/delete from NI status; watch ZKS workloads; resolve pod → owner via `ownerReferences`;
  **publish `KubeAppStatus`** `(namespace, podName, ownerName, nodeName)`; derive
  `hash(namespace+ownerName)` and synthesize/publish `AppNetworkConfig`; GC on workload deletion.
  (No object mutation, no `patch` RBAC — read/watch + own CRD/pubsub only.)
- `pkg/pillar/cmd/zedrouter/cni.go` — ZKS branch: resolve `(namespace, podName)` → `KubeAppStatus`
  → owner → derived UUID; select adapter by RPC `NetworkInstance`; compute+return MAC; publish
  synthesized `AppNetworkStatus`.
- `pkg/pillar/cmd/zedrouter/ipam.go` — ZKS IP path (resolution of Issue 1); `generateAppMac`
  reused, seeded with the derived UUID per Issue 4.
- `pkg/pillar/types/` — synthesized config/status type (or a ZKS-origin flag on
  `AppNetworkConfig`) and the `KubeAppStatus` type; wire publisher (zedkube) / subscriber
  (zedrouter); register topics in `pkg/pillar/zedbox/zedbox.go`.
- `pkg/pillar/docs/zedkube.md`, `pkg/pillar/docs/zedrouter.md` — document the model.

## 8. Readiness / gating checklist (before broad coding)

**Ready to build (additive, low risk):** the RPC field additions (`AppPod.Namespace`,
`NetworkInstance`) in `cnirpc.go` and the eve-bridge gate/forward — safe to start now.

**Decide before writing the new types:**
- **Inbound config delivery:** zedmanager *owns* the `AppNetworkConfig` publication
  (`cmd/zedmanager/zedmanager.go:160`). Do **not** add a second publisher. Introduce a separate
  `ZKSAppNetworkConfig` (or equivalent) that zedrouter subscribes to and converts in a ZKS branch.
- **Outbound status type:** `AppNetworkStatus` subscribers = zedmanager
  (`updateAIStatusUUID` → no-op if no AIStatus), zedagent (`RefreshLpsAddresses` only), msrv
  (benign). Ripple appears harmless ⇒ reuse `AppNetworkStatus` with a **ZKS-origin flag**;
  switch to a separate status topic only if a consumer misbehaves on an unknown UUID. *(Confirm
  `updateAIStatusUUID` nil-safety and that zedagent does not report ZKS statuses upward.)*

**Confirm with the user (gates build order):**
- **Container-pods first vs VMIs.** The doc drifted VMI-centric. Container-first is still the
  lower-risk v1 (a container's netns interface *is* the interface), but the VMI blocker is now
  cleared: **Issue 3 (bridge-binding MAC delegation) is validated** — a bridge-bound secondary
  interface with no `macAddress` gives the guest the CNI-assigned MAC. So VMIs are viable without a
  webhook; container-vs-VMI ordering is now a preference, not a risk gate.

**Quick code spike (≈30 min, likely fine):** confirm zedrouter's
`handleAppNetworkConfigCreate`/`doActivateAppNetwork` path is driven only by
`(AppNetworkConfig + NetworkInstanceStatus)` and has no hidden gate on zedmanager/domainmgr objects
(AppInstanceConfig, DomainStatus) or a cipher/decrypt step a synthesized config won't satisfy.

## 9. Verification

- **Build:** from `pkg/pillar`, `GOOS=linux go build ./...` (native macOS build fails by design);
  `make -C pkg/pillar vet`; unit tests via `make -C pkg/pillar test`. For eve-bridge, build with
  `GOOS=linux go build` from its module root.
- **Lab (eve-k device, real k3s + KubeVirt):**
  1. Create a local NI; confirm the leader node creates the `ni-<uuid>` NAD and other masters
     don't duplicate it.
  2. Apply an external VMI yaml referencing that NAD with **no** `macAddress`; confirm the guest
     NIC comes up with the EVE-computed MAC and a DHCP IP from the NI range. *(Issue 3 — the MAC
     half is already validated in isolation: bridge-bound secondary iface, no `macAddress`, guest
     `eth1` MAC == CNI-assigned pod MAC `de:43:01:d8:be:ec`. This step adds the eve-bridge + DHCP
     end-to-end.)*
  3. Apply a **bare ReplicaSet (`replicas: 1`)** pod referencing the NAD; confirm zedkube publishes
     its `KubeAppStatus` entry and the pod gets the derived MAC/IP via the resolution path (§4.4).
  4. Reboot the node; confirm the same MAC + same IP.
  5. Drain/fail the node so the workload migrates (new pod name, same rsName); confirm the same MAC
     (re-derived) and best-effort same IP.
  6. Delete and re-create the workload under the **same** name; confirm it gets the **same** MAC
     (derivation is a pure function — the accepted recreate semantics).
  7. Run an ENC app concurrently on the same node; confirm it is unaffected and IPs don't collide.
  8. Repeat with a user-supplied static MAC; confirm it is honored.
