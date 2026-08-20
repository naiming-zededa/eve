# ZKS primary default-route design

## Goal

Native Kubernetes workloads managed by zedkube keep the Kubernetes primary
interface (`eth0`) as their default route when they attach through one or more
cluster-wide EVE Network Instance NADs. Controller-managed EVE applications
retain their existing routing behavior, where `eth0` is not a default gateway
and application egress is provided by an EVE Network Instance.

## Routing contract

- An ordinary Kubernetes workload uses `eth0` as its default route.
- A native ZKS workload that attaches through an applicable cluster-wide EVE NI
  NAD also uses `eth0` as its default route.
- A controller-managed EVE application continues to suppress the default route
  on `eth0` and keeps explicit routes to Kubernetes node and service networks.
- Additional EVE NI interfaces continue to apply all routes returned by their
  DHCP exchanges. If an NI also returns an unqualified default route, the
  existing kernel `EEXIST` handling leaves the earlier `eth0` default route in
  place.
- There is no annotation or other override for selecting an EVE NI as the
  default route of a native ZKS workload.

## Workload classification

Zedkube already writes one marker file for every directly deployed Kubernetes
workload that it manages. A workload is managed by this path only when its NAD
resolves to a Network Instance for which the shared NAD applicability predicate
is true: the NI is cluster-wide and has a type served by eve-bridge. Eve-bridge
will use marker presence to classify the pod as a native ZKS workload.

The NAD-to-NI lookup will enforce the applicability predicate even though NAD
provisioning already applies the same check. This prevents stale NADs or a name
collision with a device-local NI from placing a workload into the native ZKS
routing path.

Marker classification takes precedence over namespace classification. This is
required so a directly deployed workload in the `eve-kube-app` namespace still
keeps the `eth0` default route. An unmarked workload in `eve-kube-app` remains a
controller-managed EVE application and retains the existing EVE route treatment.

Missing or unreadable markers preserve the existing fallback behavior: pods in
`eve-kube-app` are treated as controller-managed EVE applications, while pods in
other namespaces are treated as ordinary Kubernetes workloads.

## Eve-bridge changes

Route classification will distinguish native ZKS workloads from traditional
EVE applications instead of folding both into `isEveApp`.

For the primary `eth0` CNI call:

- ordinary Kubernetes and native ZKS workloads set `isDefaultGateway=true`;
- controller-managed EVE applications set `isDefaultGateway=false` and retain
  the existing Kubernetes service and node routes.

Secondary NI CNI processing, DHCP results, zedrouter RPC payloads, and route
installation remain unchanged. The Multus `default-route` field is not parsed or
honored by EVE for native ZKS workloads.

## Scope

The implementation changes eve-bridge workload classification and adds a
defensive cluster-wide applicability check to zedkube's NAD-to-NI lookup. The
marker file format and writer remain unchanged. No eve-api, shared Pillar type,
zedrouter, NI reconciler, or NetworkAttachmentDefinition changes are required.

## Verification

Unit tests cover primary-interface configuration for:

1. an ordinary Kubernetes workload;
2. a controller-managed EVE application;
3. a native ZKS workload outside `eve-kube-app`;
4. a native ZKS workload inside `eve-kube-app`.

The tests verify whether `isDefaultGateway` is enabled and whether the special
Kubernetes service/node routes are added. Existing DHCP and secondary-interface
tests continue to verify that NI processing is unchanged. Zedkube tests verify
that applicable cluster-wide NIs resolve from their NAD names and device-local
or otherwise inapplicable NIs do not resolve and therefore do not create native
ZKS workload markers.
