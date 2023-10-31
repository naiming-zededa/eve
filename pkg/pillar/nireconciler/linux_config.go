// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nireconciler

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	generic "github.com/lf-edge/eve/pkg/pillar/nireconciler/genericitems"
	linux "github.com/lf-edge/eve/pkg/pillar/nireconciler/linuxitems"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	uuid "github.com/satori/go.uuid"
	"github.com/vishvananda/netlink"
)

// Application connectivity configuration is modeled using dependency graph
// (see libs/depgraph).
// Config graph with all sub-graphs and config item types used for Linux
// network stack:
//
//  +--------------------------------------------------------------------+
//  |                      ApplicationConnectivity                       |
//  |                                                                    |
//  |   +------------------------------------------------------------+   |
//  |   |                           Global                           |   |
//  |   |                                                            |   |
//  |   |   +--------------------------+   +---------------------+   |   |
//  |   |   |       Uplinks            |   |      IPSets         |   |   |
//  |   |   |                          |   |                     |   |   |
//  |   |   |   +--------------+       |   |   +---------+       |   |   |
//  |   |   |   |    Uplink    | ...   |   |   |  IPSet  | ...   |   |   |
//  |   |   |   |  (external)  | ...   |   |   +---------+       |   |   |
//  |   |   |   +--------------+       |   |                     |   |   |
//  |   |   +--------------------------+   +---------------------+   |   |
//  |   |                                                            |   |
//  |   |        +-----------------------------------------+         |   |
//  |   |        |                   BlackHole             |         |   |
//  |   |        |                                         |         |   |
//  |   |        |       +-----------+   +---------+       |         |   |
//  |   |        |       |  DummyIf  |   |  Route  |       |         |   |
//  |   |        |       +-----------+   +---------+       |         |   |
//  |   |        |                                         |         |   |
//  |   |        |    +----------------+   +----------+    |         |   |
//  |   |        |    |  IptablesRule  |   |  IPRule  |    |         |   |
//  |   |        |    +----------------+   +----------+    |         |   |
//  |   |        +-----------------------------------------+         |   |
//  |   |                                                            |   |
//  |   |   +----------------------------------------------------+   |   |
//  |   |   |                   ACLRootChains                    |   |   |
//  |   |   |                                                    |   |   |
//  |   |   |   +--------------------------------------------+   |   |   |
//  |   |   |   |                 IPv4Chains                 |   |   |   |
//  |   |   |   |                                            |   |   |   |
//  |   |   |   |   +-------------------------------+        |   |   |   |
//  |   |   |   |   |         IptablesChain         |        |   |   |   |
//  |   |   |   |   |  (external, created by NIM)   | ...    |   |   |   |
//  |   |   |   |   +-------------------------------+        |   |   |   |
//  |   |   |   +--------------------------------------------+   |   |   |
//  |   |   |                                                    |   |   |
//  |   |   |   +--------------------------------------------+   |   |   |
//  |   |   |   |                 IPv6Chains                 |   |   |   |
//  |   |   |   |                                            |   |   |   |
//  |   |   |   |   +-------------------------------+        |   |   |   |
//  |   |   |   |   |         IptablesChain         |        |   |   |   |
//  |   |   |   |   |  (external, created by NIM)   | ...    |   |   |   |
//  |   |   |   |   +-------------------------------+        |   |   |   |
//  |   |   |   +--------------------------------------------+   |   |   |
//  |   |   +----------------------------------------------------+   |   |
//  |   +------------------------------------------------------------+   |
//  |                                                                    |
//  |   +------------------------------------------------------------+   |
//  |   |                           NI-<UUID>                        |   |
//  |   |                      (one for every NI)                    |   |
//  |   |                                                            |   |
//  |   |   +----------------------------------------------------+   |   |
//  |   |   |                        L2                          |   |   |
//  |   |   |                                                    |   |   |
//  |   |   |              +----------------------+              |   |   |
//  |   |   |              |        Bridge        |              |   |   |
//  |   |   |              |  (L2 NI: external)   |              |   |   |
//  |   |   |              |  (L3 NI: managed)    |              |   |   |
//  |   |   |              +----------------------+              |   |   |
//  |   |   |                                                    |   |   |
//  |   |   |      +---------------+    +-----------------+      |   |   |
//  |   |   |      |  VLANBridge   |    |    VLANPort     |      |   |   |
//  |   |   |      |  (for L2 NI)  |    |   (for L2 NI)   |      |   |   |
//  |   |   |      +---------------+    |    (uplink)     |      |   |   |
//  |   |   |                           +-----------------+      |   |   |
//  |   |   +----------------------------------------------------+   |   |
//  |   |                                                            |   |
//  |   |   +----------------------------------------------------+   |   |
//  |   |   |                        L3                          |   |   |
//  |   |   |                                                    |   |   |
//  |   |   |   +-----------+       +---------------------+      |   |   |
//  |   |   |   |   Route   | ...   |       IPRule        | ...  |   |   |
//  |   |   |   +-----------+       |   (in, out, local)  |      |   |   |
//  |   |   |                       +---------------------+      |   |   |
//  |   |   |                                                    |   |   |
//  |   |   |   +--------------+   +--------------------------+  |   |   |
//  |   |   |   |  IPReserve   |   |       IptablesRule       |  |   |   |
//  |   |   |   | (for bridge) |   |  (MASQUERADE for L3 NI)  |  |   |   |
//  |   |   |   +--------------+   +--------------------------+  |   |   |
//  |   |   +----------------------------------------------------+   |   |
//  |   |                                                            |   |
//  |   |   +----------------------------------------------------+   |   |
//  |   |   |                     Services                       |   |   |
//  |   |   |                                                    |   |   |
//  |   |   |   +---------------+    +-----------------------+   |   |   |
//  |   |   |   |   HTTPServer  |    |     IptablesRule      |   |   |   |
//  |   |   |   |   (metadata)  |    |  (redirect metadata)  |   |   |   |
//  |   |   |   +---------------+    +-----------------------+   |   |   |
//  |   |   |                                                    |   |   |
//  |   |   |   +------------------+    +-------------------+    |   |   |
//  |   |   |   |     dnsmasq      |    |       radvd       |    |   |   |
//  |   |   |   |   (DHCP + DNS)   |    |   (for IPv6 NI)   |    |   |   |
//  |   |   |   +------------------+    +-------------------+    |   |   |
//  |   |   +----------------------------------------------------+   |   |
//  |   |                                                            |   |
//  |   |   +----------------------------------------------------+   |   |
//  |   |   |           AppConn-<UUID>-<adapter-name>            |   |   |
//  |   |   |                (one for every VIF)                 |   |   |
//  |   |   |                                                    |   |   |
//  |   |   |       +---------------+   +---------------+        |   |   |
//  |   |   |       |      VIF      |   |   VLANPort    |        |   |   |
//  |   |   |       |   (external)  |   |  (for L2 NI)  |        |   |   |
//  |   |   |       +---------------+   +---------------+        |   |   |
//  |   |   |                                                    |   |   |
//  |   |   |                    +----------+                    |   |   |
//  |   |   |                    |  IPSet   |                    |   |   |
//  |   |   |                    |  (eids)  |                    |   |   |
//  |   |   |                    +----------+                    |   |   |
//  |   |   |                                                    |   |   |
//  |   |   |   +--------------------------------------------+   |   |   |
//  |   |   |   |                   ACLs                     |   |   |   |
//  |   |   |   |                                            |   |   |   |
//  |   |   |   |   +------------------------------------+   |   |   |   |
//  |   |   |   |   |             IPv4Rules              |   |   |   |   |
//  |   |   |   |   |                                    |   |   |   |   |
//  |   |   |   |   |       +----------------+           |   |   |   |   |
//  |   |   |   |   |       |  IptablesChain | ...       |   |   |   |   |
//  |   |   |   |   |       +----------------+           |   |   |   |   |
//  |   |   |   |   |      +------------------+          |   |   |   |   |
//  |   |   |   |   |      |   IptablesRule   | ...      |   |   |   |   |
//  |   |   |   |   |      +------------------+          |   |   |   |   |
//  |   |   |   |   +------------------------------------+   |   |   |   |
//  |   |   |   |                                            |   |   |   |
//  |   |   |   |   +------------------------------------+   |   |   |   |
//  |   |   |   |   |             IPv6Rules              |   |   |   |   |
//  |   |   |   |   |                                    |   |   |   |   |
//  |   |   |   |   |       +----------------+           |   |   |   |   |
//  |   |   |   |   |       |  IptablesChain | ...       |   |   |   |   |
//  |   |   |   |   |       +----------------+           |   |   |   |   |
//  |   |   |   |   |      +------------------+          |   |   |   |   |
//  |   |   |   |   |      |   IptablesRule   | ...      |   |   |   |   |
//  |   |   |   |   |      +------------------+          |   |   |   |   |
//  |   |   |   |   +------------------------------------+   |   |   |   |
//  |   |   |   +--------------------------------------------+   |   |   |
//  |   |   +----------------------------------------------------+   |   |
//  |   +------------------------------------------------------------+   |
//  +--------------------------------------------------------------------+

const (
	// GraphName : name of the graph with the managed state as a whole.
	GraphName = "ApplicationConnectivity"
	// GlobalSG : name of the sub-graph with the global configuration.
	GlobalSG = "Global"
	// UplinksSG : name of the sub-graph with (external) uplink interfaces.
	UplinksSG = "Uplinks"
	// IPSetsSG : subgraph with ipsets combined from all NIs.
	IPSetsSG = "IPSets"
	// BlackHoleSG : subgraph with config items creating a "black-hole" where traffic marked
	// by ACLs with the DROP action is routed to.
	BlackHoleSG = "BlackHole"
	// ACLRootChainsSG : subgraph listing iptables chains externally created by NIM
	// for application ACLs. From there, the traffic is guided further into
	// VIF-specific chains (based on input/output interfaces, etc.).
	ACLRootChainsSG = "ACLRootChains"
	// IPv4ChainsSG : subgraph with iptables chains for IPv4 traffic.
	// Used under ACLRootChains.
	IPv4ChainsSG = "IPv4Chains"
	// IPv6ChainsSG : subgraph with ip6tables chains for IPv6 traffic.
	// Used under ACLRootChains.
	IPv6ChainsSG = "IPv6Chains"
	// NISGPrefix : prefix used for name of the subgraph encapsulating the entire
	// configuration of the given network instance.
	NISGPrefix = "NI-"
	// L2SG : subgraph with configuration items for a given NI related to Layer2
	// of the ISO/OSI model.
	L2SG = "L2"
	// L3SG : subgraph with configuration items for a given NI related to Layer3
	// of the ISO/OSI model.
	L3SG = "L3"
	// NIServicesSG : subgraph with items belonging to a given NI that collectively
	// provide various services for connected applications, such as DHCP, DNS, cloud-init
	// metadata, etc.
	NIServicesSG = "Services"
	// AppConnACLsSG : subgraph with iptables chain and rules implementing ACLs
	// for a given application VIF (connection from app to NI).
	AppConnACLsSG = "ACLs"
	// IPv4RulesSG : subgraph with iptables rules (and some chains) implementing
	// IPv4 ACLs for a given application VIF.
	IPv4RulesSG = "IPv4Rules"
	// IPv6RulesSG : subgraph with ip6tables rules (and some chains) implementing
	// IPv6 ACLs for a given application VIF.
	IPv6RulesSG = "IPv6Rules"
)

const (
	// IPSetNameLenLimit : Netfilter limits IP set name to contain at most 31 characters.
	IPSetNameLenLimit = 31
	ipsetNamePrefixV4 = "ipv4."
	ipsetNamePrefixV6 = "ipv6."
	localIPv4Ipset    = ipsetNamePrefixV4 + "local"
	localIPv6Ipset    = ipsetNamePrefixV6 + "local"
)

const (
	blackholeIfName = "blackhole" // dummy interface for dropping traffic
	blackholeRT     = 400         // below DPCBaseRTIndex and NIBaseRTIndex
	blackholePrio   = 1000        // higher priority than any other ipRule
)

const (
	vifIfNamePrefix    = "nbu"
	bridgeIfNamePrefix = "bn"
)

const (
	metadataSrvIP = "169.254.169.254"
)

// NIToSGName returns the name of the subgraph encapsulating the entire configuration
// of the given network instance.
// There is one such subgraph for every network instance.
func NIToSGName(niID uuid.UUID) string {
	return NISGPrefix + niID.String()
}

// SGNameToNI is the inverse of NIToSGName.
func SGNameToNI(sg string) uuid.UUID {
	if !strings.HasPrefix(sg, NISGPrefix) {
		return emptyUUID
	}
	niID, err := uuid.FromString(strings.TrimPrefix(sg, NISGPrefix))
	if err != nil {
		return emptyUUID
	}
	return niID
}

// AppConnSGName : name of the subgraph containing items that collectively build
// a connection (VIF + ACLs + some other things) from an application to a network
// instance.
// It is a subgraph of the "NI-<niID>" graph where the app connection goes to.
func AppConnSGName(appID uuid.UUID, netAdapterName string) string {
	return "AppConn-" + appID.String() + "-" + netAdapterName
}

func uplinkPhysIfName(bridgeName string) string {
	return "k" + bridgeName
}

// Ipset with all the addresses from the DnsNameToIPList plus the VIF IP itself.
func eidsIpsetName(vif vifInfo, ipv6 bool) string {
	if ipv6 {
		return ipsetNamePrefixV6 + "eids." + vif.hostIfName
	}
	return ipsetNamePrefixV4 + "eids." + vif.hostIfName
}

func (r *LinuxNIReconciler) initialDepGraph() dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        GraphName,
		Description: "Application Connectivity provided using Linux network stack",
	}
	return dg.New(graphArgs)
}

func (r *LinuxNIReconciler) getIntendedGlobalState() dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        GlobalSG,
		Description: "Global configuration",
	}
	intendedCfg := dg.New(graphArgs)
	intendedCfg.PutSubGraph(r.getIntendedUplinks())
	intendedCfg.PutSubGraph(r.getIntendedGlobalIPSets())
	intendedCfg.PutSubGraph(r.getIntendedBlackholeCfg())
	intendedCfg.PutSubGraph(r.getIntendedACLRootChains())
	return intendedCfg
}

func (r *LinuxNIReconciler) getIntendedUplinks() dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        UplinksSG,
		Description: "Uplink interfaces used by network instances",
	}
	intendedUplinks := dg.New(graphArgs)
	for _, ni := range r.nis {
		if ni.deleted {
			continue
		}
		if ni.bridge.Uplink.IfName == "" {
			// Air-gapped NI, no uplink.
			continue
		}
		var uplinkIfName, masterIfName string
		switch ni.config.Type {
		case types.NetworkInstanceTypeSwitch:
			uplinkIfName = uplinkPhysIfName(ni.bridge.Uplink.IfName)
			masterIfName = ni.bridge.Uplink.IfName
		case types.NetworkInstanceTypeLocal:
			// Local NI will have its own bridge and even if uplink refers to a bridge
			// it will be used just as if it was a physical interface.
			uplinkIfName = ni.bridge.Uplink.IfName
		}
		intendedUplinks.PutItem(generic.Uplink{
			IfName:       uplinkIfName,
			LogicalLabel: ni.bridge.Uplink.LogicalLabel,
			MasterIfName: masterIfName,
			AdminUp:      true,
		}, nil)
	}
	return intendedUplinks
}

func (r *LinuxNIReconciler) getIntendedGlobalIPSets() dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        IPSetsSG,
		Description: "IPSets used by all/multiple network instances",
	}
	intendedIPSets := dg.New(graphArgs)
	intendedIPSets.PutItem(linux.IPSet{
		SetName:    localIPv4Ipset,
		TypeName:   "hash:net",
		Entries:    []string{"224.0.0.0/4", "0.0.0.0", "255.255.255.255"},
		AddrFamily: netlink.FAMILY_V4,
	}, nil)
	intendedIPSets.PutItem(linux.IPSet{
		SetName:    localIPv6Ipset,
		TypeName:   "hash:net",
		Entries:    []string{"fe80::/10", "ff02::/16"},
		AddrFamily: netlink.FAMILY_V6,
	}, nil)
	// Collect all hostnames referenced by any ACLs across all VIFs.
	// A given hostname will have one ipset used by all dnsmasq instances,
	// meaning that resolved IP addresses will be merged from across all apps
	// and used collectively for traffic matching.
	hostIPSets := make(map[string]struct{})
	for _, app := range r.apps {
		if app.deleted {
			continue
		}
		for _, adapter := range app.config.UnderlayNetworkList {
			for _, ace := range adapter.ACLs {
				for _, match := range ace.Matches {
					if match.Type == "host" {
						hostIPSets[match.Value] = struct{}{}
					}
				}
			}
		}
	}
	for hostIPSet := range hostIPSets {
		ipsetBasename := HostIPSetBasename(hostIPSet)
		intendedIPSets.PutItem(linux.IPSet{
			SetName:    ipsetNamePrefixV4 + ipsetBasename,
			TypeName:   "hash:ip",
			AddrFamily: netlink.FAMILY_V4,
		}, nil)
		intendedIPSets.PutItem(linux.IPSet{
			SetName:    ipsetNamePrefixV6 + ipsetBasename,
			TypeName:   "hash:ip",
			AddrFamily: netlink.FAMILY_V6,
		}, nil)
	}
	return intendedIPSets
}

func (r *LinuxNIReconciler) getIntendedBlackholeCfg() dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        BlackHoleSG,
		Description: "A place in the network where traffic matched by DROP ACLs is discarded",
	}
	intendedBlackholeCfg := dg.New(graphArgs)
	intendedBlackholeCfg.PutItem(linux.DummyIf{
		IfName: blackholeIfName,
		ARPOff: true,
	}, nil)
	intendedBlackholeCfg.PutItem(linux.Route{
		// ip route add default dev blackhole scope global table 400
		Route: netlink.Route{
			Table:    blackholeRT,
			Family:   netlink.FAMILY_V4,
			Scope:    netlink.SCOPE_UNIVERSE,
			Protocol: unix.RTPROT_STATIC,
		},
		OutputIf: linux.RouteOutIf{
			DummyIfName: blackholeIfName,
		},
	}, nil)
	intendedBlackholeCfg.PutItem(linux.Route{
		// ip -6 route add default dev blackhole scope global table 400
		Route: netlink.Route{
			Table:    blackholeRT,
			Family:   netlink.FAMILY_V6,
			Scope:    netlink.SCOPE_UNIVERSE,
			Protocol: unix.RTPROT_STATIC,
		},
		OutputIf: linux.RouteOutIf{
			DummyIfName: blackholeIfName,
		},
	}, nil)
	//intendedBlackholeCfg.PutItem(linux.IPRule{
	//	Priority: blackholePrio,
	//	Table:    blackholeRT,
	//	Mark:     iptables.AceDropAction,
	//	Mask:     iptables.AceDropAction,
	//}, nil)
	// Install iptables rule to ensure that packets marked with the drop action
	// are indeed dropped and never sent out via downlink or uplink interfaces.
	// Whereas routed packets marked by drop ACEs are blackholed into the dummy
	// interface using a high-priority IP rule, packets which are only bridged
	// and not routed by EVE escape this IP rule and would otherwise continue
	// in their path even if marked for dropping.
	dropMark := fmt.Sprintf("%d/%d", iptables.AceDropAction, iptables.AceActionMask)
	intendedBlackholeCfg.PutItem(iptables.Rule{
		RuleLabel: "Drop blackholed traffic",
		Table:     "mangle",
		ChainName: appChain("POSTROUTING"),
		MatchOpts: []string{"--match", "connmark", "--mark", dropMark,
			"!", "-o", blackholeIfName},
		Target: "DROP",
		Description: "Rule to ensure that packets marked with the drop action " +
			"are indeed dropped and never sent out via downlink or uplink interfaces",
	}, nil)
	return intendedBlackholeCfg
}

func (r *LinuxNIReconciler) getIntendedNICfg(niID uuid.UUID) dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        NIToSGName(niID),
		Description: "Network Instance configuration",
	}
	intendedCfg := dg.New(graphArgs)
	if r.nis[niID] == nil || r.nis[niID].deleted {
		return intendedCfg
	}
	intendedCfg.PutSubGraph(r.getIntendedNIL2Cfg(niID))
	intendedCfg.PutSubGraph(r.getIntendedNIL3Cfg(niID))
	intendedCfg.PutSubGraph(r.getIntendedNIServices(niID))
	for _, app := range r.apps {
		if app.deleted {
			continue
		}
		for i, vif := range app.vifs {
			if vif.NI != niID {
				continue
			}
			ul := app.config.UnderlayNetworkList[i]
			intendedCfg.PutSubGraph(r.getIntendedAppConnCfg(niID, vif, ul))
		}
	}
	return intendedCfg
}

func (r *LinuxNIReconciler) getIntendedNIL2Cfg(niID uuid.UUID) dg.Graph {
	ni := r.nis[niID]
	graphArgs := dg.InitArgs{
		Name:        L2SG,
		Description: "Layer 2 configuration for network instance",
	}
	intendedL2Cfg := dg.New(graphArgs)
	var bridgeIPs []*net.IPNet
	bridgeIP, _, bridgeMAC, _, _ := r.getBridgeAddrs(niID)
	if bridgeIP != nil {
		bridgeIPs = append(bridgeIPs, bridgeIP)
	}
	intendedL2Cfg.PutItem(linux.Bridge{
		IfName:       ni.brIfName,
		CreatedByNIM: r.niBridgeIsCreatedByNIM(ni),
		MACAddress:   bridgeMAC,
		IPAddresses:  bridgeIPs,
	}, nil)
	// For Switch NI also add the intended VLAN configuration.
	// Here we put VLAN config only for the bridge itself and the uplink interface,
	// downlinks have their config in AppConn-* subgraphs.
	if ni.config.Type != types.NetworkInstanceTypeSwitch {
		return intendedL2Cfg
	}
	intendedL2Cfg.PutItem(linux.VLANBridge{
		BridgeIfName:        ni.brIfName,
		EnableVLANFiltering: true,
	}, nil)
	if ni.bridge.Uplink.IfName == "" {
		// Air-gapped, no uplink port to configure as trunk.
		return intendedL2Cfg
	}
	// Find out which VLAN IDs should be allowed for the uplink trunk port.
	var trunkPort linux.TrunkPort
	for _, app := range r.apps {
		if app.deleted {
			continue
		}
		for _, ul := range app.config.UnderlayNetworkList {
			if ul.Network != niID {
				continue
			}
			vid := uint16(ul.AccessVlanID)
			if vid <= 1 {
				// There is VIF used as a trunk port.
				// Enable all valid VIDs.
				trunkPort.VIDs = nil
				trunkPort.AllVIDs = true
				break
			} else {
				var duplicate bool
				for _, prevVID := range trunkPort.VIDs {
					if prevVID == vid {
						duplicate = true
						break
					}
				}
				if !duplicate {
					trunkPort.VIDs = append(trunkPort.VIDs, vid)
				}
			}
		}
		if trunkPort.AllVIDs {
			break
		}
	}
	intendedL2Cfg.PutItem(linux.VLANPort{
		BridgeIfName: ni.brIfName,
		BridgePort: linux.BridgePort{
			UplinkIfName: uplinkPhysIfName(ni.bridge.Uplink.IfName),
		},
		VLANConfig: linux.VLANConfig{
			TrunkPort: &trunkPort,
		},
	}, nil)
	return intendedL2Cfg
}

func (r *LinuxNIReconciler) getIntendedNIL3Cfg(niID uuid.UUID) dg.Graph {
	ni := r.nis[niID]
	graphArgs := dg.InitArgs{
		Name:        L3SG,
		Description: "Layer 3 configuration for network instance",
	}
	intendedL3Cfg := dg.New(graphArgs)
	if !r.niBridgeIsCreatedByNIM(ni) {
		if bridgeIP, _, _, _, _ := r.getBridgeAddrs(niID); bridgeIP != nil {
			intendedL3Cfg.PutItem(generic.IPReserve{
				AddrWithMask: bridgeIP,
				NetIf: generic.NetworkIf{
					IfName:  ni.brIfName,
					ItemRef: dg.Reference(linux.Bridge{IfName: ni.brIfName}),
				},
			}, nil)
		}
	}
	if ni.config.Type == types.NetworkInstanceTypeSwitch {
		// No more L3 config for switch network instance.
		return intendedL3Cfg
	}
	if r.getNISubnet(ni) == nil {
		// Local network instance with undefined subnet.
		// (should be unreachable)
		return intendedL3Cfg
	}
	// Copy routes relevant for this NI from the main routing table into per-NI RT.
	srcTable := unix.RT_TABLE_MAIN
	dstTable := devicenetwork.NIBaseRTIndex + ni.bridge.BrNum
	outIfs := make(map[int]linux.RouteOutIf) // key: ifIndex
	ifIndex, found, err := r.netMonitor.GetInterfaceIndex(ni.brIfName)
	if err != nil {
		r.log.Errorf("%s: getIntendedNIL3Cfg: failed to get ifIndex "+
			"for (NI bridge) %s: %v", LogAndErrPrefix, ni.brIfName, err)
	}
	if err == nil && found {
		outIfs[ifIndex] = linux.RouteOutIf{BridgeIfName: ni.brIfName}
	}
	uplink := ni.bridge.Uplink.IfName
	if uplink != "" {
		ifIndex, found, err := r.netMonitor.GetInterfaceIndex(uplink)
		if err != nil {
			r.log.Errorf("%s: getIntendedNIL3Cfg: failed to get ifIndex "+
				"for (NI uplink) %s: %v", LogAndErrPrefix, uplink, err)
		}
		if err == nil && found {
			outIfs[ifIndex] = linux.RouteOutIf{UplinkIfName: uplink}
		}
	}
	for outIfIndex, rtOutIf := range outIfs {
		routes, err := r.netMonitor.ListRoutes(netmonitor.RouteFilters{
			FilterByTable: true,
			Table:         srcTable,
			FilterByIf:    true,
			IfIndex:       outIfIndex,
		})
		if err != nil {
			r.log.Errorf("%s: getIntendedNIL3Cfg: ListRoutes failed for ifIndex %d: %v",
				LogAndErrPrefix, outIfIndex, err)
			continue
		}
		// Copy routes from the main table into the NI-specific table.
		for _, rt := range routes {
			rtCopy := rt.Data.(netlink.Route)
			rtCopy.Table = dstTable
			// Multiple IPv6 link-locals can't be added to the same
			// table unless the Priority differs.
			// Different LinkIndex, Src, Scope doesn't matter.
			if rt.Dst != nil && rt.Dst.IP.IsLinkLocalUnicast() {
				r.log.Tracef("Forcing IPv6 priority to %v", rtCopy.LinkIndex)
				// Hack to make the kernel routes not appear identical.
				rtCopy.Priority = rtCopy.LinkIndex
			}
			rtCopy.Protocol = unix.RTPROT_STATIC
			intendedL3Cfg.PutItem(linux.Route{
				Route:          rtCopy,
				OutputIf:       rtOutIf,
				GwViaLinkRoute: gwViaLinkRoute(rt, routes),
			}, nil)
		}
	}
	// Everything not matched by the routes above should be dropped.
	// Add unreachable route with the lowest possible priority.
	intendedL3Cfg.PutItem(linux.Route{
		Route: netlink.Route{
			Priority: int(^uint32(0)),
			Table:    dstTable,
			Family:   netlink.FAMILY_V4,
			Type:     unix.RTN_UNREACHABLE,
			Protocol: unix.RTPROT_STATIC,
		},
	}, nil)
	intendedL3Cfg.PutItem(linux.Route{
		Route: netlink.Route{
			Priority: int(^uint32(0)),
			Table:    dstTable,
			Family:   netlink.FAMILY_V6,
			Type:     unix.RTN_UNREACHABLE,
			Protocol: unix.RTPROT_STATIC,
		},
	}, nil)
	// Add IPRules to select routing table for traffic coming in or out to/from
	// the network instance.
	if _, bridgeIP, _, _, _ := r.getBridgeAddrs(niID); bridgeIP != nil {
		intendedL3Cfg.PutItem(linux.IPRule{
			Priority: devicenetwork.PbrNatOutGatewayPrio,
			Table:    syscall.RT_TABLE_LOCAL,
			Src:      r.getNISubnet(ni),
			Dst:      bridgeIP,
		}, nil)
	}
	intendedL3Cfg.PutItem(linux.IPRule{
		Priority: devicenetwork.PbrNatOutPrio,
		Table:    devicenetwork.NIBaseRTIndex + ni.bridge.BrNum,
		Src:      r.getNISubnet(ni),
	}, nil)
	intendedL3Cfg.PutItem(linux.IPRule{
		Priority: devicenetwork.PbrNatInPrio,
		Table:    devicenetwork.NIBaseRTIndex + ni.bridge.BrNum,
		Dst:      r.getNISubnet(ni),
	}, nil)
	// Add S-NAT iptables rule for the local network instance (only for IPv4).
	if ni.config.Subnet.IP.To4() != nil {
		if ni.config.Type == types.NetworkInstanceTypeLocal && uplink != "" {
			intendedL3Cfg.PutItem(iptables.Rule{
				RuleLabel: fmt.Sprintf("SNAT traffic from NI %s", ni.config.UUID),
				Table:     "nat",
				ChainName: appChain("POSTROUTING"),
				MatchOpts: []string{"-o", uplink, "-s", ni.config.Subnet.String()},
				Target:    "MASQUERADE",
				Description: fmt.Sprintf("NAT traffic from the local network instance %s "+
					"as it leaves node through the uplink %s", ni.config.DisplayName,
					ni.bridge.Uplink.LogicalLabel),
			}, nil)
		}
	}
	return intendedL3Cfg
}

func (r *LinuxNIReconciler) getIntendedNIServices(niID uuid.UUID) dg.Graph {
	graphArgs := dg.InitArgs{
		Name:        NIServicesSG,
		Description: "Network instance services (DHCP, DNS, app metadata, etc.)",
	}
	intendedServices := dg.New(graphArgs)
	for _, item := range r.getIntendedMetadataSrvCfg(niID) {
		intendedServices.PutItem(item, nil)
	}
	for _, item := range r.getIntendedDnsmasqCfg(niID) {
		intendedServices.PutItem(item, nil)
	}
	for _, item := range r.getIntendedRadvdCfg(niID) {
		intendedServices.PutItem(item, nil)
	}
	return intendedServices
}

func (r *LinuxNIReconciler) getIntendedMetadataSrvCfg(niID uuid.UUID) (items []dg.Item) {
	ni := r.nis[niID]
	_, bridgeIP, _, _, err := r.getBridgeAddrs(niID)
	if err != nil {
		r.log.Errorf("%s: getIntendedMetadataSrvCfg: getBridgeAddrs(%s) failed: %v",
			LogAndErrPrefix, niID, err)
		return nil
	}
	if bridgeIP == nil {
		// No IP address for the metadata server to listen on.
		return nil
	}
	srvAddr := fmt.Sprintf("%s:%d", bridgeIP.IP.String(), 80)
	if bridgeIP.IP.To4() != nil {
		items = append(items, iptables.Rule{
			RuleLabel: fmt.Sprintf("Redirection rule for metadata server of NI: %s",
				ni.config.UUID),
			Table:     "nat",
			ChainName: appChain("PREROUTING"),
			MatchOpts: []string{"-i", ni.brIfName, "-p", "tcp", "-d", metadataSrvIP + "/32",
				"--dport", "80"},
			Target:     "DNAT",
			TargetOpts: []string{"--to-destination", srvAddr},
			Description: fmt.Sprintf("Redirect traffic headed towards the metadata "+
				"service IP (%s) into the real IP address of the HTTP server (%s) "+
				"of the NI %v", metadataSrvIP, bridgeIP.IP, ni.config.DisplayName),
		})
	}
	if r.niBridgeIsCreatedByNIM(ni) {
		items = append(items, iptables.Rule{
			RuleLabel: fmt.Sprintf("Block access to metadata server from outside "+
				"for L2 NI %s", ni.config.UUID),
			Table:     "filter",
			ChainName: appChain("INPUT"),
			MatchOpts: []string{"-i", ni.brIfName, "-p", "tcp", "--dport", "80", "-m",
				"physdev", "--physdev-in", uplinkPhysIfName(ni.brIfName)},
			Target: "DROP",
			Description: fmt.Sprintf("Do not allow external endpoints to use switch "+
				"network instance to access the metadata server of NI %s",
				ni.config.DisplayName),
		})
	}
	items = append(items, generic.HTTPServer{
		ForNI:    niID,
		ListenIP: bridgeIP.IP,
		ListenIf: generic.NetworkIf{
			IfName:  ni.brIfName,
			ItemRef: dg.Reference(linux.Bridge{IfName: ni.brIfName}),
		},
		Port:    80,
		Handler: r.metadataHandler,
	})
	return items
}

func (r *LinuxNIReconciler) getIntendedDnsmasqCfg(niID uuid.UUID) (items []dg.Item) {
	ni := r.nis[niID]
	if ni.config.Type == types.NetworkInstanceTypeSwitch {
		// Not running DHCP and DNS servers inside EVE for Switch network instances.
		return
	}
	_, bridgeIP, _, _, err := r.getBridgeAddrs(niID)
	if err != nil {
		r.log.Errorf("%s: getIntendedDnsmasqCfg: getBridgeAddrs(%s) failed: %v",
			LogAndErrPrefix, niID, err)
		return nil
	}

	// DHCP server configuration
	// By default, dnsmasq advertises a router (and we can have a static router
	// defined in the NetworkInstanceConfig).
	// To support airgap networks we interpret gateway=0.0.0.0 to not advertise
	// ourselves as a router.
	var gateway net.IP
	if ni.bridge.Uplink.IfName != "" {
		if ni.config.Gateway != nil {
			if !ni.config.Gateway.IsUnspecified() {
				gateway = ni.config.Gateway
			} // else suppress router advertisement
		} else if bridgeIP != nil {
			gateway = bridgeIP.IP
		}
	} // else : Do not advertise router for air-gapped NI.
	var uplinkIf generic.NetworkIf
	if ni.bridge.Uplink.IfName != "" {
		uplinkIf = generic.NetworkIf{
			IfName:  ni.bridge.Uplink.IfName,
			ItemRef: dg.Reference(generic.Uplink{IfName: ni.bridge.Uplink.IfName}),
		}
	}
	// Combine NTP servers assigned to the uplink together with those statically
	// configured for the network instance.
	var ntpServers []net.IP
	ntpServers = append(ntpServers, ni.bridge.Uplink.NTPServers...)
	if ni.config.NtpServer != nil {
		ntpServers = append(ntpServers, ni.config.NtpServer)
	}
	ntpServers = generics.FilterDuplicatesFn(ntpServers, netutils.EqualIPs)
	dhcpCfg := generic.DHCPServer{
		Subnet:         r.getNISubnet(ni),
		AllOnesNetmask: !r.disableAllOnesNetmask,
		IPRange: generic.IPRange{
			FromIP: ni.config.DhcpRange.Start,
			ToIP:   ni.config.DhcpRange.End,
		},
		GatewayIP:  gateway,
		DomainName: ni.config.DomainName,
		DNSServers: ni.config.DnsServers,
		NTPServers: ntpServers,
	}
	// IPRange set above does not matter that much - every VIF is statically
	// assigned IP address using a host file.
	for _, app := range r.apps {
		if app.deleted {
			continue
		}
		for _, vif := range app.vifs {
			if vif.NI != niID {
				continue
			}
			if vif.GuestIP != nil {
				dhcpCfg.StaticEntries = append(dhcpCfg.StaticEntries,
					generic.MACToIP{
						MAC:      vif.GuestIfMAC,
						IP:       vif.GuestIP,
						Hostname: app.config.UUIDandVersion.UUID.String(),
					})
			}
		}
	}

	// DNS server configuration
	var listenIP net.IP
	if bridgeIP != nil {
		listenIP = bridgeIP.IP
	}
	dnsCfg := generic.DNSServer{
		ListenIP:        listenIP,
		UplinkIf:        uplinkIf,
		UpstreamServers: ni.bridge.Uplink.DNSServers,
	}
	for _, staticEntry := range ni.config.DnsNameToIPList {
		for _, ip := range staticEntry.IPs {
			dnsCfg.StaticEntries = append(dnsCfg.StaticEntries, generic.HostnameToIP{
				Hostname: staticEntry.HostName,
				IP:       ip,
			})
		}
	}
	if bridgeIP != nil {
		// XXX arbitrary name "router"!!
		dnsCfg.StaticEntries = append(dnsCfg.StaticEntries, generic.HostnameToIP{
			Hostname: "router",
			IP:       bridgeIP.IP,
		})
	}
	for _, app := range r.apps {
		if app.deleted {
			continue
		}
		for _, vif := range app.vifs {
			if vif.NI != niID {
				continue
			}
			if vif.GuestIP != nil {
				dnsCfg.StaticEntries = append(dnsCfg.StaticEntries,
					generic.HostnameToIP{
						Hostname: app.config.DisplayName,
						IP:       vif.GuestIP,
					})
			}
		}
	}
	// Note that with IPv4/IPv6 interfaces the domU can do DNS lookups on either
	// IPv4 and IPv6 on any interface, hence we should configure the ipsets
	// for all the domU's interfaces/bridges.
	hostIPSets := make(map[string]struct{})
	for _, app := range r.apps {
		if app.deleted {
			continue
		}
		var usesThisNI bool
		for _, vif := range app.vifs {
			if vif.NI == niID {
				usesThisNI = true
				break
			}
		}
		if !usesThisNI {
			continue
		}
		for _, adapter := range app.config.UnderlayNetworkList {
			for _, ace := range adapter.ACLs {
				for _, match := range ace.Matches {
					if match.Type == "host" {
						hostIPSets[match.Value] = struct{}{}
					}
				}
			}
		}
	}
	for hostname := range hostIPSets {
		ipsetBasename := HostIPSetBasename(hostname)
		dnsCfg.LinuxIPSets = append(dnsCfg.LinuxIPSets, generic.LinuxIPSet{
			Domains: []string{hostname},
			Sets: []string{
				ipsetNamePrefixV4 + ipsetBasename,
				ipsetNamePrefixV6 + ipsetBasename,
			},
		})
	}
	items = append(items, generic.Dnsmasq{
		ForNI: niID,
		ListenIf: generic.NetworkIf{
			IfName:  ni.brIfName,
			ItemRef: dg.Reference(linux.Bridge{IfName: ni.brIfName}),
		},
		DHCPServer: dhcpCfg,
		DNSServer:  dnsCfg,
	})
	return items
}

func (r *LinuxNIReconciler) getIntendedRadvdCfg(niID uuid.UUID) (items []dg.Item) {
	ni := r.nis[niID]
	if !ni.config.IsIPv6() {
		return nil
	}
	// XXX do we need same logic as for IPv4 dnsmasq to not advertise as default router?
	// Might we need lower radvd preference if isolated local network?
	items = append(items, generic.Radvd{
		ForNI: niID,
		ListenIf: generic.NetworkIf{
			IfName:  ni.brIfName,
			ItemRef: dg.Reference(linux.Bridge{IfName: ni.brIfName}),
		},
	})
	return items
}

func (r *LinuxNIReconciler) getIntendedAppConnCfg(niID uuid.UUID,
	vif vifInfo, ul types.UnderlayNetworkConfig) dg.Graph {
	ni := r.nis[vif.NI]
	graphArgs := dg.InitArgs{
		Name:        AppConnSGName(vif.App, vif.NetAdapterName),
		Description: "Connection between application and network instance",
	}
	intendedAppConnCfg := dg.New(graphArgs)
	intendedAppConnCfg.PutItem(generic.VIF{
		IfName:         vif.hostIfName,
		NetAdapterName: vif.NetAdapterName,
		MasterIfName:   ni.brIfName,
	}, nil)
	if ni.config.Type == types.NetworkInstanceTypeSwitch {
		var vlanConfig linux.VLANConfig
		if ul.AccessVlanID <= 1 {
			// Currently we do not allow to create application trunk port
			// with a subset of (not all) VLANs.
			vlanConfig.TrunkPort = &linux.TrunkPort{AllVIDs: true}
		} else {
			vlanConfig.AccessPort = &linux.AccessPort{VID: uint16(ul.AccessVlanID)}
		}
		intendedAppConnCfg.PutItem(linux.VLANPort{
			BridgeIfName: ni.brIfName,
			BridgePort: linux.BridgePort{
				VIFIfName: vif.hostIfName,
			},
			VLANConfig: vlanConfig,
		}, nil)
	}
	// Create ipset with all the addresses from the DnsNameToIPList plus the VIF IP itself.
	var ips []net.IP
	for _, staticEntry := range ni.config.DnsNameToIPList {
		for _, ip := range staticEntry.IPs {
			ips = append(ips, ip)
		}
	}
	if vif.GuestIP != nil {
		ips = append(ips, vif.GuestIP)
	}
	ips = generics.FilterDuplicatesFn(ips, netutils.EqualIPs)
	ipv4Eids := linux.IPSet{
		SetName:    eidsIpsetName(vif, false),
		TypeName:   "hash:ip",
		AddrFamily: netlink.FAMILY_V4,
	}
	ipv6Eids := linux.IPSet{
		SetName:    eidsIpsetName(vif, true),
		TypeName:   "hash:ip",
		AddrFamily: netlink.FAMILY_V6,
	}
	for _, ip := range ips {
		if ip.To4() == nil {
			ipv6Eids.Entries = append(ipv6Eids.Entries, ip.String())
		} else {
			ipv4Eids.Entries = append(ipv4Eids.Entries, ip.String())
		}
	}
	intendedAppConnCfg.PutItem(ipv4Eids, nil)
	intendedAppConnCfg.PutItem(ipv6Eids, nil)
	intendedAppConnCfg.PutSubGraph(r.getIntendedAppConnACLs(niID, vif, ul))
	return intendedAppConnCfg
}

func (r *LinuxNIReconciler) generateBridgeIfName(
	niConfig types.NetworkInstanceConfig, br NIBridge) (string, error) {
	var brIfName string
	switch niConfig.Type {
	case types.NetworkInstanceTypeSwitch:
		if br.Uplink.IfName != "" {
			brIfName = br.Uplink.IfName
			break
		}
		// Air-gapped, create bridge just like for local NI.
		fallthrough
	case types.NetworkInstanceTypeLocal:
		brIfName = fmt.Sprintf("%s%d", bridgeIfNamePrefix, br.BrNum)
	default:
		return "", fmt.Errorf("%s: Unsupported type %v for NI %v",
			LogAndErrPrefix, niConfig.Type, niConfig.UUID)
	}
	return brIfName, nil
}

func (r *LinuxNIReconciler) generateVifHostIfName(vifNum, appNum int) string {
	return fmt.Sprintf("%s%dx%d", vifIfNamePrefix, vifNum, appNum)
}

func (r *LinuxNIReconciler) niBridgeIsCreatedByNIM(ni *niInfo) bool {
	return ni.config.Type == types.NetworkInstanceTypeSwitch &&
		ni.bridge.Uplink.IfName != ""
}

func (r *LinuxNIReconciler) getNISubnet(ni *niInfo) *net.IPNet {
	if ni.config.Subnet.IP == nil {
		return nil
	}
	return &net.IPNet{
		IP:   ni.config.Subnet.IP,
		Mask: ni.config.Subnet.Mask,
	}
}

// gwViaLinkRoute returns true if the given route uses gateway routed by another
// link-scoped route.
func gwViaLinkRoute(route netmonitor.Route, routingTable []netmonitor.Route) bool {
	if len(route.Gw) == 0 {
		return false
	}
	gwHostSubnet := devicenetwork.HostSubnet(route.Gw)
	for _, route2 := range routingTable {
		netlinkRoute2 := route2.Data.(netlink.Route)
		if netlinkRoute2.Scope == netlink.SCOPE_LINK &&
			netutils.EqualIPNets(netlinkRoute2.Dst, gwHostSubnet) {
			return true
		}
	}
	return false
}

// HostIPSetBasename returns basename (without the "ipvX." prefix) to use for ipset
// matching a given domain name (ACE match of type "host").
// Needs to ensure that the ipset name doesn't exceed the length
// limit of 31 characters imposed by netfilter.
// Function is exported only for unit testing purposes.
func HostIPSetBasename(hostname string) string {
	maxLen := IPSetNameLenLimit - 5 // leave 5 characters for "ipvX."
	if len(hostname) <= maxLen {
		return hostname
	}
	const (
		// Minimum number of characters the hash should contain
		// to bring the probability of collision down to an acceptable level.
		hashMinLen = 8
		// Separator between a hostname suffix and a hash-generated prefix.
		sep = "#"
	)
	// Function tries to keep some suffix from the original host name
	// (to keep the ipset name human-readable and traceable to its source)
	// and replaces only the remaining subdomains with a hash value.
	labels := strings.Split(hostname, ".")
	var suffixLen, i int
	for i = len(labels); i > 0; i-- {
		if suffixLen+len(labels[i-1])+1+hashMinLen > maxLen {
			break
		}
		suffixLen += len(labels[i-1]) + 1
	}
	labels = labels[i:]
	suffix := strings.Join(labels, ".")
	// Prepend (very likely unique) prefix generated as a BASE64-encoded
	// hash calculated using SHA-256 from the full host name.
	h := sha256.New()
	h.Write([]byte(hostname))
	prefix := base64.URLEncoding.EncodeToString(h.Sum(nil))
	return prefix[:maxLen-1-len(suffix)] + sep + suffix
}
