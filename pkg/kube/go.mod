module eve-k3s

go 1.18

require (
	github.com/containernetworking/cni v1.1.2
	github.com/containernetworking/plugins v1.3.0
	github.com/vishvananda/netlink v1.2.1-beta.2
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
)

require (
	github.com/coreos/go-iptables v0.6.0 // indirect
	github.com/networkplumbing/go-nft v0.3.0 // indirect
	github.com/safchain/ethtool v0.3.0 // indirect
	github.com/stretchr/testify v1.8.2 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
)

replace github.com/lf-edge/eve/pkg/pillar => ../pillar
