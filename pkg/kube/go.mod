module eve-k3s

go 1.18

require (
	github.com/containernetworking/cni v1.1.2
	github.com/containernetworking/plugins v1.3.0
	github.com/lf-edge/eve/pkg/pillar v0.0.0-20231120194851-9c194dd01514
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
)

require (
	github.com/coreos/go-iptables v0.6.0 // indirect
	github.com/eriknordmark/ipinfo v0.0.0-20230728132417-2d8f4da903d7 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/go-containerregistry v0.8.0 // indirect
	github.com/lf-edge/eve-api/go v0.0.0-20231128234947-651fbc05785b // indirect
	github.com/safchain/ethtool v0.3.0 // indirect
	github.com/satori/go.uuid v1.2.1-0.20181028125025-b2ce2384e17b // indirect
	github.com/shirou/gopsutil v3.21.11+incompatible // indirect
	github.com/sirupsen/logrus v1.9.0 // indirect
	github.com/vishvananda/netlink v1.2.1-beta.2 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
)

replace github.com/lf-edge/eve/pkg/pillar => ../pillar
