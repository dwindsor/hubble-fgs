module github.com/covalentio/hubble-fgs

go 1.14

require (
	github.com/cilium/cilium v1.7.0-rc2.0.20200311180626-711b37ed100c
	github.com/cilium/hubble v0.5.1
	github.com/ckaznocha/protoc-gen-lint v0.2.1
	github.com/envoyproxy/protoc-gen-validate v0.4.0
	github.com/fsnotify/fsnotify v1.4.10-0.20200417215612-7f4cf4dd2b52 // indirect
	github.com/golang/protobuf v1.3.2
	github.com/google/go-cmp v0.5.2 // indirect
	github.com/google/gops v0.3.14
	github.com/hashicorp/golang-lru v0.5.4
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51
	github.com/mitchellh/protoc-gen-go-json v0.0.0-20200414201540-069933b8c834
	github.com/pelletier/go-toml v1.8.0 // indirect
	github.com/prometheus/client_golang v1.5.1
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v1.0.0
	github.com/spf13/viper v1.6.1
	github.com/stretchr/testify v1.5.1
	github.com/vishvananda/netlink v1.1.1-0.20200210222539-bfba8e4149db
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e
	golang.org/x/sys v0.0.0-20201207223542-d4d67f95c62d
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e // indirect
	google.golang.org/grpc v1.26.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	k8s.io/api v0.18.4
	k8s.io/apimachinery v0.18.8
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/utils v0.0.0-20200619165400-6e3d28b6ed19 // indirect
)

// has to be in sync with both cilium and hubble overrides (mostly cilium).
replace (
	github.com/miekg/dns => github.com/cilium/dns v1.1.4-0.20190417235132-8e25ec9a0ff3
	github.com/optiopay/kafka => github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b
	github.com/vishvananda/netlink => github.com/jrfastab/netlink v1.1.1
	k8s.io/client-go => github.com/cilium/client-go v0.0.0-20200525133704-d13039a12d08
)
