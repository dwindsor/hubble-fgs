module github.com/isovalent/hubble-fgs

go 1.16

require (
	github.com/blang/semver v3.5.0+incompatible
	github.com/cilium/cilium v1.7.0-rc2.0.20200311180626-711b37ed100c
	github.com/cilium/hubble v0.5.1
	github.com/ckaznocha/protoc-gen-lint v0.2.1
	github.com/fatih/color v1.7.0
	github.com/google/go-cmp v0.5.6
	github.com/google/gops v0.3.14
	github.com/hashicorp/golang-lru v0.5.4
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51
	github.com/mitchellh/protoc-gen-go-json v1.1.0
	github.com/prometheus/client_golang v1.5.1
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v1.0.0
	github.com/spf13/viper v1.6.1
	github.com/stretchr/testify v1.6.1
	github.com/vishvananda/netlink v1.1.1-0.20200210222539-bfba8e4149db
	github.com/yalue/native_endian v1.0.1
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e
	golang.org/x/sys v0.0.0-20201231184435-2d18734c6014
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4
	google.golang.org/api v0.4.0
	google.golang.org/grpc v1.29.1
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v0.0.0-20200723160120-cee815dbe38c
	google.golang.org/protobuf v1.27.1
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.18.4
	k8s.io/apiextensions-apiserver v0.18.4
	k8s.io/apimachinery v0.18.4
	k8s.io/client-go v0.18.4
	k8s.io/code-generator v0.18.4
	sigs.k8s.io/controller-tools v0.4.1
	sigs.k8s.io/yaml v1.2.0
)

// has to be in sync with both cilium and hubble overrides (mostly cilium).
replace (
	github.com/miekg/dns => github.com/cilium/dns v1.1.4-0.20190417235132-8e25ec9a0ff3
	github.com/optiopay/kafka => github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b
	github.com/vishvananda/netlink => github.com/jrfastab/netlink v1.1.1
	k8s.io/client-go => github.com/cilium/client-go v0.0.0-20200525133704-d13039a12d08

	// Using private fork of controller-tools. See commit msg for more context
	// as to why we are using a private fork.
	sigs.k8s.io/controller-tools => github.com/christarazi/controller-tools v0.3.1-0.20200911184030-7e668c1fb4c2
)
