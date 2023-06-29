module github.com/isovalent/hubble-fgs

go 1.18

require (
	github.com/cilium/cilium v1.13.4
	github.com/cilium/ebpf v0.10.0
	github.com/cilium/lumberjack/v2 v2.3.0
	github.com/cilium/tetragon v0.0.0-00010101000000-000000000000
	github.com/cilium/tetragon/api v0.0.0-00010101000000-000000000000
	github.com/cilium/tetragon/pkg/k8s v0.0.0-20230515182614-dcca3b1890e2
	github.com/containernetworking/plugins v1.2.0
	github.com/cri-o/cri-o v1.26.3
	github.com/docker/docker v24.0.2+incompatible
	github.com/dustin/go-humanize v1.0.1
	github.com/fatih/color v1.15.0
	github.com/google/gops v0.3.27
	github.com/google/uuid v1.3.0
	github.com/hashicorp/golang-lru/v2 v2.0.4
	github.com/mennanov/fieldmask-utils v1.0.0
	github.com/miekg/dns v1.1.43
	github.com/prometheus/client_golang v1.16.0
	github.com/prometheus/client_model v0.4.0
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.7.0
	github.com/spf13/viper v1.16.0
	github.com/stretchr/testify v1.8.4
	github.com/vishvananda/netlink v1.2.1-beta.2.0.20220608195807-1a118fe229fc
	github.com/vishvananda/netns v0.0.4
	github.com/yalue/native_endian v1.0.2
	go.uber.org/multierr v1.9.0
	golang.org/x/net v0.10.0
	golang.org/x/sys v0.9.0
	golang.org/x/time v0.3.0
	google.golang.org/api v0.128.0
	google.golang.org/grpc v1.56.1
	google.golang.org/protobuf v1.31.0
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.26.6
	k8s.io/apiextensions-apiserver v0.26.6
	k8s.io/client-go v1.5.2
	k8s.io/code-generator v0.26.6
	k8s.io/klog/v2 v2.100.1
	k8s.io/utils v0.0.0-20230220204549-a5ecb0141aa5
	sigs.k8s.io/controller-tools v0.12.0
	sigs.k8s.io/e2e-framework v0.0.8
	sigs.k8s.io/yaml v1.3.0
)

require (
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20230106234847-43070de90fa1 // indirect
	github.com/AdamKorcz/go-118-fuzz-build v0.0.0-20221215162035-5330a85ea652 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20210617225240-d185dfc1b5a1 // indirect
	github.com/Microsoft/hcsshim v0.10.0-rc.8 // indirect
	github.com/armon/go-metrics v0.4.0 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/containerd/cgroups v1.1.0 // indirect
	github.com/containerd/continuity v0.4.1 // indirect
	github.com/containerd/fifo v1.1.0 // indirect
	github.com/containerd/ttrpc v1.2.2 // indirect
	github.com/containerd/typeurl/v2 v2.1.1 // indirect
	github.com/coreos/go-semver v0.3.0 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/cyphar/filepath-securejoin v0.2.3 // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/evanphx/json-patch/v5 v5.6.0 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/s2a-go v0.1.4 // indirect
	github.com/hashicorp/consul/api v1.20.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-hclog v1.2.0 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/hashicorp/serf v0.10.1 // indirect
	github.com/klauspost/compress v1.16.4 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/patternmatcher v0.5.0 // indirect
	github.com/moby/sys/mountinfo v0.6.2 // indirect
	github.com/moby/sys/sequential v0.5.0 // indirect
	github.com/moby/sys/signal v0.7.0 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/runc v1.1.5 // indirect
	github.com/opencontainers/runtime-spec v1.1.0-rc.3 // indirect
	github.com/opencontainers/selinux v1.11.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/rogpeppe/go-internal v1.9.0 // indirect
	github.com/shirou/gopsutil/v3 v3.23.1 // indirect
	github.com/tklauser/go-sysconf v0.3.11 // indirect
	github.com/tklauser/numcpus v0.6.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	go.etcd.io/etcd/api/v3 v3.6.0-alpha.0 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.6.0-alpha.0 // indirect
	go.etcd.io/etcd/client/v3 v3.6.0-alpha.0 // indirect
	go.opentelemetry.io/otel v1.14.0 // indirect
	go.opentelemetry.io/otel/trace v1.14.0 // indirect
	go.uber.org/zap v1.23.0 // indirect
	golang.org/x/exp v0.0.0-20221106115401-f9659909a136 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20230530153820-e85fd2cbaebc // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230530153820-e85fd2cbaebc // indirect
)

require (
	cloud.google.com/go/compute v1.19.3 // indirect
	cloud.google.com/go/compute/metadata v0.2.3 // indirect
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/containerd/containerd v1.7.2
	github.com/containers/storage v1.46.1 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/docker/distribution v2.8.2+incompatible // indirect
	github.com/docker/go-connections v0.4.1-0.20210727194412-58542c764a11 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/emicklei/go-restful/v3 v3.10.1 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-openapi/analysis v0.21.4 // indirect
	github.com/go-openapi/errors v0.20.3 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.20.0 // indirect
	github.com/go-openapi/loads v0.21.2 // indirect
	github.com/go-openapi/runtime v0.25.0 // indirect
	github.com/go-openapi/spec v0.20.7 // indirect
	github.com/go-openapi/strfmt v0.21.7 // indirect
	github.com/go-openapi/swag v0.22.3 // indirect
	github.com/go-openapi/validate v0.22.0 // indirect
	github.com/gobuffalo/flect v0.2.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/gnostic v0.5.7-v3refs // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.4 // indirect
	github.com/googleapis/gax-go/v2 v2.10.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/imdario/mergo v0.3.15 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/mennanov/fmutils v0.2.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/moby/spdystream v0.2.0 // indirect
	github.com/moby/term v0.0.0-20221205130635-1aeaba878587 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0-rc2.0.20221005185240-3a7f492d3f1b
	github.com/opentracing/opentracing-go v1.2.1-0.20220228012449-10b1cf09e00b // indirect
	github.com/pelletier/go-toml/v2 v2.0.8 // indirect
	github.com/petermattis/goid v0.0.0-20180202154549-b0b1615b78e5 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/common v0.42.0 // indirect
	github.com/prometheus/procfs v0.10.1 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sasha-s/go-deadlock v0.3.1 // indirect
	github.com/spf13/afero v1.9.5 // indirect
	github.com/spf13/cast v1.5.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.4.2 // indirect
	github.com/vladimirvivien/gexe v0.1.1 // indirect
	go.mongodb.org/mongo-driver v1.11.3 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/crypto v0.9.0 // indirect
	golang.org/x/mod v0.9.0 // indirect
	golang.org/x/oauth2 v0.8.0 // indirect
	golang.org/x/sync v0.3.0 // indirect
	golang.org/x/term v0.8.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	golang.org/x/tools v0.7.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20230530153820-e85fd2cbaebc // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gotest.tools/v3 v3.0.3 // indirect
	k8s.io/apimachinery v0.26.6 // indirect
	k8s.io/gengo v0.0.0-20220902162205-c0856e24416d // indirect
	k8s.io/kube-openapi v0.0.0-20221012153701-172d655c2280 // indirect
	sigs.k8s.io/controller-runtime v0.13.1-0.20221201045826-d9912251cd81 // indirect
	sigs.k8s.io/json v0.0.0-20220713155537-f223a00ba0e2 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
)

// has to be in sync with both cilium and hubble overrides (mostly cilium).
replace (
	// use local submodule for OSS
	github.com/cilium/tetragon => ./modules/tetragon-oss

	// use local API
	github.com/cilium/tetragon/api => ./api
	github.com/cilium/tetragon/pkg/k8s => ./pkg/k8s
	github.com/cilium/tetragon/tests => ./modules/tetragon-oss/tests
	github.com/isovalent/hubble-fgs/pkg/k8s => ./pkg/k8s-enterprise

	github.com/miekg/dns => github.com/cilium/dns v1.1.4-0.20190417235132-8e25ec9a0ff3
	github.com/optiopay/kafka => github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b
	github.com/vishvananda/netlink => github.com/kevsecurity/netlink v1.2.1-beta.2-clsact

	// Use a fork of lumberjack with patches to ensure compressed logs are created atomically
	gopkg.in/natefinch/lumberjack.v2 => github.com/chancez/lumberjack v0.0.0-20220314160755-2b78c6a5f7bc

	// due to CRI-O, otherwise it fails to build hubble-fgs
	k8s.io/client-go => k8s.io/client-go v0.26.4

	// Using private fork of controller-tools. See commit msg for more context
	// as to why we are using a private fork.
	sigs.k8s.io/controller-tools => github.com/christarazi/controller-tools v0.3.1-0.20200911184030-7e668c1fb4c2
	// Pull in support for helm uninstall. TODO: remove this when 0.0.8 comes out.
	sigs.k8s.io/e2e-framework => github.com/kubernetes-sigs/e2e-framework v0.0.0-20220527132303-bc7888d1b4f0
)
