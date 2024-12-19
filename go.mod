module github.com/isovalent/hubble-fgs

go 1.23.2

toolchain go1.23.3

require (
	github.com/aws/aws-sdk-go-v2 v1.32.5
	github.com/aws/aws-sdk-go-v2/config v1.28.5
	github.com/cilium/cilium v1.17.0-pre.3
	github.com/cilium/ebpf v0.16.1-0.20241212130635-98ede8ac7aa8
	github.com/cilium/lumberjack/v2 v2.4.1
	github.com/cilium/tetragon v0.0.0-00010101000000-000000000000
	github.com/cilium/tetragon/api v0.0.0-00010101000000-000000000000
	github.com/cilium/tetragon/pkg/k8s v0.0.0-20230821215247-e2d83592833f
	github.com/containerd/containerd/v2 v2.0.0
	github.com/containernetworking/plugins v1.6.0
	github.com/cri-o/cri-o v1.31.3
	github.com/docker/docker v27.3.1+incompatible
	github.com/dustin/go-humanize v1.0.1
	github.com/fatih/color v1.18.0
	github.com/gdamore/tcell/v2 v2.7.4
	github.com/go-logr/logr v1.4.2
	github.com/golang/protobuf v1.5.4
	github.com/google/cel-go v0.22.1
	github.com/google/go-cmp v0.6.0
	github.com/google/gops v0.3.28
	github.com/google/uuid v1.6.0
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/isovalent/hubble-fgs/pkg/k8s v0.0.0-00010101000000-000000000000
	github.com/isovalent/ipa v0.0.0-20241217215446-d534384d1da7
	github.com/mennanov/fieldmask-utils v1.1.2
	github.com/miekg/dns v1.1.62
	github.com/operator-framework/api v0.27.0
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.78.1
	github.com/prometheus/client_golang v1.20.5
	github.com/prometheus/client_model v0.6.1
	github.com/rivo/tview v0.0.0-20241103174730-c76f7879f592
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.8.1
	github.com/spf13/pflag v1.0.6-0.20210604193023-d5e0c0615ace
	github.com/spf13/viper v1.19.0
	github.com/sryoya/protorand v0.0.0-20240429201223-e7440656b2a4
	github.com/stretchr/testify v1.10.0
	github.com/vishvananda/netlink v1.3.1-0.20241022031324-976bd8de7d81
	github.com/vishvananda/netns v0.0.5
	github.com/xlab/treeprint v1.2.0
	github.com/yalue/native_endian v1.0.2
	go.opentelemetry.io/proto/otlp v1.3.1
	golang.org/x/net v0.33.0
	golang.org/x/sys v0.28.0
	golang.org/x/time v0.8.0
	google.golang.org/api v0.211.0
	google.golang.org/grpc v1.69.0
	google.golang.org/protobuf v1.35.2
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/api v0.32.0
	k8s.io/apiextensions-apiserver v0.32.0
	k8s.io/apimachinery v0.32.0
	k8s.io/client-go v0.32.0
	k8s.io/code-generator v0.32.0
	k8s.io/klog/v2 v2.130.1
	k8s.io/kube-openapi v0.0.0-20241105132330-32ad38e42d3f
	k8s.io/utils v0.0.0-20241104163129-6fe5fd82f078
	sigs.k8s.io/controller-runtime v0.19.3
	sigs.k8s.io/controller-tools v0.16.5
	sigs.k8s.io/e2e-framework v0.2.0
	sigs.k8s.io/yaml v1.4.0
)

require (
	cel.dev/expr v0.18.0 // indirect
	cloud.google.com/go/auth v0.12.1 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.6 // indirect
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20240806141605-e8a1dd7889d6 // indirect
	github.com/AdamKorcz/go-118-fuzz-build v0.0.0-20231105174938-2b5cbb29f3e2 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20230124172434-306776ec8161 // indirect
	github.com/Microsoft/hcsshim v0.12.9 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.46 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.20 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.24 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.24 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.24.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.28.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.1 // indirect
	github.com/aws/smithy-go v1.22.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/bombsimon/logrusr/v4 v4.1.0 // indirect
	github.com/cilium/dns v1.1.51-0.20240603182237-af788769786a // indirect
	github.com/cilium/hive v0.0.0-20241122120553-e90d0875ae01 // indirect
	github.com/cilium/proxy v0.0.0-20241115112946-fb67566cbd95 // indirect
	github.com/cilium/statedb v0.3.3 // indirect
	github.com/cilium/stream v0.0.0-20240816054136-71321e385273 // indirect
	github.com/cilium/tetragon-oss/pkg/k8s v0.0.0-00010101000000-000000000000 // indirect
	github.com/cncf/xds/go v0.0.0-20240905190251-b4127c9b8d78 // indirect
	github.com/containerd/cgroups/v3 v3.0.3 // indirect
	github.com/containerd/containerd/api v1.8.0 // indirect
	github.com/containerd/continuity v0.4.4 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/fifo v1.1.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/platforms v1.0.0-rc.0 // indirect
	github.com/containerd/plugin v1.0.0 // indirect
	github.com/containerd/ttrpc v1.2.6 // indirect
	github.com/containerd/typeurl/v2 v2.2.2 // indirect
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/coreos/go-systemd/v22 v22.5.1-0.20231103132048-7d375ecc2b09 // indirect
	github.com/deckarep/golang-set/v2 v2.7.0 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.1.0 // indirect
	github.com/evanphx/json-patch/v5 v5.9.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/gdamore/encoding v1.0.0 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/gnostic-models v0.6.9-0.20230804172637-c7be7c783f49 // indirect
	github.com/google/renameio/v2 v2.0.0 // indirect
	github.com/google/s2a-go v0.1.8 // indirect
	github.com/gopacket/gopacket v1.3.1 // indirect
	github.com/gorilla/websocket v1.5.1 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus v1.0.1 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.1.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.22.0 // indirect
	github.com/hashicorp/go-hclog v1.6.3 // indirect
	github.com/iancoleman/strcase v0.3.0 // indirect
	github.com/isovalent/metricstool v0.1.2 // indirect
	github.com/jpillora/longestcommon v0.0.0-20161227235612-adb9d91ee629 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/liggitt/tabwriter v0.0.0-20181228230101-89fcab3d43de // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mackerelio/go-osstat v0.2.5 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/patternmatcher v0.6.0 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/sequential v0.6.0 // indirect
	github.com/moby/sys/signal v0.7.1 // indirect
	github.com/moby/sys/user v0.3.0 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/mxk/go-flowrate v0.0.0-20140419014527-cca7078d478f // indirect
	github.com/opencontainers/runtime-spec v1.2.0 // indirect
	github.com/opencontainers/runtime-tools v0.9.1-0.20230914150019-408c51e934dc // indirect
	github.com/opencontainers/selinux v1.11.1 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/sagikazarmark/locafero v0.4.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/stoewer/go-strcase v1.3.0 // indirect
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.etcd.io/etcd/api/v3 v3.5.17 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.5.17 // indirect
	go.etcd.io/etcd/client/v3 v3.5.17 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.56.0 // indirect
	go.opentelemetry.io/otel v1.32.0 // indirect
	go.opentelemetry.io/otel/metric v1.32.0 // indirect
	go.opentelemetry.io/otel/trace v1.32.0 // indirect
	go.uber.org/dig v1.17.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/exp v0.0.0-20241004190924-225e2abe05e6 // indirect
	gomodules.xyz/jsonpatch/v2 v2.4.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20241118233622-e639e219e697 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241206012308-a4fef0638583 // indirect
	gopkg.in/evanphx/json-patch.v4 v4.12.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gotest.tools/v3 v3.5.1 // indirect
	k8s.io/apiserver v0.32.0 // indirect
	k8s.io/component-base v0.32.0 // indirect
	k8s.io/cri-api v0.31.2 // indirect
	k8s.io/gengo/v2 v2.0.0-20240911193312-2b36238f13e9 // indirect
	sigs.k8s.io/gateway-api v1.2.0 // indirect
	sigs.k8s.io/mcs-api v0.1.1-0.20241107131729-9615e3489a98 // indirect
	tags.cncf.io/container-device-interface v0.8.0 // indirect
	tags.cncf.io/container-device-interface/specs-go v0.8.0 // indirect
)

require (
	cloud.google.com/go/compute/metadata v0.5.2 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/containers/storage v1.55.1-0.20241015045236-02f1845caa18 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.5 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/docker/go-connections v0.5.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/emicklei/go-restful/v3 v3.12.1 // indirect
	github.com/fsnotify/fsnotify v1.8.0 // indirect
	github.com/go-openapi/analysis v0.23.0 // indirect
	github.com/go-openapi/errors v0.22.0 // indirect
	github.com/go-openapi/jsonpointer v0.21.0 // indirect
	github.com/go-openapi/jsonreference v0.21.0 // indirect
	github.com/go-openapi/loads v0.22.0 // indirect
	github.com/go-openapi/runtime v0.28.0 // indirect
	github.com/go-openapi/spec v0.21.0 // indirect
	github.com/go-openapi/strfmt v0.23.0
	github.com/go-openapi/swag v0.23.0 // indirect
	github.com/go-openapi/validate v0.24.0 // indirect
	github.com/gobuffalo/flect v1.0.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.4 // indirect
	github.com/googleapis/gax-go/v2 v2.14.0 // indirect
	github.com/hashicorp/hcl v1.0.1-vault-5 // indirect
	github.com/iceber/iouring-go v0.0.0-20230403020409-002cfd2e2a90
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/moby/spdystream v0.5.0 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0
	github.com/opentracing/opentracing-go v1.2.1-0.20220228012449-10b1cf09e00b // indirect
	github.com/pelletier/go-toml/v2 v2.2.3 // indirect
	github.com/petermattis/goid v0.0.0-20240813172612-4fcff4a6cae7 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/common v0.60.1
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sasha-s/go-deadlock v0.3.5 // indirect
	github.com/spf13/afero v1.11.0 // indirect
	github.com/spf13/cast v1.7.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/vladimirvivien/gexe v0.2.0 // indirect
	go.mongodb.org/mongo-driver v1.14.0 // indirect
	go.opencensus.io v0.24.0 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/mod v0.22.0 // indirect
	golang.org/x/oauth2 v0.24.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/term v0.27.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	golang.org/x/tools v0.27.0 // indirect
	google.golang.org/genproto v0.0.0-20241104194629-dd2ea8efbc28 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	sigs.k8s.io/json v0.0.0-20241010143419-9aa6b5e7a4b3 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.2 // indirect
)

replace (
	// use local submodule for OSS
	github.com/cilium/tetragon => ./modules/tetragon-oss

	// Access to the OSS pkg/k8s via this fake module
	github.com/cilium/tetragon-oss/pkg/k8s => ./modules/tetragon-oss/pkg/k8s

	// use local API
	github.com/cilium/tetragon/api => ./api
	github.com/cilium/tetragon/pkg/k8s => ./pkg/k8s
	github.com/cilium/tetragon/tests => ./modules/tetragon-oss/tests
	github.com/isovalent/hubble-fgs/pkg/k8s => ./pkg/k8s-enterprise

// due to CRI-O, otherwise it fails to build hubble-fgs
// TODO uncomment if replace directive below from cilium/cilium is removed
// and CRI-O still needs this.
// k8s.io/client-go => k8s.io/client-go v0.27.2
)

// This replace directive has to be in sync with with github.com/cilium/cilium
// except for sigs.k8s.io/controller-tools.  If the github.com/cilium/cilium
// version is bumped, the sync must be refreshed. As of now we use, see the
// replace directive:
// https://github.com/cilium/cilium/blob/cdf10116cea7a3babc493214b4ac856128734bcc/go.mod#L332-L338
replace go.universe.tf/metallb => github.com/cilium/metallb v0.1.1-0.20220829170633-5d7dfb1129f7
