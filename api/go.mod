module github.com/isovalent/hubble-fgs/api

go 1.24.0

replace (
	github.com/cilium/tetragon => ../modules/tetragon-oss
	github.com/cilium/tetragon-oss/pkg/k8s => ../modules/tetragon-oss/pkg/k8s
	github.com/cilium/tetragon/api => ../modules/tetragon-oss/api
	github.com/cilium/tetragon/pkg/k8s => ./pkg/k8s
)

require (
	github.com/cilium/tetragon v0.0.0-00010101000000-000000000000
	github.com/cilium/tetragon/api v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.9.3
	google.golang.org/grpc v1.72.2
	google.golang.org/protobuf v1.36.6
	sigs.k8s.io/yaml v1.4.0
)

require (
	github.com/kr/pretty v0.3.1 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250407143221-ac9807e6c755 // indirect
)
