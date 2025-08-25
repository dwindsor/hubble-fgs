module github.com/isovalent/hubble-fgs/api

go 1.25.0

replace (
	github.com/cilium/tetragon => ../modules/tetragon-oss
	github.com/cilium/tetragon-oss/pkg/k8s => ../modules/tetragon-oss/pkg/k8s
	github.com/cilium/tetragon/api => ../modules/tetragon-oss/api
	github.com/cilium/tetragon/pkg/k8s => ./pkg/k8s
)

require (
	github.com/cilium/tetragon v0.0.0-00010101000000-000000000000
	github.com/cilium/tetragon/api v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.75.0
	google.golang.org/protobuf v1.36.8
	sigs.k8s.io/yaml v1.4.0
)

require (
	github.com/kr/pretty v0.3.1 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
)
