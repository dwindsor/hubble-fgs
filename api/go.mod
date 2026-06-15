module github.com/isovalent/hubble-fgs/api

go 1.26.0

replace (
	github.com/cilium/tetragon => ../modules/tetragon-oss
	github.com/cilium/tetragon-oss/pkg/k8s => ../modules/tetragon-oss/pkg/k8s
	github.com/cilium/tetragon/api => ../modules/tetragon-oss/api
	github.com/cilium/tetragon/pkg/k8s => ./pkg/k8s
)

require (
	github.com/cilium/tetragon v0.0.0-00010101000000-000000000000
	github.com/cilium/tetragon/api v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.81.1
	google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af
	sigs.k8s.io/yaml v1.6.0
)

require (
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
)
