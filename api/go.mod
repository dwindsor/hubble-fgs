module github.com/isovalent/hubble-fgs/api

go 1.22.2

replace (
	github.com/cilium/tetragon => ../modules/tetragon-oss
	github.com/cilium/tetragon/api => ../modules/tetragon-oss/api

	github.com/optiopay/kafka => github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b
)

require (
	github.com/cilium/tetragon v0.0.0-00010101000000-000000000000
	github.com/cilium/tetragon/api v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.9.3
	google.golang.org/grpc v1.63.2
	google.golang.org/protobuf v1.33.0
	sigs.k8s.io/yaml v1.4.0
)

require (
	golang.org/x/net v0.23.0 // indirect
	golang.org/x/sys v0.19.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240227224415-6ceb2ff114de // indirect
)
