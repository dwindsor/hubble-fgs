// sensorinit package initializes sensor handlers. Import this package to use it.
package sensorinit

import (
	// Import sensor handlers
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/file"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/heartbeat"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/http"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/icmp"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/network"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/rawsock"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"

	// Import OSS sensor handlers
	_ "github.com/cilium/tetragon/pkg/sensors/test"
	_ "github.com/cilium/tetragon/pkg/sensors/tracing"

	// Import GRPC layer sensor handlers
	_ "github.com/isovalent/hubble-fgs/pkg/grpc/dnsproto"
	_ "github.com/isovalent/hubble-fgs/pkg/grpc/exec"
	_ "github.com/isovalent/hubble-fgs/pkg/grpc/file"
	_ "github.com/isovalent/hubble-fgs/pkg/grpc/httpproto"
	_ "github.com/isovalent/hubble-fgs/pkg/grpc/iface"
	_ "github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	_ "github.com/isovalent/hubble-fgs/pkg/grpc/networkWatermarks"
	_ "github.com/isovalent/hubble-fgs/pkg/grpc/sockinfo"
	_ "github.com/isovalent/hubble-fgs/pkg/grpc/test"
	_ "github.com/isovalent/hubble-fgs/pkg/grpc/tls"

	// Import OSS GRPC sensor handlers here
	_ "github.com/cilium/tetragon/pkg/grpc/tracing"

	// Initialize cache (tbd) remove this and actually use them
	_ "github.com/isovalent/hubble-fgs/pkg/dns"
)
