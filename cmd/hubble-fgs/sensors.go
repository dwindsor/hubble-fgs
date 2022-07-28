//go:build enterprise
// +build enterprise

package main

import (
	// Import sensor handlers
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/file"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/http"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/kfree"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/network"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/tcp"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/udp"

	_ "github.com/cilium/tetragon/pkg/sensors/test"
	_ "github.com/cilium/tetragon/pkg/sensors/tracing"

	// Import GRPC layer sensor handlers
	_ "github.com/isovalent/hubble-fgs/pkg/grpc/burst"
	_ "github.com/isovalent/hubble-fgs/pkg/grpc/dnsproto"
	_ "github.com/isovalent/hubble-fgs/pkg/grpc/exec"
	_ "github.com/isovalent/hubble-fgs/pkg/grpc/file"
	_ "github.com/isovalent/hubble-fgs/pkg/grpc/httpproto"
	_ "github.com/isovalent/hubble-fgs/pkg/grpc/iface"
	_ "github.com/isovalent/hubble-fgs/pkg/grpc/kfree"
	_ "github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	_ "github.com/isovalent/hubble-fgs/pkg/grpc/sockinfo"
	_ "github.com/isovalent/hubble-fgs/pkg/grpc/test"
	_ "github.com/isovalent/hubble-fgs/pkg/grpc/tls"
	_ "github.com/isovalent/hubble-fgs/pkg/grpc/tracing"

	// Import OSS sensors here

	// Initialize cache (tbd) remove this and actually use them
	_ "github.com/isovalent/hubble-fgs/pkg/dns"
)
