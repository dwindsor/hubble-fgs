// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// sensorinit package initializes sensor handlers. Import this package to use it.
package sensorinit

import (
	// Import sensor handlers
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/heartbeat"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/http"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/network"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/socktrack"

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
