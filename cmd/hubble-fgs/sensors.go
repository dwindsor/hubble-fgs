//go:build enterprise
// +build enterprise

package main

import (
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/http"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/kfree"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/network"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/tcp"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/test"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/tracing"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/udp"
)
