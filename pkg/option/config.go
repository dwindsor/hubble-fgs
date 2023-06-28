// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

type config struct {
	EnableProcessAncestors bool
	DnsCacheSize           int
	NetNsCacheSize         int
	FimFifoPath            string
	DisableKprobeMulti     bool
	FimRuntimeEndpoint     string
}

var (
	// Config contains all the configuration used by Tetragon.
	Config = config{
		EnableProcessAncestors: false,
		DnsCacheSize:           1024,
		NetNsCacheSize:         256,
		FimFifoPath:            "/var/run/cilium/hubble",
		FimRuntimeEndpoint:     "",
	}
)
