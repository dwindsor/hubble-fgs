// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

type config struct {
	EnableProcessAncestors bool
	DnsCacheSize           int
	TlsCacheSize           int
	NetNsCacheSize         int
	FimFifoPath            string
	DisableKprobeMulti     bool
	FimRuntimeEndpoint     string
	DetachOldBpf           bool

	FlowExportFilename       string
	FlowExportFileMaxSizeMB  int
	FlowExportFileMaxBackups int
	FlowExportFileCompress   bool
	EnableIcmpTracking       bool

	EnableDnsDebug bool

	EnableSandboxPolicies bool
	SandboxPolicies       []string
}

var (
	// Config contains all the configuration used by Tetragon.
	Config = config{
		EnableProcessAncestors: false,
		DnsCacheSize:           1024,
		TlsCacheSize:           1024,
		NetNsCacheSize:         256,
		FimFifoPath:            "/var/run/cilium/hubble",
		FimRuntimeEndpoint:     "",
		EnableDnsDebug:         false,
		EnableIcmpTracking:     false,
	}
)
