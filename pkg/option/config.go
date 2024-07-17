// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

type config struct {
	EnableProcessAncestors bool
	DnsCacheSize           int
	ProcessTreeCacheSize   int
	EndpointCacheSize      int
	BpfEndpointCacheSize   int
	TlsCacheSize           int
	TcpCacheSize           int
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
	EnableCilium          bool
}

var (
	// Config contains all the configuration used by Tetragon.
	Config = config{
		EnableProcessAncestors: false,
		DnsCacheSize:           1024,
		ProcessTreeCacheSize:   1024,
		BpfEndpointCacheSize:   1024,
		EndpointCacheSize:      1024,
		TlsCacheSize:           1024,
		TcpCacheSize:           32768,
		NetNsCacheSize:         256,
		FimFifoPath:            "/var/run/cilium/hubble",
		FimRuntimeEndpoint:     "",
		EnableDnsDebug:         false,
		EnableIcmpTracking:     false,
		EnableCilium:           false,
	}
)
