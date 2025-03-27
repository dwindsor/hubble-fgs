// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

import (
	"time"

	mandateconf "github.com/isovalent/hubble-fgs/pkg/mandate/conf"
)

type config struct {
	EnableProcessTree         bool
	ProcessTreeExportInterval time.Duration
	ProcessTreeExportFilename string

	DnsCacheSize         int
	ProcessTreeCacheSize int
	EndpointCacheSize    int
	BpfEndpointCacheSize int
	TlsCacheSize         int
	TcpCacheSize         int
	NetNsCacheSize       int

	FimFifoPath            string
	FimRuntimeEndpoint     string
	FimMaxFileSizeDigest   int64
	FimMaxTimeoutDigestSec int64

	DisableKprobeMulti bool
	DetachOldBpf       bool

	FlowExportFilename       string
	FlowExportFileMaxSizeMB  int
	FlowExportFileMaxBackups int
	FlowExportFileCompress   bool

	EnablePolicyK8sWatcher bool
	EnableSandboxPolicies  bool
	SandboxPolicies        []string
	EnableCilium           bool

	EnableAlerts    bool
	AlertsExportDir string

	DebugX []string

	ProcessCacheStaleInterval time.Duration

	EnableAWSSonar bool
	AWSSonarRegion string

	EnableIcmpTracking bool
	EnableDnsDebug     bool
	EnableBPFDNSParser bool

	DNSStatsPerSocket bool

	EnableFimDispatcher bool

	MandateConf mandateconf.ManagerConf
}

var (
	// Config contains all the configuration used by Tetragon.
	Config = config{
		EnableProcessTree:         false,
		ProcessTreeExportInterval: 0,
		DnsCacheSize:              1024,
		ProcessTreeCacheSize:      65000,
		BpfEndpointCacheSize:      65000,
		EndpointCacheSize:         65000,
		TlsCacheSize:              1024,
		TcpCacheSize:              32768,
		NetNsCacheSize:            256,
		FimFifoPath:               "/var/run/cilium/hubble",
		FimRuntimeEndpoint:        "",
		FimMaxFileSizeDigest:      1 * 1024 * 1024 * 1024, // 1GB
		FimMaxTimeoutDigestSec:    30,
		EnableDnsDebug:            false,
		EnableIcmpTracking:        false,
		EnableCilium:              false,
		ProcessCacheStaleInterval: time.Duration(60 * time.Minute),
		EnableFimDispatcher:       false,
	}
)
