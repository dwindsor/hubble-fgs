// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

import (
	"time"

	mandateconf "github.com/isovalent/hubble-fgs/pkg/mandate/conf"
)

type config struct {
	// Environment specifies the environment in which Tetragon is running. It
	// can be one of the following:
	// - "kubernetes": Tetragon is running in a Kubernetes environment. In this
	// mode, Tetragon retrieves the local node information from Kubernetes API
	// server.
	// - "": Unspecified. Tetragon will not attempt to retrieve any environment
	//   specific information.
	Environment                    string
	EnableApplicationModel         bool
	EnableSyscallTracking          bool
	ApplicationModelExportInterval time.Duration
	ApplicationModelExportFilename string

	TelemetryExportFilename string
	ConnectionLogFileName   string

	DnsCacheSize         int
	ProcessTreeCacheSize int
	EndpointCacheSize    int
	BpfEndpointCacheSize int
	TlsCacheSize         int
	TcpCacheSize         int
	NetNsCacheSize       int

	FimFifoLocalPath       string
	FimFifoPath            string
	FimRuntimeEndpoint     string
	FimMaxFileSizeDigest   int64
	FimMaxTimeoutDigestSec int64

	DisableKprobeMulti bool
	DetachOldBpf       bool

	OCSFExportFilename       string
	OCSFExportServer         string
	OCSFExportFileMaxSizeMB  int
	OCSFExportFileMaxBackups int
	OCSFExportFileCompress   bool

	FlowExportFilename       string
	FlowExportFileMaxSizeMB  int
	FlowExportFileMaxBackups int
	FlowExportFileCompress   bool

	EnablePolicyK8sWatcher bool
	EnableSandboxPolicies  bool
	SandboxPolicies        []string
	EnableCilium           bool

	NetworkPolicies    []string
	NetworkPoliciesDir string

	EnableAlerts    bool
	AlertsExportDir string

	DebugX []string

	ProcessCacheStaleInterval time.Duration

	EnableAWSSonar bool
	AWSSonarRegion string

	EnableIcmpTracking             bool
	EnableDnsDebug                 bool
	EnableBPFDNSParser             bool
	BPFDNSParserMaxPendingRequests uint32

	DNSStatsPerSocket bool

	EnableFimDispatcher bool

	MandateConf mandateconf.ManagerConf

	EnableTCP       bool
	EnableTCPRTT    bool
	EnableUDP       bool
	EnableLatency   bool
	EnableICMP      bool
	EnableRawsock   bool
	EnableDNS       bool
	Layer3CLIEnable bool

	UDPIdleSocketTimeout time.Duration

	EnableNetworkEvents bool

	EnableAlertProfiling bool
}

var (
	// Config contains all the configuration used by Tetragon.
	Config = config{
		EnableApplicationModel:         false,
		EnableSyscallTracking:          false,
		ApplicationModelExportInterval: 0,
		DnsCacheSize:                   1024,
		ProcessTreeCacheSize:           65000,
		BpfEndpointCacheSize:           65000,
		EndpointCacheSize:              65000,
		TlsCacheSize:                   1024,
		TcpCacheSize:                   32768,
		NetNsCacheSize:                 256,
		FimFifoPath:                    "/var/run/cilium/hubble",
		FimRuntimeEndpoint:             "",
		FimMaxFileSizeDigest:           1 * 1024 * 1024 * 1024, // 1GB
		FimMaxTimeoutDigestSec:         30,
		EnableDnsDebug:                 false,
		EnableIcmpTracking:             false,
		EnableCilium:                   false,
		ProcessCacheStaleInterval:      time.Duration(60 * time.Minute),
		EnableFimDispatcher:            false,
		BPFDNSParserMaxPendingRequests: 1024,
		EnableAlertProfiling:           false,
		EnableNetworkEvents:            true,
	}
)
