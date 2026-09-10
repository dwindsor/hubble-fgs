// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package option

import (
	"net/url"
	"time"

	"github.com/cilium/tetragon/pkg/option"

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
	Environment                       string
	EnableApplicationModel            bool
	AppModelTrackExecIds              bool
	EnableSyscallTracking             bool
	ApplicationModelExportInterval    time.Duration
	ApplicationModelExportFilename    string
	ApplicationModelSplitMaxHostProcs int
	ApplicationModelExportFragments   bool
	ApplicationModelRetentionDuration time.Duration

	ApplicationModelExportFileMaxSizeMB  int
	ApplicationModelExportFileMaxBackups int
	ApplicationModelExportFileCompress   bool

	TelemetryExportFilename string
	ConnectionLogFileName   string

	SplunkHECEndpoint *url.URL
	SplunkHECToken    string
	// SplunkHECMaxContentLength is the maximum request body size in bytes.
	SplunkHECMaxContentLength int
	SplunkHECFlushInterval    time.Duration
	SplunkHECTimeout          time.Duration
	SplunkHECSourcetypes      []string
	EnableSplunkHECDebug      bool

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

	PoliciesDir string

	EnableAlerts         bool
	AlertsExportDir      string
	AlertsExportFilename string

	DebugX []string

	ProcessCacheStaleInterval time.Duration

	EnableAWSSonar bool
	AWSSonarRegion string

	Layer3SocketMapSize            int
	TCPSocketMapSize               int
	UDPSocketMapSize               int
	NetworkWatermarksMapSize       int
	ICMPSocketMapSize              int
	HTTPContextMapSize             int
	TLSContextMapSize              int
	DisableLayer3                  bool
	EnableIcmpTracking             bool
	EnableUserDNSDebug             bool
	EnableBPFDNSParser             bool
	BPFDNSParserMaxPendingRequests uint32
	EnableBPFDNSPerPod             bool
	BPFDNSPerPodPrealloc           uint32
	BPFDNSPerPodThresold           uint32
	// DNSPorts has to be []int because viper doesn't support []uint16 but
	// we proceed to validate that the ranges are correct.
	DNSPorts []int

	DNSStatsPerSocket bool

	DNSReportQuestions    bool
	EnableDNSMetrics      bool
	DNSMetricsLabelFilter []string

	EnableFimDispatcher bool

	MandateConf mandateconf.ManagerConf

	EnableTCP       bool
	EnableUDP       bool
	EnableICMP      bool
	ICMPV6Info      bool
	EnableIGMP      bool
	EnableRawsock   bool
	EnableUserDNS   bool
	Layer3CLIEnable bool

	RawsockReportClose        bool
	EnableRawsockMetrics      bool
	RawsockMetricsLabelFilter []string

	TCPStatsInterval time.Duration

	EnableTCPWatermarks              bool
	TCPWatermarksWindowSizeMs        uint32
	TCPWatermarksBurstTriggerPercent uint32
	TCPWatermarksDipTriggerPercent   uint32

	EnableTCPRTT  bool
	TCPRTTHistMin uint32
	TCPRTTHistMax uint32

	EnableTCPMetrics      bool
	TCPMetricsLabelFilter []string

	TCPDisableEvents        []string
	TCPDisableListenEvents  bool
	TCPDisableConnectEvents bool
	TCPDisableAcceptEvents  bool
	TCPDisableCloseEvents   bool

	EnableUDPCGroup      bool
	UDPStatsInterval     time.Duration
	UDPIdleSocketTimeout time.Duration
	UDPInKernelManaged   bool

	EnableUDPWatermarks              bool
	UDPWatermarksWindowSizeMs        uint32
	UDPWatermarksBurstTriggerPercent uint32
	UDPWatermarksDipTriggerPercent   uint32

	EnableUDPMetrics      bool
	UDPMetricsLabelFilter []string

	UDPDisableEvents        []string
	UDPDisableListenEvents  bool
	UDPDisableConnectEvents bool
	UDPDisableStatsEvents   bool
	UDPDisableCloseEvents   bool

	// MulticastAppID is derived from the MulticastApp string.
	MulticastApp           string
	MulticastAppID         MulticastAppID
	MulticastPorts         []int // see comment above for DNSPorts
	MulticastSeqCheck      bool
	MulticastSamplePercent float64

	EnableNetworkWatermarksExitGen   bool
	NetworkWatermarksExitGenInterval time.Duration

	EnableNetworkEvents bool

	EnableNetworkInterfaceStats   bool
	NetworkInterfaceStatsInterval time.Duration

	EnableTLSSensor       bool
	TLSSensorMode         string
	TLSSensorPorts        []int // see comment above for DNSPorts
	EnableTLSMetrics      bool
	TLSMetricsLabelFilter []string

	EnableNopSensor bool
	NopSensorPorts  []int

	EnableHTTPSensor       bool
	HTTPSensorPorts        []int // see comment above for DNSPorts
	EnableHTTP2Handling    bool
	EnableHTTPMetrics      bool
	HTTPMetricsLabelFilter []string

	EnableAlertProfiling bool

	// K8sServiceAccountAuth is the base64 string for authenticating with k8s control plane
	// when Tetragon is running outside of k8s cluster.
	// The value must be in the below format "API_SERVER|TOKEN|CA"
	K8sServiceAccountAuth string

	// NodeNamespace is the namespace for registering TetragonNode resource
	// This is used when Tetragon agent is running outside but connecting to k8s cluster.
	NodeNamespace string

	AdditionalNodeLabels map[string]string

	BPFDebugAreas *BPFDbgEnum
}

const (
	// Needs to be in sync with TLS_MAX_PORTS from tls_map.h
	TLS_MAX_PORTS = 512

	SplunkHECSourcetypeEvents           = "tetragon:events"
	SplunkHECSourcetypeFlows            = "tetragon:flows"
	SplunkHECSourcetypeOCSF             = "tetragon:ocsf"
	SplunkHECSourcetypeApplicationModel = "tetragon:application_model"
	SplunkHECSourcetypeTelemetry        = "tetragon:telemetry"
	SplunkHECSourcetypeConnections      = "tetragon:connections"
	SplunkHECSourcetypeAlerts           = "tetragon:alerts"
)

var defaultSplunkHECSourcetypes = []string{
	SplunkHECSourcetypeApplicationModel,
	SplunkHECSourcetypeTelemetry,
	SplunkHECSourcetypeEvents,
	SplunkHECSourcetypeAlerts,
}

var (
	// Config contains all the configuration used by Tetragon.
	Config = config{
		EnableApplicationModel:            false,
		EnableSyscallTracking:             false,
		ApplicationModelExportInterval:    0,
		ApplicationModelExportFragments:   false,
		ApplicationModelRetentionDuration: time.Duration(24 * time.Hour),
		SplunkHECMaxContentLength:         1024 * 1024,
		SplunkHECFlushInterval:            time.Duration(2) * time.Second,
		SplunkHECTimeout:                  time.Duration(30) * time.Second,
		SplunkHECSourcetypes:              append([]string{}, defaultSplunkHECSourcetypes...),
		EnableSplunkHECDebug:              false,
		DnsCacheSize:                      1024,
		ProcessTreeCacheSize:              65000,
		BpfEndpointCacheSize:              65000,
		EndpointCacheSize:                 65000,
		TlsCacheSize:                      1024,
		TcpCacheSize:                      32768,
		NetNsCacheSize:                    256,
		FimFifoPath:                       "/var/run/cilium/hubble",
		FimRuntimeEndpoint:                "",
		FimMaxFileSizeDigest:              1 * 1024 * 1024 * 1024, // 1GB
		FimMaxTimeoutDigestSec:            30,
		EnableUserDNSDebug:                false,
		Layer3SocketMapSize:               32768,
		TCPSocketMapSize:                  32768,
		UDPSocketMapSize:                  32768,
		NetworkWatermarksMapSize:          32768,
		ICMPSocketMapSize:                 32768,
		HTTPContextMapSize:                1000,
		TLSContextMapSize:                 32000,
		EnableIcmpTracking:                false,
		EnableCilium:                      false,
		ProcessCacheStaleInterval:         time.Duration(60 * time.Minute),
		EnableFimDispatcher:               false,
		BPFDNSParserMaxPendingRequests:    1024,
		EnableAlertProfiling:              false,
		EnableNetworkEvents:               true,
		UDPInKernelManaged:                false,
		ApplicationModelSplitMaxHostProcs: 100,
		EnableTCPMetrics:                  true,
		EnableUDPCGroup:                   true,
		EnableUDPMetrics:                  true,
		EnableNetworkWatermarksExitGen:    true,
		NetworkWatermarksExitGenInterval:  time.Duration(1) * time.Second,
		UDPIdleSocketTimeout:              time.Duration(2) * time.Minute,
		EnableRawsockMetrics:              true,
		NetworkInterfaceStatsInterval:     NetworkStatInterval,
		TLSSensorMode:                     "cgroup",
		EnableTLSMetrics:                  true,
		EnableHTTP2Handling:               true,
		EnableHTTPMetrics:                 true,
		// Set default value for bpf debug areas
		// to be kept in sync with bpf/libs/debug.h
		BPFDebugAreas: NewBPFDbgEnum(option.Config.BPFDebugAreas, map[string]uint8{
			"dns":  1 << 0,
			"http": 1 << 1,
			"tcp":  1 << 2,
		}),
	}
)
