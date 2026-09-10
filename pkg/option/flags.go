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
	"fmt"
	"math"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	eedefaults "github.com/isovalent/hubble-fgs/pkg/defaults"

	fm "github.com/isovalent/hubble-fgs/pkg/sensors/file/utils"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

const (
	KeyEnvironment                       = "environment"
	KeyOCSFExportFilename                = "ocsf-export-filename"
	KeyOCSFExportServer                  = "ocsf-export-server"
	KeyOCSFExportFileMaxSizeMB           = "ocsf-export-file-max-size-mb"
	KeyOCSFExportFileMaxBackups          = "ocsf-export-file-max-backups"
	KeyOCSFExportFileCompress            = "ocsf-export-file-compress"
	KeyFlowExportFilename                = "flow-export-filename"
	KeyFlowExportFileMaxSizeMB           = "flow-export-file-max-size-mb"
	KeyFlowExportFileMaxBackups          = "flow-export-file-max-backups"
	KeyFlowExportFileCompress            = "flow-export-file-compress"
	KeyFimFifoPath                       = "fim-fifo-path"
	KeyFimFifoLocalPath                  = "fim-fifo-local-path"
	KeyFimRuntimeEndpoint                = "fim-runtime-endpoint"
	keyFimMaxFileSizeDigest              = "fim-max-file-size-digest"
	keyFimTimeoutDigest                  = "fim-timeout-digest"
	KeyDnsCacheSize                      = "dns-cache-size"
	KeyEndpointCacheSize                 = "endpoint-cache-size"
	KeyBpfEndpointCacheSize              = "bpf-endpoint-cache-size"
	KeyTlsCacheSize                      = "tls-cache-size"
	KeyTcpCacheSize                      = "tcp-cache-size"
	KeyNetNsCacheSize                    = "net-ns-cache-size"
	KeyDetatchOldBPF                     = "detach-old-bpf"
	KeyEnableApplicationModel            = "enable-application-model"
	KeyAppModelTrackExecIds              = "app-model-track-exec-ids"
	KeyEnableSyscallTracking             = "enable-syscall-tracking"
	KeyApplicationModelCacheSize         = "application-model-cache-size"
	KeyApplicationModelExportInterval    = "application-model-export-interval"
	KeyApplicationModelExportFilename    = "application-model-export-filename"
	KeyTelemetryExportFilename           = "telemetry-export-filename"
	KeySplunkHECEndpoint                 = "splunk-hec-endpoint"
	KeySplunkHECToken                    = "splunk-hec-token"
	KeySplunkHECMaxContentLength         = "splunk-hec-max-content-length"
	KeySplunkHECFlushInterval            = "splunk-hec-flush-interval"
	KeySplunkHECTimeout                  = "splunk-hec-timeout"
	KeySplunkHECSourcetypes              = "splunk-hec-sourcetypes"
	KeyEnableSplunkHECDebug              = "enable-splunk-hec-debug"
	KeyConnectionLogFilename             = "connection-log-filename"
	keyLayer3SocketMapSize               = "bpf-layer3-socket-cache-size"
	keyTCPSocketMapSize                  = "bpf-tcp-socket-cache-size"
	keyUDPSocketMapSize                  = "bpf-udp-socket-cache-size"
	keyNetworkWatermarksMapSize          = "bpf-network-watermarks-cache-size"
	keyICMPSocketMapSize                 = "bpf-icmp-socket-cache-size"
	keyHTTPContextMapSize                = "bpf-http-context-cache-size"
	keyTLSContextMapSize                 = "bpf-tls-context-cache-size"
	KeyDisableLayer3                     = "disable-layer3"
	keyEnableIcmpTracking                = "enable-icmp-tracking"
	keyEnablePolicyK8sWatcher            = "enable-policy-k8swatcher"
	keyEnableSandboxPolicies             = "enable-sandboxpolicies"
	keySandboxPolicy                     = "sandbox-policy"
	keyNetworkPolicy                     = "network-policy"
	keyNetworkPolicyDir                  = "network-policy-dir"
	keyEnableAlerts                      = "enable-alerts"
	keyAlertsExportDir                   = "alerts-export-dir"
	keyAlertsExportFilename              = "alerts-export-filename"
	keyDebugX                            = "debugx"
	keyEnableAWSSonar                    = "enable-aws-sonar"
	keyAWSSonarRegion                    = "aws-sonar-region"
	KeyEnableCiliumAPI                   = "enable-cilium-api"
	KeyEnableDnsDebug                    = "enable-dns-debug"
	keyEnableUserDNSDebug                = "enable-user-dns-debug"
	KeyProcessCacheStaleInterval         = "process-cache-stale-interval"
	keyEnableBPFDNSParser                = "enable-bpf-dns-parser"
	keyBPFDNSParserMaxPendingRequests    = "bpf-dns-parser-max-pending-requests"
	KeyEnableBPFDNSPerPod                = "enable-bpf-dns-parser-per-pod"
	KeyBPFDNSPerPodPrealloc              = "bpf-dns-parser-per-pod-prealloc"
	KeyBPFDNSPerPodThreshold             = "bpf-dns-parser-per-pod-threshold"
	KeyDNSPorts                          = "dns-ports"
	keyDNSStatsPerSocket                 = "dns-stats-per-socket"
	KeyEnableFimDispatcher               = "fim-enable-dispatcher"
	KeyMandateURL                        = "mandate-url"
	KeyMandateRefreshPeriod              = "mandate-refresh-period"
	KeyEnableTCP                         = "enable-tcp"
	keyTCPStatsInterval                  = "tcp-stats-interval"
	keyEnableTCPWatermarks               = "enable-tcp-watermarks"
	keyTCPWatermarksWindowSizeMs         = "tcp-watermarks-window-size-ms"
	keyTCPWatermarksBurstTriggerPercent  = "tcp-watermarks-burst-trigger-percent"
	keyTCPWatermarksDipTriggerPercent    = "tcp-watermarks-dip-trigger-percent"
	keyEnableTCPRTT                      = "enable-tcp-rtt"
	keyTCPRTTHistMin                     = "tcp-rtt-min"
	keyTCPRTTHistMax                     = "tcp-rtt-max"
	keyEnableTCPMetrics                  = "enable-tcp-metrics"
	keyTCPMetricsLabelFilter             = "tcp-metrics-label-filter"
	keyTCPDisableEvents                  = "tcp-disable-events"
	keyEnableUDP                         = "enable-udp"
	KeyEnableUDPCgroup                   = "enable-udp-cgroup"
	keyUDPStatsInterval                  = "udp-stats-interval"
	keyEnableUserDNS                     = "enable-user-dns"
	keyUDPIdleSocketTimeout              = "udp-idle-socket-timeout"
	keyUDPInKernelManaged                = "udp-in-kernel-managed"
	keyEnableUDPWatermarks               = "enable-udp-watermarks"
	keyUDPWatermarksWindowSizeMs         = "udp-watermarks-window-size-ms"
	keyUDPWatermarksBurstTriggerPercent  = "udp-watermarks-burst-trigger-percent"
	keyUDPWatermarksDipTriggerPercent    = "udp-watermarks-dip-trigger-percent"
	keyEnableUDPMetrics                  = "enable-udp-metrics"
	keyUDPMetricsLabelFilter             = "udp-metrics-label-filter"
	keyUDPDisableEvents                  = "udp-disable-events"
	keyEnableICMP                        = "enable-icmp"
	keyICMPV6Info                        = "icmpv6-info"
	keyEnableIGMP                        = "enable-igmp"
	keyEnableRawsock                     = "enable-rawsock"
	keyRawsockReportClose                = "rawsock-report-close"
	keyEnableRawsockMetrics              = "enable-rawsock-metrics"
	keyRawsockMetricsLabelFilter         = "rawsock-metrics-label-filter"
	keyEnableDNS                         = "enable-dns"
	keyDNSReportQuestions                = "dns-report-questions"
	keyEnableDNSMetrics                  = "enable-dns-metrics"
	keyDNSMetricsLabelFilter             = "dns-metrics-label-filter"
	keyMulticastApp                      = "multicast-app"
	keyMulticastPorts                    = "multicast-ports"
	keyEnableMulticastSeqCheck           = "enable-multicast-seq-check"
	keyMulticastSamplePercent            = "multicast-sample-percent"
	keyEnableNetworkWatermarksExitGen    = "enable-network-watermarks-exit-gen"
	keyNetworkWatermarksExitGenInterval  = "network-watermarks-exit-gen-interval"
	keyEnableNetworkEvents               = "enable-network-events"
	keyEnableNetworkInterfaceStats       = "enable-network-interface-stats"
	keyNetworkInterfaceStatsInterval     = "network-interface-stats-interval"
	keyEnableTLSSensor                   = "enable-tls-sensor"
	keyTLSSensorMode                     = "tls-sensor-mode"
	keyTLSSensorPorts                    = "tls-sensor-ports"
	keyEnableTLSMetrics                  = "enable-tls-sensor-metrics"
	keyTLSMetricsLabelFilter             = "tls-sensor-metrics-label-filter"
	keyEnableNopSensor                   = "enable-nop-sensor"
	keyNopSensorPorts                    = "nop-sensor-ports"
	keyEnableHTTPSensor                  = "enable-http-sensor"
	keyHTTPSensorPorts                   = "http-sensor-ports"
	keyEnableHTTP2Handling               = "enable-http2-handling"
	keyEnableHTTPMetrics                 = "enable-http-sensor-metrics"
	keyHTTPMetricsLabelFilter            = "http-sensor-metrics-label-filter"
	keyEnableAlertsProfiling             = "enable-alerts-profiling"
	keyK8sServiceAccountAuth             = "k8s-service-account-auth"
	keyTetragonNodeNamespace             = "node-namespace"
	KeyAdditionalNodeLabel               = "additional-node-label"
	KeyPolicyDir                         = "policy-dir"
	KeyApplicationModelSplitMaxHostProcs = "application-model-split-max-host-processes"
	KeyApplicationModelExportFragments   = "application-model-export-fragments"
	KeyApplicationModelRetentionDuration = "application-model-retention-duration"

	KeyApplicationModelExportFileMaxSizeMB  = "application-model-export-file-max-size-mb"
	KeyApplicationModelExportFileMaxBackups = "application-model-export-file-max-backups"
	KeyApplicationModelExportFileCompress   = "application-model-export-file-compress"

	EnvironmentAWS        = "aws"
	EnvironmentAzure      = "azure"
	EnvironmentGCloud     = "gcloud"
	EnvironmentKubernetes = "kubernetes"
	NetworkStatInterval   = time.Duration(10 * time.Second)

	// A batch smaller than this cannot hold a single application model event.
	splunkHECMinContentLength = 4096
	// Flushing more often than this wastes a request per record.
	splunkHECMinFlushInterval = 1 * time.Second
	// A shorter timeout gives up on large batches the collector is still reading.
	splunkHECMinTimeout = 10 * time.Second
)

var (
	environments              = []string{EnvironmentAWS, EnvironmentAzure, EnvironmentGCloud, EnvironmentKubernetes}
	splunkHECValidSourcetypes = []string{
		SplunkHECSourcetypeEvents,
		SplunkHECSourcetypeFlows,
		SplunkHECSourcetypeOCSF,
		SplunkHECSourcetypeApplicationModel,
		SplunkHECSourcetypeTelemetry,
		SplunkHECSourcetypeConnections,
		SplunkHECSourcetypeAlerts,
	}

	redactedKeys = []string{
		keyK8sServiceAccountAuth,
		KeySplunkHECToken,
	}
)

type MulticastAppID int

// Explicitly state the app IDs. These must match the same in the BPF code.
const (
	MulticastNoApp  MulticastAppID = 0
	MulticastAppRTP MulticastAppID = 2
)

var (
	multicastAppID = map[string]MulticastAppID{
		"":    MulticastNoApp,
		"RTP": MulticastAppRTP,
	}
)

// RedactedSettings returns all settings with sensitive keys redacted.
func RedactedSettings() map[string]any {
	res := viper.AllSettings()
	for _, k := range redactedKeys {
		if _, ok := res[k]; ok {
			res[k] = "[redacted]"
		}
	}
	return res
}

func FixUpOSSFlags(flags *pflag.FlagSet) {
	flags.Lookup(option.KeyEnableTracingPolicyCRD).Hidden = true

	fl := flags.Lookup(option.KeyBpfDebugArea)
	if fl != nil {
		// replace the original OSS config (used as a pflag flag) with our EE one
		// to add EE specific bpf areas to the underlying SliceEnum.
		// Keep the same address.
		*option.Config.BPFDebugAreas = *Config.BPFDebugAreas.BPFDbgEnum // update the enum
		// replace usage string
		usageStr, _, _ := strings.Cut(fl.Usage, "(")
		fl.Usage = usageStr + Config.BPFDebugAreas.Allowed()
	}
}

func AddEnterpriseFlags(flags *pflag.FlagSet) {
	flags.String(KeyEnvironment, "", "Specify the environment in which Tetragon is running. Valid values are: "+fmt.Sprintf("%s", environments))
	flags.MarkHidden(KeyEnvironment)
	// OCSF export flags
	flags.String(KeyOCSFExportFilename, "", "Filename for OCSF JSON export. Disabled by default")
	flags.String(KeyOCSFExportServer, "", "Server for OCSF JSON export. Disabled by default")
	flags.Int(KeyOCSFExportFileMaxSizeMB, 10, "Size in MB for rotating OCSF JSON export files")
	flags.Int(KeyOCSFExportFileMaxBackups, 5, "Number of rotated OCSF JSON export files to retain")
	flags.Bool(KeyOCSFExportFileCompress, false, "Compress rotated OCSF JSON export files")
	// flows export flags
	flags.String(KeyFlowExportFilename, "", "Filename for flow JSON export. Disabled by default")
	flags.Int(KeyFlowExportFileMaxSizeMB, 10, "Size in MB for rotating flow JSON export files")
	flags.Int(KeyFlowExportFileMaxBackups, 5, "Number of rotated flow JSON export files to retain")
	flags.Bool(KeyFlowExportFileCompress, false, "Compress rotated flow JSON export files")
	flags.Bool(KeyEnableApplicationModel, false, "Enable application model in memory")
	flags.Bool(KeyAppModelTrackExecIds, true, "Track execution IDs in the application model")
	flags.Bool(KeyEnableSyscallTracking, false, "Track system calls in the application model. Application model must be enabled for this to work")
	// Experimental flags to periodically export process model to export JSON file.
	flags.Duration(KeyApplicationModelExportInterval, 0, "Interval at which to export application model as JSON.")
	flags.MarkHidden(KeyApplicationModelExportInterval)
	flags.String(KeyApplicationModelExportFilename, "", "Filename for application model JSON export. Set to \"\" to disable.")
	flags.MarkHidden(KeyApplicationModelExportFilename)
	flags.Int(KeyApplicationModelExportFileMaxSizeMB, 25, "Size in MB for rotating flow JSON export files")
	flags.MarkHidden(KeyApplicationModelExportFileMaxSizeMB)
	flags.Int(KeyApplicationModelExportFileMaxBackups, 1, "Number of rotated flow JSON export files to retain")
	flags.MarkHidden(KeyApplicationModelExportFileMaxBackups)
	flags.Bool(KeyApplicationModelExportFileCompress, false, "Compress rotated flow JSON export files")
	flags.MarkHidden(KeyApplicationModelExportFileCompress)
	flags.Bool(KeyApplicationModelExportFragments, false, "When exporting application model to JSON, export as fragments. This circumvents message ingest size limits when the application model is large.")
	flags.Duration(KeyApplicationModelRetentionDuration, time.Duration(24*time.Hour), "Retention period for exited processes in the application model.")
	flags.String(KeyTelemetryExportFilename, "", "Filename for telemetry JSON export. Set to \"\" to disable. To enable telemetry export, --"+KeyEnableApplicationModel+" flag must be set to true. Telemetry export uses the export interval specified by --"+KeyApplicationModelExportInterval+" flag.")
	flags.String(KeySplunkHECEndpoint, "", "URL of the Splunk HTTP Event Collector endpoint to send telemetry to. Set to \"\" to disable.")
	flags.String(KeySplunkHECToken, "", "Authentication token for the Splunk HTTP Event Collector endpoint specified by --"+KeySplunkHECEndpoint+" flag.")
	flags.Int(KeySplunkHECMaxContentLength, 1024*1024, "Maximum size in bytes of a single request body sent to the Splunk HTTP Event Collector. Must not exceed the max_content_length configured on the Splunk server.")
	flags.Duration(KeySplunkHECFlushInterval, 3*time.Second, fmt.Sprintf("Maximum time a record waits to be batched before it is sent to the Splunk HTTP Event Collector. Must be at least %s.", splunkHECMinFlushInterval))
	flags.Duration(KeySplunkHECTimeout, 30*time.Second, fmt.Sprintf("Timeout for a single request to the Splunk HTTP Event Collector. Must be at least %s.", splunkHECMinTimeout))
	flags.StringSlice(KeySplunkHECSourcetypes, Config.SplunkHECSourcetypes, "Comma-separated list of JSON export sourcetypes to send to the Splunk HTTP Event Collector.")
	flags.Bool(KeyEnableSplunkHECDebug, false, "Enable verbose debug logging for Splunk HEC sends and batches.")
	flags.String(KeyConnectionLogFilename, "", "Filename for connection log. Set to \"\" to disable.")
	flags.MarkHidden(KeyConnectionLogFilename)
	flags.Int(KeyDnsCacheSize, 1024, "Set the size of the internal DNS cache. Higher values enable Tetragon to keep track of more destination names before evicting old ones")
	flags.Int(KeyApplicationModelCacheSize, 65536, "Set the size of the BPF data structure to store application model and statistics. Higher values enable Tetragon to keep track of more processes before evicting old ones")
	flags.Int(KeyApplicationModelSplitMaxHostProcs, 100, "Maximum number of host processes per application model telemetry event")
	flags.Int(KeyEndpointCacheSize, 65536, "Set the size of the internal endpoint cache. Higher values enable Tetragon to keep track of more network endpoints before evicting old ones")
	flags.Int(KeyBpfEndpointCacheSize, 65536, "Set the size of the internal BPF endpoint cache. Higher values enable Tetragon to keep track of more network endpoints before evicting old ones")
	flags.Int(KeyTlsCacheSize, 1024, "Set the size of the internal TLS cache. Higher values enable Tetragon to keep track of more in progress handshakes before evicting old ones")
	flags.Int(KeyTcpCacheSize, 32768, "Set the size of the internal TCP cache. Higher values enable Tetragon to keep track of more concurrent TCP sessions before evicting old ones")
	flags.Int(KeyNetNsCacheSize, 256, "Set the size of the internal network namespace cache. This should be aligned with the maximum number of network namespaces (approximately, the maxumum number of pods) we expect to see in the system")
	flags.String(KeyFimFifoPath, defaults.DefaultRunDir, "Path for the FIFO used for fs-scanner and tetragon communication (for k8s deployments)")
	flags.String(KeyFimFifoLocalPath, fm.LocalScannerFifoPath, "Path for the FIFO used for fs-scanner and tetragon communication (for standalone deployments)")
	flags.String(KeyFimRuntimeEndpoint, "", "Custom container runtime endpoint for FIM (can be used only for containerd or cri-o)")
	flags.Int64(keyFimMaxFileSizeDigest, 1*1024*1024*1024, "Set the maximum file size in FIM that we will compute a digest (in bytes)")
	flags.Int64(keyFimTimeoutDigest, 30, "Set the timeout when computing a file digest in FIM (in seconds)")

	// Provide option to detach old programs even when using old names that make it
	// hard to find Tetragon specific programs. Use with some caution because we
	// could remove progs associated with other agents. But this is necessary in
	// cases where upgrading from older versions to fix bug where we failed to
	// detach programs and left stale progs attached at cgroups and tc hooks.
	flags.Bool(KeyDetatchOldBPF, false, "Detach old cgroup programs from their interfaces when loading Tetragon. Disabled by default.")

	flags.Bool(KeyDisableLayer3, false, "Disable layer3 entirely; equivalent to setting all the layer3 BPF caches to 1")
	// Options to specify layer3 map sizes.
	flags.Int(keyLayer3SocketMapSize, 32768, "Set the number of network sockets to track in BPF. Higher values enable Tetragon to keep track of more sockets before evicting old ones")
	flags.Int(keyTCPSocketMapSize, 32768, "Set the number of TCP sockets to track in BPF. Higher values enable Tetragon to keep track of more TCP sockets before evicting old ones")
	flags.Int(keyUDPSocketMapSize, 32768, "Set the number of UDP sockets to track in BPF. Higher values enable Tetragon to keep track of more UDP sockets before evicting old ones")
	flags.Int(keyNetworkWatermarksMapSize, 32768, "Set the number of processes for which to track network watermarks in BPF. Higher values enable Tetragon to keep track of more processes before evicting old ones")
	flags.Int(keyICMPSocketMapSize, 32768, "Set the number of ICMP sockets to track in BPF. Higher values enable Tetragon to keep track of more ICMP sockets before evicting old ones")
	flags.Int(keyHTTPContextMapSize, 1000, "Set the number of HTTP requests to track in BPF. Higher values enable Tetragon to keep track of more HTTP requests before evicting old ones")
	flags.Int(keyTLSContextMapSize, 32000, "Set the number of TLS sessions to track in BPF. Higher values enable Tetragon to keep track of more TLS sessions before evicting old ones")

	// Provide option to enable extra socket tracking for ICMP matching.
	flags.Bool(keyEnableIcmpTracking, false, "Enable additional socket tracking for ICMP")

	flags.Bool(keyEnablePolicyK8sWatcher, true, "Enable watching Kubernetes API server for all supported policy resources, unless some of the features are disabled by other options, or Kubernetes API server is disabled entirely by `--enable-k8s-api=false`.")
	flags.Bool(keyEnableSandboxPolicies, true, "Enable sandboxpolicies")
	flags.StringSlice(keySandboxPolicy, []string{}, "Sandbox policy file to load at startup")
	flags.StringSlice(keyNetworkPolicy, []string{}, "Network policy file to load at startup")
	flags.String(keyNetworkPolicyDir, "", "Directory for network policies to load at startup")
	flags.Bool(keyEnableAlerts, true, "Enable alerts.")
	flags.String(keyAlertsExportDir, "", "Directory for alert JSON export (filenames will be retrieved from alert rule names). Disabled by default.")
	flags.String(keyAlertsExportFilename, "", "Specify a global filename (unless overridden with alert specific export.filename), relative to alerts-export-dir, for alert JSON export. Disabled by default.")
	flags.StringSlice(keyDebugX, []string{}, "Extended debug to enable (e.g. \"tcp,udp+\"). Choose from: tcp, udp, icmp, rawsock. Tetragon defaults to maintaining metrics for program errors. Specifying the protocol/sub-system here causes events to be dispatched as well; adding a '+' will also get console messages")
	flags.Bool(KeyEnableDnsDebug, false, fmt.Sprintf("Enable DNS debug messages (deprecated flag, use --%s instead)", keyEnableUserDNSDebug))
	flags.Bool(keyEnableUserDNSDebug, false, "Enable userspace parser DNS debug messages.")
	flags.Duration(KeyProcessCacheStaleInterval, time.Duration(60*time.Minute), "Interval between stale process cache checks")
	flags.Bool(KeyEnableCiliumAPI, false, "Associate IP addresses in Tetragon's networking events with Kubernetes pods using Cilium's IP cache")
	flags.Bool(keyEnableBPFDNSParser, false, "Enable in-kernel BPF DNS parser. A 5.15.0+ kernel is required.")
	flags.Uint32(keyBPFDNSParserMaxPendingRequests, 1024, "Size of the BPF DNS parser pending requests ID map.")
	flags.Bool(KeyEnableBPFDNSPerPod, false, "Enable in-kernel BPF DNS parser maps per Pod partitioning.")
	flags.Uint32(KeyBPFDNSPerPodPrealloc, 15, "Number of maps to preallocate at startup for BPF DNS parser maps per Pod partitioning.")
	flags.Uint32(KeyBPFDNSPerPodThreshold, 5, "Threshold of free maps to keep at runtime for the BPF DNS parser maps per Pod partitioning.")
	flags.IntSlice(KeyDNSPorts, []int{53}, "Ports on which to parse DNS packets.")
	flags.Bool(keyDNSStatsPerSocket, false, "If UDP statistics are enabled, record DNS server statistics for each connection. Default is to group DNS server statistics per DNS server reducing the memory and CPU used and the stats reported")
	flags.Bool(KeyEnableFimDispatcher, false, "Enable FIM dispatcher when supported")
	flags.String(KeyMandateURL, "", "Set a URL for a Tetragon Mandate file")
	flags.Duration(KeyMandateRefreshPeriod, 1*time.Minute, "Refresh period for the Mandate file")
	flags.Bool(KeyEnableTCP, false, "Enable TCP observability")
	flags.Duration(keyTCPStatsInterval, 0, fmt.Sprintf("Enable and specify interval for TCP statistics (requires --%s)", KeyEnableTCP))
	flags.Bool(keyEnableTCPWatermarks, false, fmt.Sprintf("Enable TCP watermarks detection (requires --%s)", KeyEnableTCP))
	flags.Uint32(keyTCPWatermarksWindowSizeMs, 0, fmt.Sprintf("TCP watermarks window size in milliseconds (requires --%s and --%s)", KeyEnableTCP, keyEnableTCPWatermarks))
	flags.Uint32(keyTCPWatermarksBurstTriggerPercent, 0, fmt.Sprintf("TCP watermarks burst trigger percent (requires --%s and --%s)", KeyEnableTCP, keyEnableTCPWatermarks))
	flags.Uint32(keyTCPWatermarksDipTriggerPercent, 0, fmt.Sprintf("TCP watermarks dip trigger percent (requires --%s and --%s)", KeyEnableTCP, keyEnableTCPWatermarks))
	flags.Bool(keyEnableTCPRTT, false, "Enable TCP RTT observability")
	flags.Uint32(keyTCPRTTHistMin, 0, fmt.Sprintf("Set the minimum value for the RTT histograms (requires --%s and --%s)", KeyEnableTCP, keyEnableTCPRTT))
	flags.Uint32(keyTCPRTTHistMax, 0, fmt.Sprintf("Set the maximum value for the RTT histograms (requires --%s and --%s)", KeyEnableTCP, keyEnableTCPRTT))
	flags.Bool(keyEnableTCPMetrics, true, fmt.Sprintf("Enable TCP metrics (requires --%s)", KeyEnableTCP))
	flags.StringSlice(keyTCPMetricsLabelFilter, []string{}, fmt.Sprintf("TCP metrics label filter (requires --%s and --%s)", KeyEnableTCP, keyEnableTCPMetrics))
	flags.StringSlice(keyTCPDisableEvents, []string{}, fmt.Sprintf("specify TCP events to disable, from listen, connect, stats, and close (requires --%s)", KeyEnableTCP))
	flags.Bool(keyEnableUDP, false, "Enable UDP observability")
	flags.Bool(KeyEnableUDPCgroup, true, fmt.Sprintf("Use Cgroups for UDP (requires --%s)", keyEnableUDP))
	flags.Duration(keyUDPStatsInterval, 0, fmt.Sprintf("Enable and specify interval for UDP statistics (requires --%s)", keyEnableUDP))
	flags.Duration(keyUDPIdleSocketTimeout, 2*time.Minute, "How long a UDP socket should be idle to be considered closed")
	flags.Bool(keyUDPInKernelManaged, false, "Enable in-kernel management for UDP maps. A 5.8.0+ kernel is required.")
	flags.Bool(keyEnableUDPWatermarks, false, fmt.Sprintf("Enable UDP watermarks detection (requires --%s)", keyEnableUDP))
	flags.Uint32(keyUDPWatermarksWindowSizeMs, 0, fmt.Sprintf("UDP watermarks window size in milliseconds (requires --%s and --%s)", keyEnableUDP, keyEnableUDPWatermarks))
	flags.Uint32(keyUDPWatermarksBurstTriggerPercent, 0, fmt.Sprintf("UDP watermarks burst trigger percent (requires --%s and --%s)", keyEnableUDP, keyEnableUDPWatermarks))
	flags.Uint32(keyUDPWatermarksDipTriggerPercent, 0, fmt.Sprintf("UDP watermarks dip trigger percent (requires --%s and --%s)", keyEnableUDP, keyEnableUDPWatermarks))
	flags.Bool(keyEnableUDPMetrics, true, fmt.Sprintf("Enable UDP metrics (requires --%s)", keyEnableUDP))
	flags.StringSlice(keyUDPMetricsLabelFilter, []string{}, fmt.Sprintf("UDP metrics label filter (requires --%s and --%s)", keyEnableUDP, keyEnableUDPMetrics))
	flags.StringSlice(keyUDPDisableEvents, []string{}, fmt.Sprintf("specify UDP events to disable, from listen, connect, stats, and close (requires --%s)", keyEnableUDP))
	flags.Bool(keyEnableICMP, false, "Enable ICMP observability")
	flags.Bool(keyICMPV6Info, false, fmt.Sprintf("Enable ICMPV6 information (requires --%s)", keyEnableICMP))
	flags.Bool(keyEnableIGMP, false, "Enable IGMP observability")
	flags.Bool(keyEnableRawsock, false, "Enable raw socket observability")
	flags.Bool(keyRawsockReportClose, false, fmt.Sprintf("Report raw sockets closing (requires --%s)", keyEnableRawsock))
	flags.Bool(keyEnableRawsockMetrics, true, fmt.Sprintf("Enable raw socket metrics (requires --%s)", keyEnableRawsock))
	flags.StringSlice(keyRawsockMetricsLabelFilter, []string{}, fmt.Sprintf("Raw socket metrics label filter (requires --%s and --%s)", keyEnableRawsock, keyEnableRawsockMetrics))
	flags.Bool(keyEnableDNS, false, fmt.Sprintf("Enable DNS observability (deprecated flag, use --%s instead)", keyEnableUserDNS))
	flags.Bool(keyEnableUserDNS, false, "Enable DNS observability via the userspace DNS parser.")
	flags.Bool(keyDNSReportQuestions, false, fmt.Sprintf("Report DNS questions as well as answers (requires --%s)", keyEnableDNS))
	flags.Bool(keyEnableDNSMetrics, true, fmt.Sprintf("Enable DNS metrics (requires --%s)", keyEnableDNS))
	flags.StringSlice(keyDNSMetricsLabelFilter, []string{}, fmt.Sprintf("DNS metrics label filter (requires --%s and --%s)", keyEnableDNS, keyEnableDNSMetrics))
	flags.String(keyMulticastApp, "", fmt.Sprintf("Specify the multicast app to observe on the ports specified with --%s.", keyMulticastPorts))
	flags.IntSlice(keyMulticastPorts, []int{}, fmt.Sprintf("UDP ports on which to observe the multicast app specified with --%s.", keyMulticastApp))
	flags.Bool(keyEnableMulticastSeqCheck, false, fmt.Sprintf("Enable sequence checking for the multicast app specified with --%s and --%s.", keyMulticastApp, keyMulticastPorts))
	flags.Float64(keyMulticastSamplePercent, 0, fmt.Sprintf("Specify percentage of multicast app packets to report timestamps for the multicast app specified with --%s and --%s.", keyMulticastApp, keyMulticastPorts))
	flags.Bool(keyEnableNetworkWatermarksExitGen, true, fmt.Sprintf("Enable generation of network watermarks exit events from user space when required (requires --%s)", keyNetworkWatermarksExitGenInterval))
	flags.Duration(keyNetworkWatermarksExitGenInterval, 1*time.Second, fmt.Sprintf("Specify the network watermarks exit event generation interval (requires --%s)", keyEnableNetworkWatermarksExitGen))
	flags.Bool(keyEnableNetworkEvents, true, "Enable Network Events from BPF to userspace")
	flags.Bool(keyEnableNetworkInterfaceStats, false, "Enable network interface statistics")
	flags.Duration(keyNetworkInterfaceStatsInterval, NetworkStatInterval, fmt.Sprintf("Network interface statistics interval (requires --%s)", keyEnableNetworkInterfaceStats))
	flags.Bool(keyEnableTLSSensor, false, fmt.Sprintf("Enable TLS observability (requires --%s)", KeyEnableTCP))
	flags.String(keyTLSSensorMode, "cgroup", fmt.Sprintf("Specify the TLS sensor mode (cgroup or socket, requires --%s)", keyEnableTLSSensor))
	flags.IntSlice(keyTLSSensorPorts, []int{}, fmt.Sprintf("Specify the ports to observe TLS over (requires --%s)", keyEnableTLSSensor))
	flags.Bool(keyEnableTLSMetrics, true, fmt.Sprintf("Enable TLS metrics (requires --%s)", keyEnableTLSSensor))
	flags.StringSlice(keyTLSMetricsLabelFilter, []string{}, fmt.Sprintf("TLS metrics label filter (requires --%s and --%s)", keyEnableTLSSensor, keyEnableTLSMetrics))
	flags.Bool(keyEnableNopSensor, false, "Enable the NOP sensor")
	flags.IntSlice(keyNopSensorPorts, []int{}, fmt.Sprintf("Ports to configure Nop sensor (requires --%s)", keyEnableNopSensor))
	flags.Bool(keyEnableHTTPSensor, false, fmt.Sprintf("Enable HTTP observability (requires --%s)", KeyEnableTCP))
	flags.IntSlice(keyHTTPSensorPorts, []int{}, fmt.Sprintf("Specify the ports to observe HTTP over (requires --%s)", keyEnableHTTPSensor))
	flags.Bool(keyEnableHTTP2Handling, true, fmt.Sprintf("Enable HTTP2 handling (requires --%s)", keyEnableHTTPSensor))
	flags.Bool(keyEnableHTTPMetrics, true, fmt.Sprintf("Enable HTTP metrics (requires --%s)", keyEnableHTTPSensor))
	flags.StringSlice(keyHTTPMetricsLabelFilter, []string{}, fmt.Sprintf("HTTP metrics label filter (requires --%s and --%s)", keyEnableHTTPSensor, keyEnableHTTPMetrics))
	flags.Bool(keyEnableAlertsProfiling, false, "Enable profiling for alerts")
	flags.String(keyK8sServiceAccountAuth, "", "Base64 encoded of <API_SERVER>|<TOKEN>|<CA_CERT> to access the k8s API server")
	flags.MarkHidden(keyK8sServiceAccountAuth)

	flags.String(keyTetragonNodeNamespace, "", "The namespace to register tetragon node if required")
	flags.StringArray(KeyAdditionalNodeLabel, []string{}, "Additional node label to add to the local node metadata, specified as key=value. Can be specified multiple times")
	flags.String(KeyPolicyDir, eedefaults.DefaultPoliciesDir, "Directory for all kind of policies to load at startup. Only single depth level files are supported")
	// Mark other policiesDir options as deprecated
	_ = flags.MarkDeprecated(option.KeyTracingPolicyDir, "Deprecated in v1.18.0, to be removed in v1.20.0. Use "+KeyPolicyDir+"instead.")
	_ = flags.MarkDeprecated(keyNetworkPolicyDir, "Deprecated in v1.18.0, to be removed in v1.20.0. Use "+KeyPolicyDir+"instead.")
	_ = flags.MarkDeprecated(keyEnableDNS, "use --"+keyEnableUserDNS+" instead. Deprecated in v1.19.0, to be removed in v1.21.0.")
	_ = flags.MarkDeprecated(KeyEnableDnsDebug, "use --"+keyEnableUserDNSDebug+" instead. Deprecated in v1.19.0, to be removed in v1.21.0.")
}

func ReadAndValidateEnterpriseFlags() error {
	if err := readAndSetEnterpriseFlags(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	err := validateConfig(Config)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	return nil
}

func readAndSetEnterpriseFlags() error {
	Config.Environment = viper.GetString(KeyEnvironment)
	Config.OCSFExportFilename = viper.GetString(KeyOCSFExportFilename)
	Config.OCSFExportServer = viper.GetString(KeyOCSFExportServer)
	Config.EnableApplicationModel = viper.GetBool(KeyEnableApplicationModel)
	Config.AppModelTrackExecIds = viper.GetBool(KeyAppModelTrackExecIds)
	Config.EnableSyscallTracking = viper.GetBool(KeyEnableSyscallTracking)
	Config.ApplicationModelExportInterval = viper.GetDuration(KeyApplicationModelExportInterval)
	Config.ApplicationModelExportFilename = viper.GetString(KeyApplicationModelExportFilename)
	Config.ApplicationModelExportFileMaxSizeMB = viper.GetInt(KeyApplicationModelExportFileMaxSizeMB)
	Config.ApplicationModelExportFileMaxBackups = viper.GetInt(KeyApplicationModelExportFileMaxBackups)
	Config.ApplicationModelExportFileCompress = viper.GetBool(KeyApplicationModelExportFileCompress)
	Config.ApplicationModelSplitMaxHostProcs = viper.GetInt(KeyApplicationModelSplitMaxHostProcs)
	Config.ApplicationModelExportFragments = viper.GetBool(KeyApplicationModelExportFragments)
	Config.ApplicationModelRetentionDuration = viper.GetDuration(KeyApplicationModelRetentionDuration)
	Config.TelemetryExportFilename = viper.GetString(KeyTelemetryExportFilename)
	endpointStr := viper.GetString(KeySplunkHECEndpoint)
	if endpointStr == "" {
		Config.SplunkHECEndpoint = nil
	} else {
		u, err := url.Parse(endpointStr)
		if err != nil {
			return fmt.Errorf("invalid value for --%s: %w", KeySplunkHECEndpoint, err)
		}
		Config.SplunkHECEndpoint = u
	}
	Config.SplunkHECToken = viper.GetString(KeySplunkHECToken)
	Config.SplunkHECMaxContentLength = viper.GetInt(KeySplunkHECMaxContentLength)
	Config.SplunkHECFlushInterval = viper.GetDuration(KeySplunkHECFlushInterval)
	Config.SplunkHECTimeout = viper.GetDuration(KeySplunkHECTimeout)
	Config.SplunkHECSourcetypes = viper.GetStringSlice(KeySplunkHECSourcetypes)
	Config.EnableSplunkHECDebug = viper.GetBool(KeyEnableSplunkHECDebug)
	Config.ConnectionLogFileName = viper.GetString(KeyConnectionLogFilename)
	Config.DetachOldBpf = viper.GetBool(KeyDetatchOldBPF)
	Config.DnsCacheSize = viper.GetInt(KeyDnsCacheSize)
	Config.ProcessTreeCacheSize = viper.GetInt(KeyApplicationModelCacheSize)
	Config.EndpointCacheSize = viper.GetInt(KeyEndpointCacheSize)
	Config.BpfEndpointCacheSize = viper.GetInt(KeyBpfEndpointCacheSize)
	Config.TlsCacheSize = viper.GetInt(KeyTlsCacheSize)
	Config.TcpCacheSize = viper.GetInt(KeyTcpCacheSize)
	Config.NetNsCacheSize = viper.GetInt(KeyNetNsCacheSize)
	Config.FimFifoPath = viper.GetString(KeyFimFifoPath)
	Config.FimFifoLocalPath = viper.GetString(KeyFimFifoLocalPath)
	Config.FimRuntimeEndpoint = viper.GetString(KeyFimRuntimeEndpoint)
	Config.FimMaxFileSizeDigest = viper.GetInt64(keyFimMaxFileSizeDigest)
	Config.FimMaxTimeoutDigestSec = viper.GetInt64(keyFimTimeoutDigest)
	Config.FlowExportFilename = viper.GetString(KeyFlowExportFilename)
	Config.FlowExportFileMaxSizeMB = viper.GetInt(KeyFlowExportFileMaxSizeMB)
	Config.FlowExportFileMaxBackups = viper.GetInt(KeyFlowExportFileMaxBackups)
	Config.FlowExportFileCompress = viper.GetBool(KeyFlowExportFileCompress)
	Config.DisableLayer3 = viper.GetBool(KeyDisableLayer3)
	Config.Layer3SocketMapSize = viper.GetInt(keyLayer3SocketMapSize)
	Config.TCPSocketMapSize = viper.GetInt(keyTCPSocketMapSize)
	Config.UDPSocketMapSize = viper.GetInt(keyUDPSocketMapSize)
	Config.NetworkWatermarksMapSize = viper.GetInt(keyNetworkWatermarksMapSize)
	Config.ICMPSocketMapSize = viper.GetInt(keyICMPSocketMapSize)
	Config.HTTPContextMapSize = viper.GetInt(keyHTTPContextMapSize)
	Config.TLSContextMapSize = viper.GetInt(keyTLSContextMapSize)
	Config.EnableIcmpTracking = viper.GetBool(keyEnableIcmpTracking)
	Config.EnablePolicyK8sWatcher = viper.GetBool(keyEnablePolicyK8sWatcher)
	Config.EnableSandboxPolicies = viper.GetBool(keyEnableSandboxPolicies)
	Config.SandboxPolicies = viper.GetStringSlice(keySandboxPolicy)
	Config.NetworkPolicies = viper.GetStringSlice(keyNetworkPolicy)
	Config.NetworkPoliciesDir = viper.GetString(keyNetworkPolicyDir)
	Config.PoliciesDir = viper.GetString(KeyPolicyDir)
	Config.EnableAlerts = viper.GetBool(keyEnableAlerts)
	Config.AlertsExportDir = viper.GetString(keyAlertsExportDir)
	Config.AlertsExportFilename = viper.GetString(keyAlertsExportFilename)
	Config.DebugX = viper.GetStringSlice(keyDebugX)
	Config.EnableAWSSonar = viper.GetBool(keyEnableAWSSonar)
	Config.AWSSonarRegion = viper.GetString(keyAWSSonarRegion)
	if viper.IsSet(keyEnableUserDNSDebug) {
		Config.EnableUserDNSDebug = viper.GetBool(keyEnableUserDNSDebug)
	} else {
		Config.EnableUserDNSDebug = viper.GetBool(KeyEnableDnsDebug)
	}
	Config.EnableCilium = viper.GetBool(KeyEnableCiliumAPI)
	Config.ProcessCacheStaleInterval = viper.GetDuration(KeyProcessCacheStaleInterval)
	Config.EnableBPFDNSParser = viper.GetBool(keyEnableBPFDNSParser)
	Config.BPFDNSParserMaxPendingRequests = viper.GetUint32(keyBPFDNSParserMaxPendingRequests)
	Config.EnableBPFDNSPerPod = viper.GetBool(KeyEnableBPFDNSPerPod)
	Config.BPFDNSPerPodPrealloc = viper.GetUint32(KeyBPFDNSPerPodPrealloc)
	Config.BPFDNSPerPodThresold = viper.GetUint32(KeyBPFDNSPerPodThreshold)
	Config.DNSPorts = viper.GetIntSlice(KeyDNSPorts)
	Config.DNSStatsPerSocket = viper.GetBool(keyDNSStatsPerSocket)

	Config.EnableFimDispatcher = viper.GetBool(KeyEnableFimDispatcher)
	Config.MandateConf.URL = viper.GetString(KeyMandateURL)
	Config.MandateConf.RefreshPeriod = viper.GetDuration(KeyMandateRefreshPeriod)
	Config.EnableTCP = viper.GetBool(KeyEnableTCP)
	Config.TCPStatsInterval = viper.GetDuration(keyTCPStatsInterval)
	Config.EnableTCPWatermarks = viper.GetBool(keyEnableTCPWatermarks)
	Config.TCPWatermarksWindowSizeMs = viper.GetUint32(keyTCPWatermarksWindowSizeMs)
	Config.TCPWatermarksBurstTriggerPercent = viper.GetUint32(keyTCPWatermarksBurstTriggerPercent)
	Config.TCPWatermarksDipTriggerPercent = viper.GetUint32(keyTCPWatermarksDipTriggerPercent)
	Config.EnableTCPRTT = viper.GetBool(keyEnableTCPRTT)
	Config.TCPRTTHistMin = viper.GetUint32(keyTCPRTTHistMin)
	Config.TCPRTTHistMax = viper.GetUint32(keyTCPRTTHistMax)
	Config.EnableTCPMetrics = viper.GetBool(keyEnableTCPMetrics)
	Config.TCPMetricsLabelFilter = viper.GetStringSlice(keyTCPMetricsLabelFilter)
	Config.TCPDisableEvents = viper.GetStringSlice(keyTCPDisableEvents)
	for _, e := range Config.TCPDisableEvents {
		switch e {
		case "listen":
			Config.TCPDisableListenEvents = true
		case "connect":
			Config.TCPDisableConnectEvents = true
		case "accept":
			Config.TCPDisableAcceptEvents = true
		case "close":
			Config.TCPDisableCloseEvents = true
		}
	}
	Config.EnableUDP = viper.GetBool(keyEnableUDP)
	Config.EnableUDPCGroup = viper.GetBool(KeyEnableUDPCgroup)
	Config.UDPStatsInterval = viper.GetDuration(keyUDPStatsInterval)
	Config.UDPIdleSocketTimeout = viper.GetDuration(keyUDPIdleSocketTimeout)
	Config.UDPInKernelManaged = viper.GetBool(keyUDPInKernelManaged)
	Config.EnableUDPWatermarks = viper.GetBool(keyEnableUDPWatermarks)
	Config.UDPWatermarksWindowSizeMs = viper.GetUint32(keyUDPWatermarksWindowSizeMs)
	Config.UDPWatermarksBurstTriggerPercent = viper.GetUint32(keyUDPWatermarksBurstTriggerPercent)
	Config.UDPWatermarksDipTriggerPercent = viper.GetUint32(keyUDPWatermarksDipTriggerPercent)
	Config.EnableUDPMetrics = viper.GetBool(keyEnableUDPMetrics)
	Config.UDPMetricsLabelFilter = viper.GetStringSlice(keyUDPMetricsLabelFilter)
	Config.UDPDisableEvents = viper.GetStringSlice(keyUDPDisableEvents)
	for _, e := range Config.UDPDisableEvents {
		switch e {
		case "listen":
			Config.UDPDisableListenEvents = true
		case "connect":
			Config.UDPDisableConnectEvents = true
		case "stats":
			Config.UDPDisableStatsEvents = true
		case "close":
			Config.UDPDisableCloseEvents = true
		}
	}
	Config.EnableICMP = viper.GetBool(keyEnableICMP)
	Config.ICMPV6Info = viper.GetBool(keyICMPV6Info)
	Config.EnableIGMP = viper.GetBool(keyEnableIGMP)
	Config.EnableRawsock = viper.GetBool(keyEnableRawsock)
	Config.RawsockReportClose = viper.GetBool(keyRawsockReportClose)
	Config.EnableRawsockMetrics = viper.GetBool(keyEnableRawsockMetrics)
	Config.RawsockMetricsLabelFilter = viper.GetStringSlice(keyRawsockMetricsLabelFilter)
	if viper.IsSet(keyEnableUserDNS) {
		Config.EnableUserDNS = viper.GetBool(keyEnableUserDNS)
	} else {
		Config.EnableUserDNS = viper.GetBool(keyEnableDNS)
	}
	Config.DNSReportQuestions = viper.GetBool(keyDNSReportQuestions)
	Config.EnableDNSMetrics = viper.GetBool(keyEnableDNSMetrics)
	Config.DNSMetricsLabelFilter = viper.GetStringSlice(keyDNSMetricsLabelFilter)
	Config.MulticastApp = viper.GetString(keyMulticastApp)
	// Set the AppID from the app string. If not found, this will default to 0 (MulticastNoApp)
	Config.MulticastAppID = multicastAppID[Config.MulticastApp]
	Config.MulticastPorts = viper.GetIntSlice(keyMulticastPorts)
	Config.MulticastSeqCheck = viper.GetBool(keyEnableMulticastSeqCheck)
	Config.MulticastSamplePercent = viper.GetFloat64(keyMulticastSamplePercent)
	Config.EnableNetworkWatermarksExitGen = viper.GetBool(keyEnableNetworkWatermarksExitGen)
	Config.NetworkWatermarksExitGenInterval = viper.GetDuration(keyNetworkWatermarksExitGenInterval)
	Config.EnableNetworkEvents = viper.GetBool(keyEnableNetworkEvents)
	Config.EnableNetworkInterfaceStats = viper.GetBool(keyEnableNetworkInterfaceStats)
	Config.NetworkInterfaceStatsInterval = viper.GetDuration(keyNetworkInterfaceStatsInterval)
	Config.EnableTLSSensor = viper.GetBool(keyEnableTLSSensor)
	Config.TLSSensorMode = viper.GetString(keyTLSSensorMode)
	Config.TLSSensorPorts = viper.GetIntSlice(keyTLSSensorPorts)
	Config.EnableTLSMetrics = viper.GetBool(keyEnableTLSMetrics)
	Config.TLSMetricsLabelFilter = viper.GetStringSlice(keyTLSMetricsLabelFilter)
	Config.EnableNopSensor = viper.GetBool(keyEnableNopSensor)
	Config.NopSensorPorts = viper.GetIntSlice(keyNopSensorPorts)
	Config.EnableHTTPSensor = viper.GetBool(keyEnableHTTPSensor)
	Config.HTTPSensorPorts = viper.GetIntSlice(keyHTTPSensorPorts)
	Config.EnableHTTP2Handling = viper.GetBool(keyEnableHTTP2Handling)
	Config.EnableHTTPMetrics = viper.GetBool(keyEnableHTTPMetrics)
	Config.HTTPMetricsLabelFilter = viper.GetStringSlice(keyHTTPMetricsLabelFilter)
	Config.EnableAlertProfiling = viper.GetBool(keyEnableAlertsProfiling)
	// Layer 3 protocols can be enabled on the CLI or in policies. If any were enabled on the CLI
	// then we ignore enable/disable in policies.
	if Config.EnableTCP || Config.EnableUDP || Config.EnableICMP || Config.EnableIGMP || Config.EnableRawsock || Config.EnableUserDNS {
		Config.Layer3CLIEnable = true
	}

	Config.K8sServiceAccountAuth = viper.GetString(keyK8sServiceAccountAuth)
	Config.NodeNamespace = viper.GetString(keyTetragonNodeNamespace)
	additionalNodeLabels, err := parseAdditionalNodeLabels(viper.GetStringSlice(KeyAdditionalNodeLabel))
	if err != nil {
		return err
	}
	Config.AdditionalNodeLabels = additionalNodeLabels
	return nil
}

func parseAdditionalNodeLabels(values []string) (map[string]string, error) {
	labels := make(map[string]string, len(values))
	for _, value := range values {
		key, labelValue, ok := strings.Cut(value, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("--%s must be specified as key=value", KeyAdditionalNodeLabel)
		}
		if _, exists := labels[key]; exists {
			return nil, fmt.Errorf("duplicate --%s key %q", KeyAdditionalNodeLabel, key)
		}
		labels[key] = labelValue
	}
	return labels, nil
}

func validateConfig(config config) error {
	if err := platformValidateConfig(config); err != nil {
		return err
	}

	if config.Layer3CLIEnable && config.DisableLayer3 {
		return fmt.Errorf("switch config --%s set together with a switch that enables layer3", KeyDisableLayer3)
	}

	if (config.SplunkHECEndpoint == nil) != (config.SplunkHECToken == "") {
		return fmt.Errorf("--%s and --%s must be set together", KeySplunkHECEndpoint, KeySplunkHECToken)
	}
	if config.SplunkHECEndpoint != nil {
		u := config.SplunkHECEndpoint
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("invalid value for --%s: scheme must be http or https", KeySplunkHECEndpoint)
		}
		if u.Host == "" {
			return fmt.Errorf("invalid value for --%s: missing host", KeySplunkHECEndpoint)
		}
	}

	if config.SplunkHECMaxContentLength <= splunkHECMinContentLength {
		return fmt.Errorf("--%s must be greater than %d bytes", KeySplunkHECMaxContentLength, splunkHECMinContentLength)
	}

	if config.SplunkHECFlushInterval < splunkHECMinFlushInterval {
		return fmt.Errorf("--%s must be at least %s", KeySplunkHECFlushInterval, splunkHECMinFlushInterval)
	}

	if config.SplunkHECTimeout < splunkHECMinTimeout {
		return fmt.Errorf("--%s must be at least %s", KeySplunkHECTimeout, splunkHECMinTimeout)
	}

	for _, sourcetype := range config.SplunkHECSourcetypes {
		if !slices.Contains(splunkHECValidSourcetypes, sourcetype) {
			return fmt.Errorf("invalid value for --%s: %q is not a valid sourcetype, valid values are %v", KeySplunkHECSourcetypes, sourcetype, splunkHECValidSourcetypes)
		}
	}

	if !config.EnableTCP {
		if config.EnableTCPWatermarks || config.EnableTCPRTT {
			return fmt.Errorf("TCP observability requires --%s", KeyEnableTCP)
		}
	}

	if config.EnableTCPWatermarks {
		if config.TCPWatermarksWindowSizeMs == 0 {
			return fmt.Errorf("TCP watermarks observability requires a window size > 0, set with --%s", keyTCPWatermarksWindowSizeMs)
		}
		if config.TCPWatermarksBurstTriggerPercent == 0 && config.TCPWatermarksDipTriggerPercent == 0 {
			return fmt.Errorf("TCP watermarks requires a burst trigger percent > 0 or a dip trigger percent > 0, specify them with --%s or --%s", keyTCPWatermarksBurstTriggerPercent, keyTCPWatermarksDipTriggerPercent)
		}
	}

	if !config.EnableTCPRTT {
		if config.TCPRTTHistMin > 0 || config.TCPRTTHistMax > 0 {
			return fmt.Errorf("TCP RTT observability requires --%s", keyEnableTCPRTT)
		}
	}

	if !config.EnableTCP && len(config.TCPDisableEvents) > 0 {
		return fmt.Errorf("TCP events disabled but TCP observability not enabled")
	}

	for _, e := range config.TCPDisableEvents {
		switch e {
		case "listen", "connect", "accept", "close":
		default:
			return fmt.Errorf("invalid TCP disabled event %s; valid events are listen, connect, accept, and close", e)
		}
	}

	if !config.EnableUDP {
		if config.EnableUDPWatermarks {
			return fmt.Errorf("UDP observability requires --%s", keyEnableUDP)
		}
	}

	if config.EnableUserDNS {
		// The DNS parser is loaded alongside the UDP sensor
		if !config.EnableUDP {
			return fmt.Errorf("the DNS parser requires --%s", keyEnableUDP)
		}
	}

	if config.EnableBPFDNSParser {
		// The BPF DNS parser is loaded alongside the UDP sensor
		if !config.EnableUDP {
			return fmt.Errorf("the BPF DNS parser requires --%s", keyEnableUDP)
		}
	}

	if config.EnableBPFDNSPerPod {
		if !config.EnableBPFDNSParser {
			return fmt.Errorf("the BPF DNS parser per Pod map feature requires --%s", keyEnableBPFDNSParser)
		}

		// SupportProcessTree is used to discriminate against using the
		// sockops or tracing program. The issue is that sockops don't
		// support the cgroup ancestor helper between 5.15 and 6.4 and
		// thus these can't be combined.
		//
		// As a workaround if needed, fentry could be used to replace
		// sockops reliably for 5.15 to 6.4.
		if utils.SupportProcessTree() && !utils.SockopsSupportsCgroupAncestorHelper() {
			return fmt.Errorf("the BPF DNS parser per Pod map feature requires sockops to support bpf_get_current_ancestor_cgroup_id (from v6.4)")

		}
	}

	if len(config.DNSPorts) > networkapi.UdpMaxDnsPorts {
		return fmt.Errorf("invalid number of DNS ports len(%v)=%d, the maximum number of port is %d", config.DNSPorts, len(config.DNSPorts), networkapi.UdpMaxDnsPorts)
	}
	for _, port := range config.DNSPorts {
		if port < 0 || port > math.MaxUint16 {
			return fmt.Errorf("invalid DNS port %d, must be included between 0 and 65535", port)
		}
	}

	if !config.EnableUDP && len(config.UDPDisableEvents) > 0 {
		return fmt.Errorf("UDP events disabled but UDP observability not enabled")
	}

	for _, e := range config.UDPDisableEvents {
		switch e {
		case "listen", "connect", "stats", "close":
		default:
			return fmt.Errorf("invalid UDP disabled event %s; valid events are listen, connect, stats, and close", e)
		}
	}

	if config.EnableUDPWatermarks {
		if config.UDPWatermarksWindowSizeMs == 0 {
			return fmt.Errorf("UDP watermarks observability requires a window size > 0, set with --%s", keyUDPWatermarksWindowSizeMs)
		}
		if config.UDPWatermarksBurstTriggerPercent == 0 && config.UDPWatermarksDipTriggerPercent == 0 {
			return fmt.Errorf("UDP watermarks requires a burst trigger percent > 0 or a dip trigger percent > 0, specify them with --%s or --%s", keyUDPWatermarksBurstTriggerPercent, keyUDPWatermarksDipTriggerPercent)
		}
	}

	if len(config.MulticastPorts) > networkapi.UdpMaxMulticastPorts {
		return fmt.Errorf("invalid number of multicast ports len(%v)=%d, the maximum number of port is %d", config.MulticastPorts, len(config.MulticastPorts), networkapi.UdpMaxMulticastPorts)
	}
	for _, port := range config.MulticastPorts {
		if port < 0 || port > math.MaxUint16 {
			return fmt.Errorf("invalid multicast port %d, must be included between 0 and 65535", port)
		}
	}
	if config.MulticastApp != "" && config.MulticastAppID == MulticastNoApp {
		return fmt.Errorf("invalid multicast app: %s", config.MulticastApp)
	}
	if config.MulticastSamplePercent < 0 || config.MulticastSamplePercent > 100 {
		return fmt.Errorf("invalid multicast sample percent: %f", config.MulticastSamplePercent)
	}
	// if an app was specified, but no ports, OR
	// if an app wasn't specified, but ports were
	// (using != as XOR)
	if (config.MulticastAppID != MulticastNoApp) != (len(config.MulticastPorts) > 0) {
		return fmt.Errorf("multicast observability requires the app to be specified with --%s and the ports to be specified with --%s", keyMulticastApp, keyMulticastPorts)
	}
	// if multicast sequence checking is enabled, but the app or ports weren't specified
	if config.MulticastSeqCheck && (config.MulticastAppID == MulticastNoApp || len(config.MulticastPorts) == 0) {
		return fmt.Errorf("multicast observability requires the app to be specified with --%s and the ports to be specified with --%s", keyMulticastApp, keyMulticastPorts)
	}
	// if multicast sample percent is specified, but the app or ports weren't specified
	if config.MulticastSamplePercent > 0 && (config.MulticastAppID == MulticastNoApp || len(config.MulticastPorts) == 0) {
		return fmt.Errorf("multicast observability requires the app to be specified with --%s and the ports to be specified with --%s", keyMulticastApp, keyMulticastPorts)
	}
	// multicast inspection (sequence checking and packet sampling) only available from kernel >=v6.12
	if (config.MulticastSeqCheck || config.MulticastSamplePercent > 0) && !kernels.MinKernelVersion("6.12") {
		return fmt.Errorf("multicast sequence checking and packet sampling require kernel >=v6.12")
	}

	if (config.EnableIcmpTracking || config.ICMPV6Info) && !config.EnableICMP {
		return fmt.Errorf("ICMP observability requires --%s", keyEnableICMP)
	}

	if !config.EnableRawsock {
		if config.RawsockReportClose {
			return fmt.Errorf("rawsock close reports require --%s", keyEnableRawsock)
		}
	}

	if config.EnableNetworkWatermarksExitGen && config.NetworkWatermarksExitGenInterval == 0 {
		return fmt.Errorf("network watermarks exit event generation requires an interval > 0, specified with --%s", keyNetworkWatermarksExitGenInterval)
	}

	if config.EnableNetworkInterfaceStats && config.NetworkInterfaceStatsInterval == 0 {
		return fmt.Errorf("network interface stats requires an interval > 0, specified with --%s", keyNetworkInterfaceStatsInterval)
	}

	if config.EnableTLSSensor {
		if !config.EnableTCP {
			return fmt.Errorf("TLS observability requires TCP enabled with --%s", KeyEnableTCP)
		}
		if config.TLSSensorMode != "cgroup" && config.TLSSensorMode != "socket" {
			return fmt.Errorf("TLS sensor mode must be one of 'cgroup' or 'socket'")
		}
		if len(config.TLSSensorPorts) == 0 {
			return fmt.Errorf("TLS observability requires the ports to be specified with --%s", keyTLSSensorPorts)
		}
		if len(config.TLSSensorPorts) > TLS_MAX_PORTS {
			return fmt.Errorf("TLS observability only supports up to %d ports, got %d", TLS_MAX_PORTS, len(config.TLSSensorPorts))
		}
	} else {
		if len(config.TLSSensorPorts) > 0 {
			return fmt.Errorf("TLS sensor ports specified but TLS sensor not enabled. Enable it with --%s", keyEnableTLSSensor)
		}
	}

	if config.EnableNopSensor {
		if len(config.NopSensorPorts) == 0 {
			return fmt.Errorf("NOP observability requires the ports to be specified with --%s", keyNopSensorPorts)
		}
		if len(config.NopSensorPorts) > TLS_MAX_PORTS {
			return fmt.Errorf("NOP observability only supports up to %d ports, got %d", TLS_MAX_PORTS, len(config.NopSensorPorts))
		}
	} else {
		if len(config.NopSensorPorts) > 0 {
			return fmt.Errorf("NOP sensor ports specified but NOP sensor not enabled. Enable it with --%s", keyEnableNopSensor)
		}
	}

	if config.EnableHTTPSensor {
		if !config.EnableTCP {
			return fmt.Errorf("HTTP observability requires TCP enabled with --%s", KeyEnableTCP)
		}
		if len(config.HTTPSensorPorts) == 0 {
			return fmt.Errorf("HTTP observability requires the ports to be specified with --%s", keyHTTPSensorPorts)
		}
		if len(config.HTTPSensorPorts) > TLS_MAX_PORTS {
			return fmt.Errorf("HTTP observability only supports up to %d ports, got %d", TLS_MAX_PORTS, len(config.HTTPSensorPorts))
		}
	} else {
		if len(config.HTTPSensorPorts) > 0 {
			return fmt.Errorf("HTTP sensor ports specified but HTTP sensor not enabled. Enable it with --%s", keyEnableHTTPSensor)
		}
	}

	// Network policies can be loaded via the k8s resource watcher as well
	if (len(config.NetworkPolicies) != 0 || config.NetworkPoliciesDir != "") && !config.EnableTCP {
		return fmt.Errorf("network policies require --%s", KeyEnableTCP)
	}

	if config.EnableSyscallTracking && !config.EnableApplicationModel {
		return fmt.Errorf("system call tracking requires --%s", KeyEnableApplicationModel)
	}

	if config.EnableApplicationModel && option.Config.DisableProcessCache {
		return fmt.Errorf("--%s cannot be used together with --%s", KeyEnableApplicationModel, option.KeyDisableProcessCache)
	}

	if config.Environment != "" {
		if !slices.Contains(environments, config.Environment) {
			return fmt.Errorf("invalid environment '%s', valid values are %s", config.Environment, environments)
		}
	}

	if config.ApplicationModelSplitMaxHostProcs < 2 {
		return fmt.Errorf("%s must be greater than 1", KeyApplicationModelSplitMaxHostProcs)
	}

	return nil
}
