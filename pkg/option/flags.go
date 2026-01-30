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
	"slices"
	"time"

	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	eedefaults "github.com/isovalent/hubble-fgs/pkg/defaults"

	fm "github.com/isovalent/hubble-fgs/pkg/sensors/file/utils"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

const (
	KeyEnvironment                    = "environment"
	KeyOCSFExportFilename             = "ocsf-export-filename"
	KeyOCSFExportServer               = "ocsf-export-server"
	KeyOCSFExportFileMaxSizeMB        = "ocsf-export-file-max-size-mb"
	KeyOCSFExportFileMaxBackups       = "ocsf-export-file-max-backups"
	KeyOCSFExportFileCompress         = "ocsf-export-file-compress"
	KeyFlowExportFilename             = "flow-export-filename"
	KeyFlowExportFileMaxSizeMB        = "flow-export-file-max-size-mb"
	KeyFlowExportFileMaxBackups       = "flow-export-file-max-backups"
	KeyFlowExportFileCompress         = "flow-export-file-compress"
	KeyFimFifoPath                    = "fim-fifo-path"
	KeyFimFifoLocalPath               = "fim-fifo-local-path"
	KeyFimRuntimeEndpoint             = "fim-runtime-endpoint"
	keyFimMaxFileSizeDigest           = "fim-max-file-size-digest"
	keyFimTimeoutDigest               = "fim-timeout-digest"
	KeyDnsCacheSize                   = "dns-cache-size"
	KeyEndpointCacheSize              = "endpoint-cache-size"
	KeyBpfEndpointCacheSize           = "bpf-endpoint-cache-size"
	KeyTlsCacheSize                   = "tls-cache-size"
	KeyTcpCacheSize                   = "tcp-cache-size"
	KeyNetNsCacheSize                 = "net-ns-cache-size"
	KeyDetatchOldBPF                  = "detach-old-bpf"
	KeyEnableApplicationModel         = "enable-application-model"
	KeyEnableSyscallTracking          = "enable-syscall-tracking"
	KeyApplicationModelCacheSize      = "application-model-cache-size"
	KeyApplicationModelExportInterval = "application-model-export-interval"
	KeyApplicationModelExportFilename = "application-model-export-filename"
	KeyTelemetryExportFilename        = "telemetry-export-filename"
	KeyConnectionLogFilename          = "connection-log-filename"
	keyEnableIcmpTracking             = "enable-icmp-tracking"
	keyEnablePolicyK8sWatcher         = "enable-policy-k8swatcher"
	keyEnableSandboxPolicies          = "enable-sandboxpolicies"
	keySandboxPolicy                  = "sandbox-policy"
	keyNetworkPolicy                  = "network-policy"
	keyNetworkPolicyDir               = "network-policy-dir"
	keyEnableAlerts                   = "enable-alerts"
	keyAlertsExportDir                = "alerts-export-dir"
	keyAlertsExportFilename           = "alerts-export-filename"
	keyDebugX                         = "debugx"
	keyEnableAWSSonar                 = "enable-aws-sonar"
	keyAWSSonarRegion                 = "aws-sonar-region"
	KeyEnableCiliumAPI                = "enable-cilium-api"
	KeyEnableDnsDebug                 = "enable-dns-debug"
	KeyProcessCacheStaleInterval      = "process-cache-stale-interval"
	keyEnableBPFDNSParser             = "enable-bpf-dns-parser"
	keyBPFDNSParserMaxPendingRequests = "bpf-dns-parser-max-pending-requests"
	KeyEnableBPFDNSPerPod             = "enable-bpf-dns-parser-per-pod"
	KeyBPFDNSPerPodPrealloc           = "bpf-dns-parser-per-pod-prealloc"
	KeyBPFDNSPerPodThreshold          = "bpf-dns-parser-per-pod-threshold"
	KeyDNSPorts                       = "dns-ports"
	keyDNSStatsPerSocket              = "dns-stats-per-socket"
	KeyEnableFimDispatcher            = "fim-enable-dispatcher"
	KeyMandateURL                     = "mandate-url"
	KeyMandateRefreshPeriod           = "mandate-refresh-period"
	KeyEnableTCP                      = "enable-tcp"
	keyEnableTCPRTT                   = "enable-tcp-rtt"
	keyEnableUDP                      = "enable-udp"
	keyEnableLatency                  = "enable-latency"
	keyEnableICMP                     = "enable-icmp"
	keyEnableRawsock                  = "enable-rawsock"
	keyEnableDNS                      = "enable-dns"
	keyUDPIdleSocketTimeout           = "udp-idle-socket-timeout"
	keyUDPInKernelManaged             = "udp-in-kernel-managed"
	keyEnableNetworkEvents            = "enable-network-events"
	keyEnableAlertsProfiling          = "enable-alerts-profiling"
	keyK8sServiceAccountAuth          = "k8s-service-account-auth"
	keyTetragonNodeNamespace          = "node-namespace"
	KeyPolicyDir                      = "policy-dir"

	EnvironmentAWS        = "aws"
	EnvironmentAzure      = "azure"
	EnvironmentGCloud     = "gcloud"
	EnvironmentKubernetes = "kubernetes"
)

var (
	environments = []string{EnvironmentAWS, EnvironmentAzure, EnvironmentGCloud, EnvironmentKubernetes}

	redactedKeys = []string{
		keyK8sServiceAccountAuth,
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
	flags.Lookup(option.KeyCompatibilitySyscall64SizeType).Usage =
		"syscall64 type will produce output of type size (compatibility flag, will be removed in v1.16)"

	flags.Lookup(option.KeyEnableTracingPolicyCRD).Hidden = true
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
	flags.Bool(KeyEnableSyscallTracking, false, "Track system calls in the application model. Application model must be enabled for this to work")
	// Experimental flags to periodically export process model to export JSON file.
	flags.Duration(KeyApplicationModelExportInterval, 0, "Interval at which to export application model as JSON.")
	flags.MarkHidden(KeyApplicationModelExportInterval)
	flags.String(KeyApplicationModelExportFilename, "", "Filename for application model JSON export. Set to \"\" to disable.")
	flags.MarkHidden(KeyApplicationModelExportFilename)
	flags.String(KeyTelemetryExportFilename, "", "Filename for telemetry JSON export. Set to \"\" to disable. To enable telemetry export, --"+KeyEnableApplicationModel+" flag must be set to true. Telemetry export uses the export interval specified by --"+KeyApplicationModelExportInterval+" flag.")
	flags.String(KeyConnectionLogFilename, "", "Filename for connection log. Set to \"\" to disable.")
	flags.MarkHidden(KeyConnectionLogFilename)
	flags.Int(KeyDnsCacheSize, 1024, "Set the size of the internal DNS cache. Higher values enable Tetragon to keep track of more destination names before evicting old ones")
	flags.Int(KeyApplicationModelCacheSize, 65536, "Set the size of the BPF data structure to store application model and statistics. Higher values enable Tetragon to keep track of more processes before evicting old ones")
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
	flags.Bool(KeyEnableDnsDebug, false, "Enable DNS debug messages")
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
	flags.Bool(keyEnableTCPRTT, false, "Enable TCP RTT observability")
	flags.Bool(keyEnableUDP, false, "Enable UDP observability")
	flags.Bool(keyEnableLatency, false, fmt.Sprintf("Enable TCP and/or UDP latency observability (requires --%s and/or --%s)", KeyEnableTCP, keyEnableUDP))
	flags.Bool(keyEnableICMP, false, "Enable ICMP observability")
	flags.Bool(keyEnableRawsock, false, "Enable raw socket observability")
	flags.Bool(keyEnableDNS, false, "Enable DNS observability")
	flags.Duration(keyUDPIdleSocketTimeout, 2*time.Minute, "How long a UDP socket should be idle to be considered closed")
	flags.Bool(keyUDPInKernelManaged, false, "Enable in-kernel management for UDP maps. A 5.8.0+ kernel is required.")
	flags.Bool(keyEnableNetworkEvents, true, "Enable Network Events from BPF to userspace")
	flags.Bool(keyEnableAlertsProfiling, false, "Enable profiling for alerts")
	flags.String(keyK8sServiceAccountAuth, "", "Base64 encoded of <API_SERVER>|<TOKEN>|<CA_CERT> to access the k8s API server")
	flags.MarkHidden(keyK8sServiceAccountAuth)

	flags.String(keyTetragonNodeNamespace, "", "The namespace to register tetragon node if required")
	flags.String(KeyPolicyDir, eedefaults.DefaultPoliciesDir, "Directory for all kind of policies to load at startup. Only single depth level files are supported")
	// Mark other policiesDir options as deprecated
	_ = flags.MarkDeprecated(option.KeyTracingPolicyDir, "Deprecated in v1.18.0, to be removed in v1.20.0. Use "+KeyPolicyDir+"instead.")
	_ = flags.MarkDeprecated(keyNetworkPolicyDir, "Deprecated in v1.18.0, to be removed in v1.20.0. Use "+KeyPolicyDir+"instead.")
}

func ReadAndValidateEnterpriseFlags() error {
	readAndSetEnterpriseFlags()

	err := validateConfig(Config)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	return nil
}

func readAndSetEnterpriseFlags() {
	Config.Environment = viper.GetString(KeyEnvironment)
	Config.OCSFExportFilename = viper.GetString(KeyOCSFExportFilename)
	Config.OCSFExportServer = viper.GetString(KeyOCSFExportServer)
	Config.EnableApplicationModel = viper.GetBool(KeyEnableApplicationModel)
	Config.EnableSyscallTracking = viper.GetBool(KeyEnableSyscallTracking)
	Config.ApplicationModelExportInterval = viper.GetDuration(KeyApplicationModelExportInterval)
	Config.ApplicationModelExportFilename = viper.GetString(KeyApplicationModelExportFilename)
	Config.TelemetryExportFilename = viper.GetString(KeyTelemetryExportFilename)
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
	Config.EnableDnsDebug = viper.GetBool(KeyEnableDnsDebug)
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
	Config.EnableTCPRTT = viper.GetBool(keyEnableTCPRTT)
	Config.EnableUDP = viper.GetBool(keyEnableUDP)
	Config.EnableLatency = viper.GetBool(keyEnableLatency)
	Config.EnableICMP = viper.GetBool(keyEnableICMP)
	Config.EnableRawsock = viper.GetBool(keyEnableRawsock)
	Config.EnableDNS = viper.GetBool(keyEnableDNS)
	Config.UDPIdleSocketTimeout = viper.GetDuration(keyUDPIdleSocketTimeout)
	Config.UDPInKernelManaged = viper.GetBool(keyUDPInKernelManaged)
	Config.EnableNetworkEvents = viper.GetBool(keyEnableNetworkEvents)
	Config.EnableAlertProfiling = viper.GetBool(keyEnableAlertsProfiling)
	// Layer 3 protocols can be enabled on the CLI or in policies. If any were enabled on the CLI
	// then we ignore enable/disable in policies.
	if Config.EnableTCP || Config.EnableUDP || Config.EnableICMP || Config.EnableRawsock || Config.EnableDNS {
		Config.Layer3CLIEnable = true
	}

	Config.K8sServiceAccountAuth = viper.GetString(keyK8sServiceAccountAuth)
	Config.NodeNamespace = viper.GetString(keyTetragonNodeNamespace)
}

func validateConfig(config config) error {
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

	// Network policies can be loaded via the k8s resource watcher as well
	if (len(config.NetworkPolicies) != 0 || config.NetworkPoliciesDir != "") && !config.EnableTCP {
		return fmt.Errorf("network policies require --%s", KeyEnableTCP)
	}

	if config.EnableSyscallTracking && !config.EnableApplicationModel {
		return fmt.Errorf("system call tracking requires --%s", KeyEnableApplicationModel)
	}

	if config.EnableApplicationModel && !option.Config.EnableCgIDmap {
		return fmt.Errorf("application model requires --%s", option.KeyEnableCgIDmap)
	}

	if config.Environment != "" {
		if !slices.Contains(environments, config.Environment) {
			return fmt.Errorf("invalid environment '%s', valid values are %s", config.Environment, environments)
		}
	}
	return nil
}
