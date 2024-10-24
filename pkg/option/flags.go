//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package option

import (
	"fmt"
	"time"

	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	KeyHubbleLib                 = "hubble-lib"
	KeyFlowExportFilename        = "flow-export-filename"
	KeyFlowExportFileMaxSizeMB   = "flow-export-file-max-size-mb"
	KeyFlowExportFileMaxBackups  = "flow-export-file-max-backups"
	KeyFlowExportFileCompress    = "flow-export-file-compress"
	KeyFimFifoPath               = "fim-fifo-path"
	KeyFimRuntimeEndpoint        = "fim-runtime-endpoint"
	KeyDnsCacheSize              = "dns-cache-size"
	KeyEndpointCacheSize         = "endpoint-cache-size"
	KeyBpfEndpointCacheSize      = "bpf-endpoint-cache-size"
	KeyProcessTreeSize           = "process-tree-cache-size"
	KeyTlsCacheSize              = "tls-cache-size"
	KeyTcpCacheSize              = "tcp-cache-size"
	KeyNetNsCacheSize            = "net-ns-cache-size"
	KeyDetatchOldBPF             = "detach-old-bpf"
	KeyEnableProcessAncestors    = "enable-process-ancestors"
	KeyEnableProcessTree         = "enable-process-tree"
	KeyProcessTreeExportInterval = "process-tree-export-interval"
	keyEnableIcmpTracking        = "enable-icmp-tracking"
	keyEnableSandboxPolicies     = "enable-sandboxpolicies"
	keyEnableSandboxPoliciesCRD  = "enable-sandboxpolicies-crd"
	keySandboxPolicy             = "sandbox-policy"
	keyDebugX                    = "debugx"
	keyEnableAWSSonar            = "enable-aws-sonar"
	keyAWSSonarRegion            = "aws-sonar-region"
	KeyEnableCiliumAPI           = "enable-cilium-api"
	KeyProtocolShift             = "protocol-shift"
	KeyEnableDnsDebug            = "enable-dns-debug"
	KeyProcessCacheStaleInterval = "process-cache-stale-interval"
)

func AddEnterpriseFlags(flags *pflag.FlagSet) {
	flags.String(KeyHubbleLib, defaults.DefaultTetragonLib, "Location of hubble libs (btf and bpf files)")
	// TODO(michi) Remove after branching v1.12.
	flags.MarkDeprecated(KeyHubbleLib, fmt.Sprintf("Use --%s instead.", option.KeyHubbleLib))
	flags.String(KeyFlowExportFilename, "", "Filename for flow JSON export. Disabled by default")
	flags.Int(KeyFlowExportFileMaxSizeMB, 10, "Size in MB for rotating flow JSON export files")
	flags.Int(KeyFlowExportFileMaxBackups, 5, "Number of rotated flow JSON export files to retain")
	flags.Bool(KeyFlowExportFileCompress, false, "Compress rotated flow JSON export files")
	flags.Bool(KeyEnableProcessAncestors, true, "Include ancestors in process exec events")
	flags.Bool(KeyEnableProcessTree, false, "Include BPF process tree in memory")
	// An experimental flag to periodically export process model to export JSON file.
	flags.Duration(KeyProcessTreeExportInterval, 0, "Interval at which to export process tree as JSON.")
	flags.MarkHidden(KeyProcessTreeExportInterval)
	flags.Int(KeyDnsCacheSize, 1024, "Set the size of the internal DNS cache. Higher values enable Tetragon to keep track of more destination names before evicting old ones")
	flags.Int(KeyProcessTreeSize, 1024, "Set the size of the BPF data structure to store process tree and statistics. Higher values enable Tetragon to keep track of more processes before evicting old ones")
	flags.Int(KeyEndpointCacheSize, 1024, "Set the size of the internal endpoint cache. Higher values enable Tetragon to keep track of more network endpoints before evicting old ones")
	flags.Int(KeyBpfEndpointCacheSize, 1024, "Set the size of the internal BPF endpoint cache. Higher values enable Tetragon to keep track of more network endpoints before evicting old ones")
	flags.Int(KeyTlsCacheSize, 1024, "Set the size of the internal TLS cache. Higher values enable Tetragon to keep track of more in progress handshakes before evicting old ones")
	flags.Int(KeyTcpCacheSize, 32768, "Set the size of the internal TCP cache. Higher values enable Tetragon to keep track of more concurrent TCP sessions before evicting old ones")
	flags.Int(KeyNetNsCacheSize, 256, "Set the size of the internal network namespace cache. This should be aligned with the maximum number of network namespaces (approximately, the maxumum number of pods) we expect to see in the system")
	flags.String(KeyFimFifoPath, defaults.DefaultRunDir, "Path for the FIFO used for fs-scanner and tetragon communication")
	flags.String(KeyFimRuntimeEndpoint, "", "Custom container runtime endpoint for FIM (can be used only for containerd or cri-o)")

	// Provide option to detach old programs even when using old names that make it
	// hard to find Tetragon specific programs. Use with some caution because we
	// could remove progs associated with other agents. But this is necessary in
	// cases where upgrading from older versions to fix bug where we failed to
	// detach programs and left stale progs attached at cgroups and tc hooks.
	flags.Bool(KeyDetatchOldBPF, false, "Detach old cgroup programs from their interfaces when loading Tetragon. Disabled by default.")

	// Provide option to enable extra socket tracking for ICMP matching.
	flags.Bool(keyEnableIcmpTracking, true, "Enable additional socket tracking for ICMP")
	flags.Bool(keyEnableSandboxPolicies, true, "Enable sandboxpolicies")
	flags.Bool(keyEnableSandboxPoliciesCRD, true, "Enable SandboxPolicy and SanboxPolicyNamespaced custom resources")
	flags.StringSlice(keySandboxPolicy, []string{}, "Sandbox policy file to load at startup")
	flags.StringSlice(keyDebugX, []string{}, "Extended debug to enable (e.g. \"tcp,udp+\"). Choose from: tcp, udp, icmp, rawsock. Tetragon defaults to maintaining metrics for program errors. Specifying the protocol/sub-system here causes events to be dispatched as well; adding a '+' will also get console messages")
	flags.Bool(KeyEnableDnsDebug, false, "Enable DNS debug messages")
	flags.Duration(KeyProcessCacheStaleInterval, time.Duration(60*time.Minute), "Interval between stale process cache checks")
	flags.String(KeyProtocolShift, "auto", "(deprecated)")
	flags.Bool(KeyEnableCiliumAPI, false, "Access Cilium API to associate Tetragon events with Cilium endpoints and DNS cache")
}

func ReadAndSetEnterpriseFlags() {
	Config.EnableProcessAncestors = viper.GetBool(KeyEnableProcessAncestors)
	Config.EnableProcessTree = viper.GetBool(KeyEnableProcessTree)
	Config.ProcessTreeExportInterval = viper.GetDuration(KeyProcessTreeExportInterval)
	Config.DetachOldBpf = viper.GetBool(KeyDetatchOldBPF)
	Config.DnsCacheSize = viper.GetInt(KeyDnsCacheSize)
	Config.ProcessTreeCacheSize = viper.GetInt(KeyProcessTreeSize)
	Config.EndpointCacheSize = viper.GetInt(KeyEndpointCacheSize)
	Config.BpfEndpointCacheSize = viper.GetInt(KeyBpfEndpointCacheSize)
	Config.TlsCacheSize = viper.GetInt(KeyTlsCacheSize)
	Config.TcpCacheSize = viper.GetInt(KeyTcpCacheSize)
	Config.NetNsCacheSize = viper.GetInt(KeyNetNsCacheSize)
	Config.FimFifoPath = viper.GetString(KeyFimFifoPath)
	Config.FimRuntimeEndpoint = viper.GetString(KeyFimRuntimeEndpoint)
	Config.FlowExportFilename = viper.GetString(KeyFlowExportFilename)
	Config.FlowExportFileMaxSizeMB = viper.GetInt(KeyFlowExportFileMaxSizeMB)
	Config.FlowExportFileMaxBackups = viper.GetInt(KeyFlowExportFileMaxBackups)
	Config.FlowExportFileCompress = viper.GetBool(KeyFlowExportFileCompress)
	Config.EnableIcmpTracking = viper.GetBool(keyEnableIcmpTracking)
	// TODO(michi) Remove after branching v1.12.
	// We parse shared flags with OSS then we parse Enterprise ones
	if viper.IsSet(KeyHubbleLib) {
		logger.GetLogger().Warnf("Flag --%s has been deprecated, please use --%s instead", KeyHubbleLib, option.KeyHubbleLib)
		// If option.KeyHubbleLib has been set then it takes precedence.
		if viper.IsSet(option.KeyHubbleLib) == false {
			option.Config.HubbleLib = viper.GetString(KeyHubbleLib)
		}
	}
	Config.EnableSandboxPolicies = viper.GetBool(keyEnableSandboxPolicies)
	Config.EnableSandboxPoliciesCRD = viper.GetBool(keyEnableSandboxPoliciesCRD)
	Config.SandboxPolicies = viper.GetStringSlice(keySandboxPolicy)
	Config.DebugX = viper.GetStringSlice(keyDebugX)
	Config.EnableAWSSonar = viper.GetBool(keyEnableAWSSonar)
	Config.AWSSonarRegion = viper.GetString(keyAWSSonarRegion)
	Config.EnableDnsDebug = viper.GetBool(KeyEnableDnsDebug)
	Config.EnableCilium = viper.GetBool(KeyEnableCiliumAPI)
	Config.ProcessCacheStaleInterval = viper.GetDuration(KeyProcessCacheStaleInterval)
}
