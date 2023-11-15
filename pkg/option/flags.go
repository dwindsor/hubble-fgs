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

	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	KeyHubbleLib                = "hubble-lib"
	KeyFlowExportFilename       = "flow-export-filename"
	KeyFlowExportFileMaxSizeMB  = "flow-export-file-max-size-mb"
	KeyFlowExportFileMaxBackups = "flow-export-file-max-backups"
	KeyFlowExportFileCompress   = "flow-export-file-compress"
	KeyFimFifoPath              = "fim-fifo-path"
	KeyFimRuntimeEndpoint       = "fim-runtime-endpoint"
	KeyDnsCacheSize             = "dns-cache-size"
	KeyTlsCacheSize             = "tls-cache-size"
	KeyNetNsCacheSize           = "net-ns-cache-size"
	KeyDetatchOldBPF            = "detach-old-bpf"
	KeyEnableProcessAncestors   = "enable-process-ancestors"
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
	flags.Int(KeyDnsCacheSize, 1024, "Set the size of the internal DNS cache. Higher values enable Tetragon to keep track of more destination names before evicting old ones")
	flags.Int(KeyTlsCacheSize, 1024, "Set the size of the internal TLS cache. Higher values enable Tetragon to keep track of more in progress handshakes before evicting old ones")
	flags.Int(KeyNetNsCacheSize, 256, "Set the size of the internal network namespace cache. This should be aligned with the maximum number of network namespaces (approximately, the maxumum number of pods) we expect to see in the system")
	flags.String(KeyFimFifoPath, "/var/run/cilium/hubble", "Path for the FIFO used for fs-scanner and tetragon communication")
	flags.String(KeyFimRuntimeEndpoint, "", "Custom container runtime endpoint for FIM (can be used only for containerd or cri-o)")

	// Provide option to detach old programs even when using old names that make it
	// hard to find Tetragon specific programs. Use with some caution because we
	// could remove progs associated with other agents. But this is necessary in
	// cases where upgrading from older versions to fix bug where we failed to
	// detach programs and left stale progs attached at cgroups and tc hooks.
	flags.Bool(KeyDetatchOldBPF, false, "Detach old cgroup programs from their interfaces when loading Tetragon. Disabled by default.")
}

func ReadAndSetEnterpriseFlags() {
	Config.EnableProcessAncestors = viper.GetBool(KeyEnableProcessAncestors)
	Config.DetachOldBpf = viper.GetBool(KeyDetatchOldBPF)
	Config.DnsCacheSize = viper.GetInt(KeyDnsCacheSize)
	Config.TlsCacheSize = viper.GetInt(KeyTlsCacheSize)
	Config.NetNsCacheSize = viper.GetInt(KeyNetNsCacheSize)
	Config.FimFifoPath = viper.GetString(KeyFimFifoPath)
	Config.FimRuntimeEndpoint = viper.GetString(KeyFimRuntimeEndpoint)
	Config.FlowExportFilename = viper.GetString(KeyFlowExportFilename)
	Config.FlowExportFileMaxSizeMB = viper.GetInt(KeyFlowExportFileMaxSizeMB)
	Config.FlowExportFileMaxBackups = viper.GetInt(KeyFlowExportFileMaxBackups)
	Config.FlowExportFileCompress = viper.GetBool(KeyFlowExportFileCompress)
	// TODO(michi) Remove after branching v1.12.
	// We parse shared flags with OSS then we parse Enterprise ones
	if viper.IsSet(KeyHubbleLib) {
		logger.GetLogger().Warnf("Flag --%s has been deprecated, please use --%s instead", KeyHubbleLib, option.KeyHubbleLib)
		// If option.KeyHubbleLib has been set then it takes precedence.
		if viper.IsSet(option.KeyHubbleLib) == false {
			option.Config.HubbleLib = viper.GetString(KeyHubbleLib)
		}
	}
}
