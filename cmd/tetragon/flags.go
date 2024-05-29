//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/spf13/viper"
)

const (
	keyConfigDir        = "config-dir"
	keyDebug            = "debug"
	keyBTF              = "btf"
	keyProcFS           = "procfs"
	keyKernelVersion    = "kernel"
	keyVerbosity        = "verbose"
	keyProcessCacheSize = "process-cache-size"
	keyDataCacheSize    = "data-cache-size"
	keyForceSmallProgs  = "force-small-progs"

	keyLogLevel  = "log-level"
	keyLogFormat = "log-format"

	keyEnableK8sAPI    = "enable-k8s-api"
	keyEnableCiliumAPI = "enable-cilium-api"

	keyK8sKubeConfigPath = "k8s-kubeconfig-path"

	keyMetricsServer     = "metrics-server"
	keyServerAddress     = "server-address"
	keyGopsAddr          = "gops-address"
	keyEnableProcessCred = "enable-process-cred"
	keyEnableProcessNs   = "enable-process-ns"
	keyConfigFile        = "config-file"
	keyTracingPolicy     = "tracing-policy"
	keyTracingPolicyDir  = "tracing-policy-dir"

	keyExportFilename             = "export-filename"
	keyExportFileMaxSizeMB        = "export-file-max-size-mb"
	keyExportFileRotationInterval = "export-file-rotation-interval"
	keyExportFileMaxBackups       = "export-file-max-backups"
	keyExportFileCompress         = "export-file-compress"
	keyExportRateLimit            = "export-rate-limit"
	keyExportFilePerm             = "export-file-perm"

	keyEnableExportAggregation     = "enable-export-aggregation"
	keyExportAggregationWindowSize = "export-aggregation-window-size"
	keyExportAggregationBufferSize = "export-aggregation-buffer-size"

	keyExportAllowlist = "export-allowlist"
	keyExportDenylist  = "export-denylist"

	keyFieldFilters     = "field-filters"
	KeyRedactionFilters = "redaction-filters"

	keyNetnsDir = "netns-dir"

	keyEventQueueSize = "event-queue-size"

	keyReleasePinnedBPF = "release-pinned-bpf"

	keyProtocolShift = "protocol-shift"

	keyDisableKprobeMulti = "disable-kprobe-multi"

	keyRBSize      = "rb-size"
	keyRBSizeTotal = "rb-size-total"

	keyEnablePolicyFilter      = "enable-policy-filter"
	keyEnablePolicyFilterDebug = "enable-policy-filter-debug"

	keyEnableDnsDebug = "enable-dns-debug"

	keyEnablePidSetFilter = "enable-pid-set-filter"

	keyEnablePodInfo = "enable-pod-info"

	keyEnableMsgHandlingLatency = "enable-msg-handling-latency"

	KeyGenerateDocs = "generate-docs"

	keyCgroupRate = "cgroup-rate"

	KeyHealthServerAddress = "health-server-address"
	KeyHealthTimeInterval  = "health-server-interval"
)

func readAndSetFlags() {
	option.Config.HubbleLib = viper.GetString(option.KeyHubbleLib)
	option.Config.BTF = viper.GetString(keyBTF)
	option.Config.ProcFS = viper.GetString(keyProcFS)
	option.Config.KernelVersion = viper.GetString(keyKernelVersion)
	option.Config.Verbosity = viper.GetInt(keyVerbosity)
	option.Config.ForceSmallProgs = viper.GetBool(keyForceSmallProgs)
	option.Config.Debug = viper.GetBool(keyDebug)

	option.Config.EnableProcessCred = viper.GetBool(keyEnableProcessCred)
	option.Config.EnableProcessNs = viper.GetBool(keyEnableProcessNs)
	option.Config.EnableK8s = viper.GetBool(keyEnableK8sAPI)
	option.Config.EnableCilium = viper.GetBool(keyEnableCiliumAPI)

	option.Config.GopsAddr = viper.GetString(keyGopsAddr)

	logLevel := viper.GetString(keyLogLevel)
	logFormat := viper.GetString(keyLogFormat)
	logger.PopulateLogOpts(option.Config.LogOpts, logLevel, logFormat)

	option.Config.ProcessCacheSize = viper.GetInt(keyProcessCacheSize)
	option.Config.DataCacheSize = viper.GetInt(keyDataCacheSize)

	option.Config.MetricsServer = viper.GetString(keyMetricsServer)
	option.Config.ServerAddress = viper.GetString(keyServerAddress)

	option.Config.ExportFilename = viper.GetString(keyExportFilename)
	option.Config.ExportFileMaxSizeMB = viper.GetInt(keyExportFileMaxSizeMB)
	option.Config.ExportFileRotationInterval = viper.GetDuration(keyExportFileRotationInterval)
	option.Config.ExportFileMaxBackups = viper.GetInt(keyExportFileMaxBackups)
	option.Config.ExportFileCompress = viper.GetBool(keyExportFileCompress)
	option.Config.ExportRateLimit = viper.GetInt(keyExportRateLimit)
	option.Config.ExportFilePerm = viper.GetString(keyExportFilePerm)

	option.Config.EnableExportAggregation = viper.GetBool(keyEnableExportAggregation)
	option.Config.ExportAggregationWindowSize = viper.GetDuration(keyExportAggregationWindowSize)
	option.Config.ExportAggregationBufferSize = viper.GetUint64(keyExportAggregationBufferSize)

	option.Config.EventQueueSize = viper.GetUint(keyEventQueueSize)

	option.Config.ReleasePinned = viper.GetBool(keyReleasePinnedBPF)

	option.Config.DisableKprobeMulti = viper.GetBool(keyDisableKprobeMulti)

	option.Config.RBSize = viper.GetInt(keyRBSize)
	option.Config.RBSizeTotal = viper.GetInt(keyRBSizeTotal)

	option.Config.EnablePolicyFilter = viper.GetBool(keyEnablePolicyFilter)
	option.Config.EnablePolicyFilterDebug = viper.GetBool(keyEnablePolicyFilterDebug)

	enterpriseOption.Config.EnableDnsDebug = viper.GetBool(keyEnableDnsDebug)

	option.Config.EnablePidSetFilter = viper.GetBool(keyEnablePidSetFilter)

	option.Config.TracingPolicyDir = viper.GetString(keyTracingPolicyDir)

	// deprecation timeline: deprecated -> v1.12.0
	// manually handle the deprecation of --config-file
	if viper.IsSet(keyConfigFile) {
		log.Warnf("Flag --%s has been deprecated, please use --%s instead", keyConfigFile, keyTracingPolicy)
		option.Config.TracingPolicy = viper.GetString(keyConfigFile)
	}

	option.Config.EnablePodInfo = viper.GetBool(keyEnablePodInfo)

	option.Config.K8sKubeConfigPath = viper.GetString(keyK8sKubeConfigPath)

	// if both --config-file and --tracing-policy are set, the latter takes priority
	if viper.IsSet(keyTracingPolicy) {
		option.Config.TracingPolicy = viper.GetString(keyTracingPolicy)
	}

	option.Config.EnableMsgHandlingLatency = viper.GetBool(keyEnableMsgHandlingLatency)

	option.Config.CgroupRate = option.ParseCgroupRate(viper.GetString(keyCgroupRate))

	option.Config.HealthServerAddress = viper.GetString(KeyHealthServerAddress)
	option.Config.HealthServerInterval = viper.GetInt(KeyHealthTimeInterval)
}
