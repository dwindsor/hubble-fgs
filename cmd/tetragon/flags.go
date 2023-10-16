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
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/spf13/viper"
)

const (
	keyConfigDir        = "config-dir"
	keyDebug            = "debug"
	keyHubbleLib        = "hubble-lib"
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

	keyMetricsServer     = "metrics-server"
	keyServerAddress     = "server-address"
	keyGopsAddr          = "gops-address"
	keyEnableProcessCred = "enable-process-cred"
	keyEnableProcessNs   = "enable-process-ns"
	keyConfigFile        = "config-file"
	keyTracingPolicy     = "tracing-policy"

	keyExportFilename             = "export-filename"
	keyExportFileMaxSizeMB        = "export-file-max-size-mb"
	keyExportFileRotationInterval = "export-file-rotation-interval"
	keyExportFileMaxBackups       = "export-file-max-backups"
	keyExportFileCompress         = "export-file-compress"
	keyExportRateLimit            = "export-rate-limit"

	keyEnableExportAggregation     = "enable-export-aggregation"
	keyExportAggregationWindowSize = "export-aggregation-window-size"
	keyExportAggregationBufferSize = "export-aggregation-buffer-size"

	keyExportAllowlist = "export-allowlist"
	keyExportDenylist  = "export-denylist"

	keyFieldFilters = "field-filters"

	keyNetnsDir = "netns-dir"

	keyEventQueueSize = "event-queue-size"

	keyReleasePinnedBPF = "release-pinned-bpf"

	keyProtocolShift = "protocol-shift"

	keyDisableKprobeMulti = "disable-kprobe-multi"

	keyRBSize      = "rb-size"
	keyRBSizeTotal = "rb-size-total"

	keyEnablePolicyFilter      = "enable-policy-filter"
	keyEnablePolicyFilterDebug = "enable-policy-filter-debug"

	keyEnablePidSetFilter = "enable-pid-set-filter"

	keyEnablePodInfo = "enable-pod-info"
)

var (
	processCacheSize int
	dataCacheSize    int

	metricsServer string
	serverAddress string

	exportFilename             string
	exportFileMaxSizeMB        int
	exportFileRotationInterval time.Duration
	exportFileMaxBackups       int
	exportFileCompress         bool
	exportRateLimit            int

	// Export aggregation options
	enableExportAggregation     bool
	exportAggregationWindowSize time.Duration
	exportAggregationBufferSize uint64
)

func readAndSetFlags() {
	option.Config.HubbleLib = viper.GetString(keyHubbleLib)
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

	processCacheSize = viper.GetInt(keyProcessCacheSize)
	dataCacheSize = viper.GetInt(keyDataCacheSize)

	metricsServer = viper.GetString(keyMetricsServer)
	serverAddress = viper.GetString(keyServerAddress)

	exportFilename = viper.GetString(keyExportFilename)
	exportFileMaxSizeMB = viper.GetInt(keyExportFileMaxSizeMB)
	exportFileRotationInterval = viper.GetDuration(keyExportFileRotationInterval)
	exportFileMaxBackups = viper.GetInt(keyExportFileMaxBackups)
	exportFileCompress = viper.GetBool(keyExportFileCompress)
	exportRateLimit = viper.GetInt(keyExportRateLimit)

	enableExportAggregation = viper.GetBool(keyEnableExportAggregation)
	exportAggregationWindowSize = viper.GetDuration(keyExportAggregationWindowSize)
	exportAggregationBufferSize = viper.GetUint64(keyExportAggregationBufferSize)

	option.Config.EventQueueSize = viper.GetUint(keyEventQueueSize)

	option.Config.ReleasePinned = viper.GetBool(keyReleasePinnedBPF)

	option.Config.DisableKprobeMulti = viper.GetBool(keyDisableKprobeMulti)

	option.Config.RBSize = viper.GetInt(keyRBSize)
	option.Config.RBSizeTotal = viper.GetInt(keyRBSizeTotal)

	option.Config.EnablePolicyFilter = viper.GetBool(keyEnablePolicyFilter)
	option.Config.EnablePolicyFilterDebug = viper.GetBool(keyEnablePolicyFilterDebug)

	option.Config.EnablePidSetFilter = viper.GetBool(keyEnablePidSetFilter)

	// deprecation timeline: deprecated -> v1.12.0
	// manually handle the deprecation of --config-file
	if viper.IsSet(keyConfigFile) {
		log.Warnf("Flag --%s has been deprecated, please use --%s instead", keyConfigFile, keyTracingPolicy)
		option.Config.TracingPolicy = viper.GetString(keyConfigFile)
	}

	option.Config.EnablePodInfo = viper.GetBool(keyEnablePodInfo)

	// if both --config-file and --tracing-policy are set, the latter takes priority
	if viper.IsSet(keyTracingPolicy) {
		option.Config.TracingPolicy = viper.GetString(keyTracingPolicy)
	}
}
