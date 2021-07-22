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

	"github.com/isovalent/hubble-fgs/pkg/observer"

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
	keyTLS              = "tls"
	keyTLSTC            = "tlstc"
	keyProcessCacheSize = "process-cache-size"

	keyLogLevel  = "log-level"
	keyLogFormat = "log-format"

	keyEnableK8sAPI    = "enable-k8s-api"
	keyEnableCiliumAPI = "enable-cilium-api"

	keyMetricsServer     = "metrics-server"
	keyNetworkInterfaces = "network-interfaces"
	keyServerAddress     = "server-address"
	keyCiliumBPF         = "cilium-bpf"
	keyEnableProcessCred = "enable-process-cred"
	keyConfigFile        = "config-file"

	keyRunStandalone      = "run-standalone"
	keyIgnoreMissingProgs = "ignore-missing-progs"

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

	keyTCPStatsSampleSeg = "tcp-stats-sample-segs"
)

var (
	debug            bool
	tls              bool
	tlstc            bool
	processCacheSize int

	enableK8sAPI    bool
	enableCiliumAPI bool

	metricsServer     string
	networkInterfaces string
	serverAddress     string
	ciliumBPF         string
	enableProcessCred bool
	configFile        string

	runStandalone bool

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

	// Sample confiugration options
	exportTCPStatsSampleSeg uint32
)

func readAndSetFlags() {
	observer.HubbleLib = viper.GetString(keyHubbleLib)
	observer.ObserverBTF = viper.GetString(keyBTF)
	observer.ProcFS = viper.GetString(keyProcFS)
	observer.KernelVersion = viper.GetString(keyKernelVersion)
	observer.Verbosity = viper.GetInt(keyVerbosity)
	observer.IgnoreMissingProgs = viper.GetBool(keyIgnoreMissingProgs)

	debug = viper.GetBool(keyDebug)
	tls = viper.GetBool(keyTLS)
	tlstc = viper.GetBool(keyTLSTC)
	processCacheSize = viper.GetInt(keyProcessCacheSize)

	enableK8sAPI = viper.GetBool(keyEnableK8sAPI)
	enableCiliumAPI = viper.GetBool(keyEnableCiliumAPI)

	metricsServer = viper.GetString(keyMetricsServer)
	networkInterfaces = viper.GetString(keyNetworkInterfaces)
	serverAddress = viper.GetString(keyServerAddress)
	ciliumBPF = viper.GetString(keyCiliumBPF)
	enableProcessCred = viper.GetBool(keyEnableProcessCred)
	configFile = viper.GetString(keyConfigFile)

	runStandalone = viper.GetBool(keyRunStandalone)

	exportFilename = viper.GetString(keyExportFilename)
	exportFileMaxSizeMB = viper.GetInt(keyExportFileMaxSizeMB)
	exportFileRotationInterval = viper.GetDuration(keyExportFileRotationInterval)
	exportFileMaxBackups = viper.GetInt(keyExportFileMaxBackups)
	exportFileCompress = viper.GetBool(keyExportFileCompress)
	exportRateLimit = viper.GetInt(keyExportRateLimit)

	enableExportAggregation = viper.GetBool(keyEnableExportAggregation)
	exportAggregationWindowSize = viper.GetDuration(keyExportAggregationWindowSize)
	exportAggregationBufferSize = viper.GetUint64(keyExportAggregationBufferSize)

	exportTCPStatsSampleSeg = viper.GetUint32(keyTCPStatsSampleSeg)
}
