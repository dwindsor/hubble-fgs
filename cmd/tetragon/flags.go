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
	"fmt"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/strutils"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/spf13/viper"
)

const (
	keyEnableCiliumAPI = "enable-cilium-api"

	keyProtocolShift = "protocol-shift"

	keyEnableDnsDebug = "enable-dns-debug"

	keyProcessCacheStaleInterval = "process-cache-stale-interval"
)

func readAndSetFlags() error {
	option.Config.HubbleLib = viper.GetString(option.KeyHubbleLib)
	option.Config.BTF = viper.GetString(option.KeyBTF)
	option.Config.ProcFS = viper.GetString(option.KeyProcFS)
	option.Config.KernelVersion = viper.GetString(option.KeyKernelVersion)
	option.Config.Verbosity = viper.GetInt(option.KeyVerbosity)
	option.Config.ForceSmallProgs = viper.GetBool(option.KeyForceSmallProgs)
	option.Config.Debug = viper.GetBool(option.KeyDebug)
	option.Config.ClusterName = viper.GetString(option.KeyClusterName)

	option.Config.EnableProcessCred = viper.GetBool(option.KeyEnableProcessCred)
	option.Config.EnableProcessNs = viper.GetBool(option.KeyEnableProcessNs)
	option.Config.EnableK8s = viper.GetBool(option.KeyEnableK8sAPI)
	enterpriseOption.Config.EnableCilium = viper.GetBool(keyEnableCiliumAPI)

	option.Config.GopsAddr = viper.GetString(option.KeyGopsAddr)

	logLevel := viper.GetString(option.KeyLogLevel)
	logFormat := viper.GetString(option.KeyLogFormat)
	logger.PopulateLogOpts(option.Config.LogOpts, logLevel, logFormat)

	option.Config.ProcessCacheSize = viper.GetInt(option.KeyProcessCacheSize)
	option.Config.DataCacheSize = viper.GetInt(option.KeyDataCacheSize)

	option.Config.MetricsServer = viper.GetString(option.KeyMetricsServer)
	option.Config.ServerAddress = viper.GetString(option.KeyServerAddress)

	option.Config.ExportFilename = viper.GetString(option.KeyExportFilename)
	option.Config.ExportFileMaxSizeMB = viper.GetInt(option.KeyExportFileMaxSizeMB)
	option.Config.ExportFileRotationInterval = viper.GetDuration(option.KeyExportFileRotationInterval)
	option.Config.ExportFileMaxBackups = viper.GetInt(option.KeyExportFileMaxBackups)
	option.Config.ExportFileCompress = viper.GetBool(option.KeyExportFileCompress)
	option.Config.ExportRateLimit = viper.GetInt(option.KeyExportRateLimit)
	option.Config.ExportFilePerm = viper.GetString(option.KeyExportFilePerm)

	option.Config.EnableExportAggregation = viper.GetBool(option.KeyEnableExportAggregation)
	option.Config.ExportAggregationWindowSize = viper.GetDuration(option.KeyExportAggregationWindowSize)
	option.Config.ExportAggregationBufferSize = viper.GetUint64(option.KeyExportAggregationBufferSize)

	option.Config.EventQueueSize = viper.GetUint(option.KeyEventQueueSize)

	option.Config.ReleasePinned = viper.GetBool(option.KeyReleasePinnedBPF)

	option.Config.DisableKprobeMulti = viper.GetBool(option.KeyDisableKprobeMulti)

	var err error
	if option.Config.RBSize, err = strutils.ParseSize(viper.GetString(option.KeyRBSize)); err != nil {
		return fmt.Errorf("failed to parse rb-size value: %s", err)
	}
	if option.Config.RBSizeTotal, err = strutils.ParseSize(viper.GetString(option.KeyRBSizeTotal)); err != nil {
		return fmt.Errorf("failed to parse rb-size-total value: %s", err)
	}
	if option.Config.RBQueueSize, err = strutils.ParseSize(viper.GetString(option.KeyRBQueueSize)); err != nil {
		return fmt.Errorf("failed to parse rb-queue-size value: %s", err)
	}

	option.Config.EnablePolicyFilter = viper.GetBool(option.KeyEnablePolicyFilter)
	option.Config.EnablePolicyFilterDebug = viper.GetBool(option.KeyEnablePolicyFilterDebug)

	enterpriseOption.Config.EnableDnsDebug = viper.GetBool(keyEnableDnsDebug)

	option.Config.EnablePidSetFilter = viper.GetBool(option.KeyEnablePidSetFilter)

	option.Config.TracingPolicyDir = viper.GetString(option.KeyTracingPolicyDir)

	option.Config.EnablePodInfo = viper.GetBool(option.KeyEnablePodInfo)
	option.Config.EnableTracingPolicyCRD = viper.GetBool(option.KeyEnableTracingPolicyCRD)

	option.Config.K8sKubeConfigPath = viper.GetString(option.KeyK8sKubeConfigPath)

	switch o := viper.GetString(option.KeyUsernameMetadata); o {
	case "unix":
		option.Config.UsernameMetadata = int(option.USERNAME_METADATA_UNIX)
	case "disabled":
		option.Config.UsernameMetadata = int(option.USERNAME_METADATA_DISABLED)
	default:
		return fmt.Errorf("unknown option for %s: %q", option.KeyUsernameMetadata, o)
	}

	option.Config.EnableMsgHandlingLatency = viper.GetBool(option.KeyEnableMsgHandlingLatency)

	option.Config.CgroupRate = option.ParseCgroupRate(viper.GetString(option.KeyCgroupRate))

	option.Config.HealthServerAddress = viper.GetString(option.KeyHealthServerAddress)
	option.Config.HealthServerInterval = viper.GetInt(option.KeyHealthTimeInterval)

	option.Config.KeepSensorsOnExit = viper.GetBool(option.KeyKeepSensorsOnExit)

	option.Config.EnableCRI = viper.GetBool(option.KeyEnableCRI)
	option.Config.CRIEndpoint = viper.GetString(option.KeyCRIEndpoint)

	option.Config.EnableCgIDmap = viper.GetBool(option.KeyEnableCgIDmap)
	option.Config.EnableCgIDmapDebug = viper.GetBool(option.KeyEnableCgIDmapDebug)

	option.Config.PprofAddr = viper.GetString(option.KeyPprofAddr)

	option.Config.EventCacheNumRetries = viper.GetInt(option.KeyEventCacheRetries)
	option.Config.EventCacheRetryDelay = viper.GetInt(option.KeyEventCacheRetryDelay)

	option.Config.CompatibilitySyscall64SizeType = viper.GetBool(option.KeyCompatibilitySyscall64SizeType)

	enterpriseOption.Config.ProcessCacheStaleInterval = viper.GetDuration(keyProcessCacheStaleInterval)

	return nil
}
