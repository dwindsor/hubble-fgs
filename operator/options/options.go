// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package options

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
)

// EE options

const (
	// SkipPolicySandboxCRD specifies whether operator will skip the creation of the
	// sandboxpolicy CRD
	SkipPolicySandboxCRD = "skip-policysandbox-crd"

	installTetragonDaemonSet = "install-tetragon-daemon-set"
	namespaceEnvKey          = "TETRAGON_NAMESPACE"

	exportContainerNameKey     = "ds-export-container-name"
	exportContainerNameDefault = "export-stdout"
	exportContainerImageEnvKey = "EXPORT_CONTAINER_IMAGE"

	exportContainerCommandKey     = "ds-export-container-command"
	exportContainerCommandDefault = "hubble-export-stdout"

	exportContainerArgsKey     = "ds-export-container-args"
	exportContainerArgsDefault = "/var/run/cilium/tetragon/tetragon.log"

	exportContainerTerminationMessagePathKey     = "ds-export-container-term-msg-path"
	exportContainerTerminationMessagePathDefault = "/dev/termination-log"

	exportContainerTerminationMessagePolicyKey     = "ds-export-container-term-msg-policy"
	exportContainerTerminationMessagePolicyDefault = corev1.TerminationMessageFallbackToLogsOnError

	exportContainerImagePullPolicyKey     = "ds-export-container-img-pull-policy"
	exportContainerImagePullPolicyDefault = corev1.PullIfNotPresent

	tetragonContainerNameKey     = "ds-tetragon-container-name"
	tetragonContainerNameDefault = "tetragon"
	tetragonContainerImageEnvKey = "TETRAGON_CONTAINER_IMAGE"

	tetragonContainerArgsKey     = "ds-tetragon-container-args"
	tetragonContainerArgsDefault = "--config-dir=/etc/tetragon/tetragon.conf.d/"

	tetragonContainerTerminationMessagePathKey     = "ds-tetragon-container-term-msg-path"
	tetragonContainerTerminationMessagePathDefault = "/dev/termination-log"

	tetragonContainerTerminationMessagePolicyKey     = "ds-tetragon-container-term-msg-policy"
	tetragonContainerTerminationMessagePolicyDefault = corev1.TerminationMessageFallbackToLogsOnError

	tetragonContainerImagePullPolicyKey     = "ds-tetragon-container-img-pull-policy"
	tetragonContainerImagePullPolicyDefault = corev1.PullIfNotPresent

	tetragonContainerLivenessProbeCommandKey = "ds-tetragon-container-live-probe-command"

	tetragonContainerLivenessProbeTimeoutSecondsKey     = "ds-tetragon-container-live-probe-timeout-sec"
	tetragonContainerLivenessProbeTimeoutSecondsDefault = int32(60)

	tetragonContainerLivenessProbePeriodSecondsKey     = "ds-tetragon-container-live-probe-period-sec"
	tetragonContainerLivenessProbePeriodSecondsDefault = int32(10)

	tetragonContainerLivenessProbeSuccessThresholdKey     = "ds-tetragon-container-live-probe-success-threshold"
	tetragonContainerLivenessProbeSuccessThresholdDefault = int32(1)

	tetragonContainerLivenessProbeFailureThresholdKey     = "ds-tetragon-container-live-probe-failure-threshold"
	tetragonContainerLivenessProbeFailureThresholdDefault = int32(3)

	daemonSetRestartPolicy                        = "ds-restart-policy"
	daemonSetRestartPolicyDefault                 = corev1.RestartPolicyAlways
	daemonSetTerminationGracePeriodSeconds        = "ds-termination-grace-period-sec"
	daemonSetTerminationGracePeriodSecondsDefault = int64(1)
	daemonSetDNSPolicy                            = "ds-dns-policy"
	daemonSetDNSPolicyDefault                     = corev1.DNSDefault
	daemonSetServiceAccountName                   = "ds-sa-name"
	daemonSetServiceAccountNameDefault            = "tetragon"
	daemonSetHostNetwork                          = "ds-host-network"
	daemonSetHostNetworkDefault                   = true
	daemonSetSchedulerName                        = "ds-scheduler-name"
	daemonSetSchedulerNameDefault                 = "default-scheduler"
	daemonSetUpdateMaxUnavailable                 = "ds-update-max-unavailable"
	daemonSetUpdateMaxUnavailableDefault          = int32(1)
	daemonSetUpdateMaxSurge                       = "ds-update-max-surge"
)

// OperatorConfig is the configuration used by the operator.
type OperatorConfig struct {
	Namespace        string
	InstallDaemonSet bool
	DaemonSetName    string

	ExportContainerName                     string
	ExportContainerImage                    string
	ExportContainerCommand                  []string
	ExportContainerArgs                     []string
	ExportContainerTerminationMessagePath   string
	ExportContainerTerminationMessagePolicy corev1.TerminationMessagePolicy
	ExportContainerImagePullPolicy          corev1.PullPolicy

	TetragonContainerName                          string
	TetragonContainerImage                         string
	TetragonContainerArgs                          []string
	TetragonContainerTerminationMessagePath        string
	TetragonContainerTerminationMessagePolicy      corev1.TerminationMessagePolicy
	TetragonContainerImagePullPolicy               corev1.PullPolicy
	TetragonContainerLivenessProbeCommand          []string
	TetragonContainerLivenessProbeTimeoutSec       int32
	TetragonContainerLivenessProbePeriodSec        int32
	TetragonContainerLivenessProbeSuccessThreshold int32
	TetragonContainerLivenessProbeFailureThreshold int32

	DaemonSetRestartPolicy                 corev1.RestartPolicy
	DaemonSetTerminationGracePeriodSeconds int64
	DaemonSetDNSPolicy                     corev1.DNSPolicy
	DaemonSetServiceAccountName            string
	DaemonSetHostNetwork                   bool
	DaemonSetSchedulerName                 string

	DaemonSetUpdateMaxUnavailable int32
	DaemonSetUpdateMaxSurge       int32
}

// Config represents the operator configuration.
var (
	tetragonContainerLivenessProbeCommandDefault = []string{
		"tetra",
		"status",
		"--server-address",
		"localhost:54321",
		"--retries",
		"5",
	}

	Config = &OperatorConfig{}
)

// ConfigPopulate sets all options with the values from viper.
func ConfigPopulate() {
	Config.InstallDaemonSet = viper.GetBool(installTetragonDaemonSet)
	Config.Namespace = os.Getenv(namespaceEnvKey)
	if Config.Namespace == "" {
		panic(fmt.Errorf("%s env variable not found", namespaceEnvKey))
	}
	Config.DaemonSetName = "tetragon"

	Config.ExportContainerName = viper.GetString(exportContainerNameKey)
	if Config.ExportContainerName == "" {
		Config.ExportContainerName = exportContainerNameDefault
	}
	Config.ExportContainerImage = os.Getenv(exportContainerImageEnvKey)
	if Config.ExportContainerImage == "" {
		panic(fmt.Errorf("%s env variable not found", exportContainerImageEnvKey))
	}
	exportCommand := viper.GetString(exportContainerCommandKey)
	if exportCommand != "" {
		Config.ExportContainerCommand = strings.Split(exportCommand, ",")
	} else {
		Config.ExportContainerCommand = []string{exportContainerCommandDefault}
	}
	exportArgs := viper.GetString(exportContainerArgsKey)
	if exportArgs != "" {
		Config.ExportContainerArgs = strings.Split(exportArgs, ",")
	} else {
		Config.ExportContainerArgs = []string{exportContainerArgsDefault}
	}
	Config.ExportContainerTerminationMessagePath = viper.GetString(exportContainerTerminationMessagePathKey)
	if Config.ExportContainerTerminationMessagePath == "" {
		Config.ExportContainerTerminationMessagePath = exportContainerTerminationMessagePathDefault
	}
	Config.ExportContainerTerminationMessagePolicy = corev1.TerminationMessagePolicy(viper.GetString(exportContainerTerminationMessagePolicyKey))
	if Config.ExportContainerTerminationMessagePolicy == "" {
		Config.ExportContainerTerminationMessagePolicy = exportContainerTerminationMessagePolicyDefault
	}
	Config.ExportContainerImagePullPolicy = corev1.PullPolicy(viper.GetString(exportContainerImagePullPolicyKey))
	if Config.ExportContainerImagePullPolicy == "" {
		Config.ExportContainerImagePullPolicy = exportContainerImagePullPolicyDefault
	}

	Config.TetragonContainerName = viper.GetString(tetragonContainerNameKey)
	if Config.TetragonContainerName == "" {
		Config.TetragonContainerName = tetragonContainerNameDefault
	}
	Config.TetragonContainerImage = os.Getenv(tetragonContainerImageEnvKey)
	if Config.TetragonContainerImage == "" {
		panic(fmt.Errorf("%s env variable not found", tetragonContainerImageEnvKey))
	}
	tetragonArgs := viper.GetString(tetragonContainerArgsKey)
	if tetragonArgs != "" {
		Config.TetragonContainerArgs = strings.Split(tetragonArgs, ",")
	} else {
		Config.TetragonContainerArgs = []string{tetragonContainerArgsDefault}
	}
	Config.TetragonContainerTerminationMessagePath = viper.GetString(tetragonContainerTerminationMessagePathKey)
	if Config.TetragonContainerTerminationMessagePath == "" {
		Config.TetragonContainerTerminationMessagePath = tetragonContainerTerminationMessagePathDefault
	}
	Config.TetragonContainerTerminationMessagePolicy = corev1.TerminationMessagePolicy(viper.GetString(tetragonContainerTerminationMessagePolicyKey))
	if Config.TetragonContainerTerminationMessagePolicy == "" {
		Config.TetragonContainerTerminationMessagePolicy = tetragonContainerTerminationMessagePolicyDefault
	}
	Config.TetragonContainerImagePullPolicy = corev1.PullPolicy(viper.GetString(tetragonContainerImagePullPolicyKey))
	if Config.TetragonContainerImagePullPolicy == "" {
		Config.TetragonContainerImagePullPolicy = tetragonContainerImagePullPolicyDefault
	}

	tetragonContainerLivenessProbeCommand := viper.GetString(tetragonContainerLivenessProbeCommandKey)
	if tetragonContainerLivenessProbeCommand != "" {
		Config.TetragonContainerLivenessProbeCommand = strings.Split(tetragonContainerLivenessProbeCommand, ",")
	} else {
		Config.TetragonContainerLivenessProbeCommand = tetragonContainerLivenessProbeCommandDefault
	}
	Config.TetragonContainerLivenessProbeTimeoutSec = viper.GetInt32(tetragonContainerLivenessProbeTimeoutSecondsKey)
	if Config.TetragonContainerLivenessProbeTimeoutSec == 0 {
		Config.TetragonContainerLivenessProbeTimeoutSec = tetragonContainerLivenessProbeTimeoutSecondsDefault
	}
	Config.TetragonContainerLivenessProbePeriodSec = viper.GetInt32(tetragonContainerLivenessProbePeriodSecondsKey)
	if Config.TetragonContainerLivenessProbePeriodSec == 0 {
		Config.TetragonContainerLivenessProbePeriodSec = tetragonContainerLivenessProbePeriodSecondsDefault
	}
	Config.TetragonContainerLivenessProbeSuccessThreshold = viper.GetInt32(tetragonContainerLivenessProbeSuccessThresholdKey)
	if Config.TetragonContainerLivenessProbeSuccessThreshold == 0 {
		Config.TetragonContainerLivenessProbeSuccessThreshold = tetragonContainerLivenessProbeSuccessThresholdDefault
	}
	Config.TetragonContainerLivenessProbeFailureThreshold = viper.GetInt32(tetragonContainerLivenessProbeFailureThresholdKey)
	if Config.TetragonContainerLivenessProbeFailureThreshold == 0 {
		Config.TetragonContainerLivenessProbeFailureThreshold = tetragonContainerLivenessProbeFailureThresholdDefault
	}

	Config.DaemonSetRestartPolicy = corev1.RestartPolicy(viper.GetString(daemonSetRestartPolicy))
	if Config.DaemonSetRestartPolicy == "" {
		Config.DaemonSetRestartPolicy = daemonSetRestartPolicyDefault
	}
	terminationGracePeriod := viper.GetString(daemonSetTerminationGracePeriodSeconds)
	if terminationGracePeriod != "" {
		i, err := strconv.Atoi(terminationGracePeriod)
		if err != nil {
			panic(fmt.Errorf("%s value is invalid: %s", daemonSetTerminationGracePeriodSeconds, terminationGracePeriod))
		}
		Config.DaemonSetTerminationGracePeriodSeconds = int64(i)
	} else {
		Config.DaemonSetTerminationGracePeriodSeconds = daemonSetTerminationGracePeriodSecondsDefault
	}
	Config.DaemonSetDNSPolicy = corev1.DNSPolicy(viper.GetString(daemonSetDNSPolicy))
	if Config.DaemonSetDNSPolicy == "" {
		Config.DaemonSetDNSPolicy = daemonSetDNSPolicyDefault
	}
	Config.DaemonSetServiceAccountName = viper.GetString(daemonSetServiceAccountName)
	if Config.DaemonSetServiceAccountName == "" {
		Config.DaemonSetServiceAccountName = daemonSetServiceAccountNameDefault
	}
	hostNetwork := viper.GetString(daemonSetHostNetwork)
	if hostNetwork != "" {
		b, err := strconv.ParseBool(hostNetwork)
		if err != nil {
			panic(fmt.Errorf("%s value is invalid: %s", daemonSetHostNetwork, hostNetwork))
		}
		Config.DaemonSetHostNetwork = b
	} else {
		Config.DaemonSetHostNetwork = daemonSetHostNetworkDefault
	}
	Config.DaemonSetSchedulerName = viper.GetString(daemonSetSchedulerName)
	if Config.DaemonSetSchedulerName == "" {
		Config.DaemonSetSchedulerName = daemonSetSchedulerNameDefault
	}

	updateMaxUnavailable := viper.GetString(daemonSetUpdateMaxUnavailable)
	if updateMaxUnavailable != "" {
		i, err := strconv.Atoi(updateMaxUnavailable)
		if err != nil {
			panic(fmt.Errorf("%s value is invalid: %s", daemonSetUpdateMaxUnavailable, updateMaxUnavailable))
		}
		Config.DaemonSetUpdateMaxUnavailable = int32(i)
	} else {
		Config.DaemonSetUpdateMaxUnavailable = daemonSetUpdateMaxUnavailableDefault
	}
	updateMaxSurge := viper.GetString(daemonSetUpdateMaxSurge)
	if updateMaxSurge != "" {
		i, err := strconv.Atoi(updateMaxSurge)
		if err != nil {
			panic(fmt.Errorf("%s value is invalid: %s", daemonSetUpdateMaxSurge, updateMaxSurge))
		}
		Config.DaemonSetUpdateMaxSurge = int32(i)
	}
}
