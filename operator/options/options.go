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

	kubeCfgPath = "kube-config"

	manageTetragonDaemonSet            = "manage-tetragon-ds"
	daemonSetImagePullPolicyKey        = "ds-image-pull-policy"
	daemonSetImagePullPolicyDefault    = corev1.PullIfNotPresent
	daemonSetExportDirectoryKey        = "ds-export-directory"
	daemonSetExportDirectoryDefault    = "/var/run/cilium/tetragon"
	daemonSetDNSPolicy                 = "ds-dns-policy"
	daemonSetDNSPolicyDefault          = corev1.DNSDefault
	daemonSetServiceAccountName        = "ds-service-account-name"
	daemonSetServiceAccountNameDefault = "tetragon"
	daemonSetHostNetwork               = "ds-host-network"
	daemonSetHostNetworkDefault        = true

	tetragonDaemonSetNamespaceKey     = "ds-namespace"
	tetragonDaemonSetNamespaceDefault = "kube-system"

	exportContainerModeKey          = "ds-export-mode"
	exportContainerImageKey         = "EXPORT_IMAGE"
	exportContainerImageDefault     = "quay.io/isovalent/hubble-export-stdout:v1.0.4"
	exportContainerFilenamesKey     = "ds-export-filenames"
	exportContainerFilenamesDefault = "tetragon.log"

	tetragonContainerImageKey           = "TETRAGON_IMAGE"
	tetragonContainerImageDefault       = "quay.io/isovalent/tetragon:v1.13.0-pre.1"
	tetragonContainerArgsOverrideKey    = "ds-tetragon-args-override"
	tetragonContainerGRPCEnabledKey     = "ds-tetragon-grpc-enabled"
	tetragonContainerGRPCEnabledDefault = true
	tetragonContainerGRPCAddressKey     = "ds-tetragon-grpc-address"
	tetragonContainerGRPCAddressDefault = "localhost:54321"
)

// OperatorConfig is the configuration used by the operator.
type OperatorConfig struct {
	// KubeCfgPath allows users to specify a kubeconfig file to be used by the operator
	KubeCfgPath string

	ManageDaemonSet             bool
	DaemonSetNamespace          string
	DaemonSetImagePullPolicy    corev1.PullPolicy
	DaemonSetExportDirectory    string
	DaemonSetDNSPolicy          corev1.DNSPolicy
	DaemonSetServiceAccountName string
	DaemonSetHostNetwork        bool

	ExportContainerMode      string
	ExportContainerImage     string
	ExportContainerFilenames []string

	TetragonContainerImage        string
	TetragonContainerArgsOverride []string
	TetragonContainerGRPCEnabled  bool
	TetragonContainerGRPCAddr     string
}

// Config represents the operator configuration.
var Config = &OperatorConfig{}

// ConfigPopulate sets all options with the values from viper.
func ConfigPopulate() {
	Config.KubeCfgPath = viper.GetString(kubeCfgPath)

	Config.ManageDaemonSet = viper.GetBool(manageTetragonDaemonSet)

	Config.DaemonSetNamespace = viper.GetString(tetragonDaemonSetNamespaceKey)
	if Config.DaemonSetNamespace == "" {
		Config.DaemonSetNamespace = tetragonDaemonSetNamespaceDefault
	}

	Config.DaemonSetImagePullPolicy = corev1.PullPolicy(viper.GetString(daemonSetImagePullPolicyKey))
	if Config.DaemonSetImagePullPolicy == "" {
		Config.DaemonSetImagePullPolicy = daemonSetImagePullPolicyDefault
	}

	Config.DaemonSetExportDirectory = viper.GetString(daemonSetExportDirectoryKey)
	if Config.DaemonSetExportDirectory == "" {
		Config.DaemonSetExportDirectory = daemonSetExportDirectoryDefault
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

	Config.ExportContainerMode = viper.GetString(exportContainerModeKey)

	Config.ExportContainerImage = os.Getenv(exportContainerImageKey)
	if Config.ExportContainerImage == "" {
		Config.ExportContainerImage = exportContainerImageDefault
	}

	exportFilenames := viper.GetString(exportContainerFilenamesKey)
	if exportFilenames != "" {
		Config.ExportContainerFilenames = strings.Split(exportFilenames, ",")
	} else {
		Config.ExportContainerFilenames = []string{exportContainerFilenamesDefault}
	}

	Config.TetragonContainerImage = os.Getenv(tetragonContainerImageKey)
	if Config.TetragonContainerImage == "" {
		Config.TetragonContainerImage = tetragonContainerImageDefault
	}

	args := viper.GetString(tetragonContainerArgsOverrideKey)
	if args != "" {
		Config.TetragonContainerArgsOverride = strings.Split(args, ",")
	}

	grpcEnabled := viper.GetString(tetragonContainerGRPCEnabledKey)
	if grpcEnabled != "" {
		b, err := strconv.ParseBool(grpcEnabled)
		if err != nil {
			panic(fmt.Errorf("%s value is invalid: %s", tetragonContainerGRPCEnabledKey, grpcEnabled))
		}
		Config.TetragonContainerGRPCEnabled = b
	} else {
		Config.TetragonContainerGRPCEnabled = tetragonContainerGRPCEnabledDefault
	}

	Config.TetragonContainerGRPCAddr = os.Getenv(tetragonContainerGRPCAddressKey)
	if Config.TetragonContainerGRPCAddr == "" {
		Config.TetragonContainerGRPCAddr = tetragonContainerGRPCAddressDefault
	}
}
