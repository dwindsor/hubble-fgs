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
	"github.com/spf13/viper"
)

// EE options

const (
	// SkipPolicySandboxCRD specifies whether operator will skip the creation of the
	// sandboxpolicy CRD
	SkipPolicySandboxCRD = "skip-policysandbox-crd"
	// TODO(FGI) constants should be made public
	kubeCfgPath = "kube-config"
)

// OperatorConfig is the configuration used by the operator.
type OperatorConfig struct {
	// KubeCfgPath allows users to specify a kubeconfig file to be used by the operator
	KubeCfgPath     string
	ManageDaemonSet bool
	// TODO(FGI): Rename DaemonSetNamespace to TetragonNamespace
	DaemonSetNamespace string
}

// Config represents the operator configuration.
// TODO(FGI): Don't use a package variable here
var Config = &OperatorConfig{}

// ConfigPopulate sets all options with the values from viper.
func ConfigPopulate() {
	Config.KubeCfgPath = viper.GetString(kubeCfgPath)

	Config.ManageDaemonSet = viper.GetBool("manage-agent")

	Config.DaemonSetNamespace = viper.GetString("namespace")
	if Config.DaemonSetNamespace == "" {
		Config.DaemonSetNamespace = "kube-system"
	}
}
