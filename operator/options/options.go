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
	ManageAgentKey       = "manage-agent"
)

// OperatorConfig is the configuration used by the operator.
type OperatorConfig struct {
	// KubeconfigPath allows users to specify a kubeconfig file to be used by the operator
	KubeconfigPath    string
	ManageAgent       bool
	TetragonNamespace string
}

// NewConfig sets all options with the values from viper and returns OperatorConfig.
func NewConfig() OperatorConfig {
	namespace := viper.GetString("namespace")
	if namespace == "" {
		namespace = "default"
	}
	return OperatorConfig{
		KubeconfigPath:    viper.GetString("kube-config"),
		ManageAgent:       viper.GetBool(ManageAgentKey),
		TetragonNamespace: namespace,
	}
}
