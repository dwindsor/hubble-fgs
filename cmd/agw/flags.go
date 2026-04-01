// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package main

import "github.com/spf13/viper"

type cliConfig struct {
	DafConfig              string
	NetworkPolicies        []string
	NetworkPoliciesDir     string
	EnableKubernetes       bool
	EnableNXOS             bool
	DPUServerAddress       string
	GopsAddr               string
	ConfigMap              string
	VrfMap                 []string
	Debug                  bool
	K8sServiceAccountAuth  string
	TimescapeClientEnable  bool
	TimescapePassword      string
	TimescapeEndpoint      string
	PrometheusClientEnable bool
	PrometheusUsername     string
	PrometheusPassword     string
	PrometheusEndpoint     string
	FlbSocketPath          string
	FlbConfigPath          string
}

var (
	Config = cliConfig{
		DafConfig:              "/opt/cisco/daf/etc/dafconfig",
		NetworkPolicies:        []string{},
		NetworkPoliciesDir:     "/iox_data/isovalent/policy/",
		EnableKubernetes:       true,
		EnableNXOS:             true,
		DPUServerAddress:       "0.0.0.0:8880",
		GopsAddr:               "localhost:8118",
		ConfigMap:              "smartswitch-log-config",
		VrfMap:                 []string{},
		Debug:                  false,
		K8sServiceAccountAuth:  viper.GetString(keyK8sServiceAccountAuth),
		TimescapeClientEnable:  viper.GetBool(keyTimescapeClientEnable),
		TimescapePassword:      viper.GetString(keyTimescapePassword),
		TimescapeEndpoint:      viper.GetString(keyTimescapeEndpoint),
		PrometheusClientEnable: viper.GetBool(keyPrometheusClientEnable),
		PrometheusUsername:     viper.GetString(keyPrometheusUsername),
		PrometheusPassword:     viper.GetString(keyPrometheusPassword),
		PrometheusEndpoint:     viper.GetString(keyPrometheusEndpoint),
		FlbSocketPath:          "",
		FlbConfigPath:          "",
	}
)

const (
	keyDafConfig              = "config" // The original AGW config!
	keyGopsAddress            = "gops-address"
	keyNetworkPolicy          = "network-policy"
	keyNetworkPolicyDir       = "network-policy-dir"
	keyEnableK8s              = "enable-k8s"
	keyEnableNXOS             = "enable-nxos"
	keyDPUServerAddress       = "dpu-server-address"
	keyConfigMap              = "configmap"
	keyVrfMap                 = "vrf-map"
	keyDebug                  = "debug"
	keyK8sServiceAccountAuth  = "k8s-service-account-auth"
	keyTimescapeClientEnable  = "timescape-client-enable"
	keyTimescapePassword      = "timescape-password"
	keyTimescapeEndpoint      = "timescape-endpoint"
	keyPrometheusClientEnable = "prometheus-client-enable"
	keyPrometheusUsername     = "prometheus-username"
	keyPrometheusPassword     = "prometheus-password"
	keyPrometheusEndpoint     = "prometheus-endpoint"
	keyFlbSocketPath          = "flb-socket-path"
	keyFlbConfigPath          = "flb-config-path"
)

// redactedConfig returns a copy of the Config with sensitive fields redacted.
func redactedConfig() cliConfig {
	redacted := Config
	if Config.K8sServiceAccountAuth != "" {
		redacted.K8sServiceAccountAuth = "[redacted]"
	}
	if Config.TimescapePassword != "" {
		redacted.TimescapePassword = "[redacted]"
	}
	if Config.PrometheusPassword != "" {
		redacted.PrometheusPassword = "[redacted]"
	}
	return redacted
}
