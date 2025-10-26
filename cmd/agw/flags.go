package main

import "github.com/spf13/viper"

type cliConfig struct {
	DafConfig             string
	NetworkPolicies       []string
	EnableKubernetes      bool
	EnableNXOS            bool
	DPUServerAddress      string
	GopsAddr              string
	VrfMap                []string
	Debug                 bool
	K8sServiceAccountAuth string
}

var (
	Config = cliConfig{
		DafConfig:             "/opt/cisco/daf/etc/dafconfig",
		NetworkPolicies:       []string{},
		EnableKubernetes:      true,
		EnableNXOS:            true,
		DPUServerAddress:      "0.0.0.0:8880",
		GopsAddr:              "localhost:8118",
		VrfMap:                []string{},
		Debug:                 false,
		K8sServiceAccountAuth: viper.GetString(keyK8sServiceAccountAuth),
	}
)

const (
	keyDafConfig             = "config" // The original AGW config!
	keyGopsAddress           = "gops-address"
	keyNetworkPolicy         = "network-policy"
	keyEnableK8s             = "enable-k8s"
	keyEnableNXOS            = "enable-nxos"
	keyDPUServerAddress      = "dpu-server-address"
	keyVrfMap                = "vrf-map"
	keyDebug                 = "debug"
	keyK8sServiceAccountAuth = "k8s-service-account-auth"
)

// redactedConfig returns a copy of the Config with sensitive fields redacted.
func redactedConfig() cliConfig {
	redacted := Config
	if Config.K8sServiceAccountAuth != "" {
		redacted.K8sServiceAccountAuth = "[redacted]"
	}
	return redacted
}
