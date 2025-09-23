package main

import "github.com/spf13/viper"

type cliConfig struct {
	DafConfig             string
	NetworkPolicies       []string
	EnableKubernetes      bool
	EnableNXOS            bool
	DPUServerAddress      string
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
		DPUServerAddress:      "127.0.0.1:9090",
		VrfMap:                []string{},
		Debug:                 false,
		K8sServiceAccountAuth: viper.GetString(keyK8sServiceAccountAuth),
	}
)

const (
	keyDafConfig             = "config" // The original AGW config!
	keyNetworkPolicy         = "network-policy"
	keyEnableK8s             = "enable-k8s"
	keyEnableNXOS            = "enable-nxos"
	keyDPUServerAddress      = "dpu-server-address"
	keyVrfMap                = "vrf-map"
	keyDebug                 = "debug"
	keyK8sServiceAccountAuth = "k8s-service-account-auth"
)
