package main

type config struct {
	DafConfig        string
	NetworkPolicies  []string
	EnableKubernetes bool
	EnableNXOS       bool
	DPUServerAddress string
	VrfMap           []string
	Debug            bool
}

var (
	Config = config{
		DafConfig:        "/opt/cisco/daf/etc/dafconfig",
		NetworkPolicies:  []string{},
		EnableKubernetes: true,
		EnableNXOS:       true,
		DPUServerAddress: "127.0.0.1:9090",
		VrfMap:           []string{},
		Debug:            false,
	}
)

const (
	keyDafConfig        = "config" // The original AGW config!
	keyNetworkPolicy    = "network-policy"
	keyEnableK8s        = "enable-k8s"
	keyEnableNXOS       = "enable-nxos"
	keyDPUServerAddress = "dpu-server-address"
	keyVrfMap           = "vrf-map"
	keyDebug            = "debug"
)
