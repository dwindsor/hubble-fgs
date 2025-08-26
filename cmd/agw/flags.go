package main

type config struct {
	DafConfig        string
	NetworkPolicies  []string
	EnableKubernetes bool
}

var (
	Config = config{
		DafConfig:        "/opt/cisco/daf/etc/dafconfig",
		NetworkPolicies:  []string{},
		EnableKubernetes: true,
	}
)

const (
	keyDafConfig     = "config" // The original AGW config!
	keyNetworkPolicy = "network-policy"
	keyEnableK8s     = "enable-k8s"
)
