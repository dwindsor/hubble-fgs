package main

type config struct {
	DafConfig       string
	NetworkPolicies []string
	ServerAddress   string
}

var (
	Config = config{
		DafConfig:       "/opt/cisco/daf/etc/dafconfig",
		NetworkPolicies: []string{},
		ServerAddress:   "127.0.0.1:9090",
	}
)

const (
	keyDafConfig     = "config" // The original AGW config!
	keyNetworkPolicy = "network-policy"
	keyServerAddress = "server-address"
)
