package main

type config struct {
	DafConfig       string
	NetworkPolicies []string
	ServerAddress   string
	Debug           bool
}

var (
	Config = config{
		DafConfig:       "/opt/cisco/daf/etc/dafconfig",
		NetworkPolicies: []string{},
		ServerAddress:   "127.0.0.1:9090",
		Debug:           false,
	}
)

const (
	keyDafConfig     = "config" // The original AGW config!
	keyNetworkPolicy = "network-policy"
	keyServerAddress = "server-address"
	keyDebug         = "debug"
)
