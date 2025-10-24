package main

type cliConfig struct {
	DafConfig       string
	NetworkPolicies []string
	ServerAddress   string
	DpSocketPath    string
	EnableDataplane bool
	EnableAgw       bool
	EnableLogger    bool
	Debug           bool
}

var (
	Config = cliConfig{
		DafConfig:       "/nic/conf/hypershield/firewall.json",
		NetworkPolicies: []string{},
		ServerAddress:   "169.254.101.2:8880",
		DpSocketPath:    "/tmp/daf_dp0_cpa.sock",
		Debug:           false,
		EnableDataplane: true,
		EnableAgw:       true,
		EnableLogger:    true,
	}
)

const (
	keyDafConfig       = "config" // The original AGW config!
	keyNetworkPolicy   = "network-policy"
	keyServerAddress   = "server-address"
	keyDpSocketPath    = "dp-socket-path"
	keyEnableDataplane = "enable-dataplane"
	keyEnableAgw       = "enable-agw"
	keyEnableLogger    = "enable-logger"
	keyDebug           = "debug"
)

// redactedConfig returns a copy of the Config with sensitive fields redacted.
func redactedConfig() cliConfig {
	redacted := Config
	return redacted
}
