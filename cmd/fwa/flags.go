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

type cliConfig struct {
	DafConfig       string
	NetworkPolicies []string
	ServerAddress   string
	DpSocketPath    string
	EnableDataplane bool
	EnableAgw       bool
	EnableLogger    bool
	Debug           bool
	GopsAddr        string
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
		GopsAddr:        "localhost:8118",
	}
)

const (
	keyDafConfig       = "config" // The original AGW config!
	keyGopsAddress     = "gops-address"
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
