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

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/version"

	_ "github.com/isovalent/hubble-fgs/operator/agent" // needed to init network policy schema
)

const (
	MaxProcs = 128
)

var (
	rootCmd *cobra.Command
)

func getVersion() string {
	if version.Version == "" {
		return "dev"
	}
	return version.Version
}

func Execute() error {
	rootCmd = &cobra.Command{
		Use:     "agw",
		Short:   "Hypershield AGW",
		Version: getVersion(),
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Help()
		},
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			if Config.Debug {
				logger.SetLogLevel(slog.LevelDebug)
			}
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			logger.GetLogger().Info("Starting SmartSwitch AGW", "version", getVersion())
			executeAGW()
			return nil
		},
	}

	rootCmd.SetOut(os.Stdout)

	flags := rootCmd.PersistentFlags()
	flags.StringVar(&Config.DafConfig, keyDafConfig, Config.DafConfig, "Path to config file")
	flags.BoolVar(&Config.EnableKubernetes, keyEnableK8s, Config.EnableKubernetes, "Enable Kubernetes control plane")
	flags.BoolVar(&Config.EnableNXOS, keyEnableNXOS, Config.EnableNXOS, "Enable Nexus smartswitch")
	flags.StringSliceVar(&Config.NetworkPolicies, keyNetworkPolicy, Config.NetworkPolicies, "network policy files")
	flags.StringVar(&Config.NetworkPoliciesDir, keyNetworkPolicyDir, Config.NetworkPoliciesDir, "network policy dir")
	flags.StringVar(&Config.DPUServerAddress, keyDPUServerAddress, Config.DPUServerAddress, "DPU server address")
	flags.StringSliceVar(&Config.VrfMap, keyVrfMap, Config.VrfMap, "Prepopulate VRF map")
	flags.StringVar(&Config.GopsAddr, keyGopsAddress, Config.GopsAddr, "Gops Address")
	flags.BoolVar(&Config.Debug, keyDebug, Config.Debug, "Enable debug")
	flags.StringVar(&Config.K8sServiceAccountAuth, keyK8sServiceAccountAuth, Config.K8sServiceAccountAuth, "Base64 encoded of <API_SERVER>|<TOKEN>|<CA_CERT> to access the k8s API server")
	flags.BoolVar(&Config.TimescapeClientEnable, keyTimescapeClientEnable, Config.TimescapeClientEnable, "Enable Timescape client")
	flags.StringVar(&Config.TimescapePassword, keyTimescapePassword, Config.TimescapePassword, "Timescape server authentication password")
	flags.StringVar(&Config.TimescapeEndpoint, keyTimescapeEndpoint, Config.TimescapeEndpoint, "Timescape server endpoint URL")
	flags.BoolVar(&Config.PrometheusClientEnable, keyPrometheusClientEnable, Config.PrometheusClientEnable, "Enable Prometheus client")
	flags.StringVar(&Config.PrometheusPassword, keyPrometheusPassword, Config.PrometheusPassword, "Prometheus server authentication password")
	flags.StringVar(&Config.PrometheusUsername, keyPrometheusUsername, Config.PrometheusUsername, "Prometheus server authentication username")
	flags.StringVar(&Config.PrometheusEndpoint, keyPrometheusEndpoint, Config.PrometheusEndpoint, "Prometheus server endpoint URL")
	flags.StringVar(&Config.FlbSocketPath, keyFlbSocketPath, Config.FlbSocketPath, "FluentBit unix socket path for AGW log mirroring")
	flags.StringVar(&Config.FlbConfigPath, keyFlbConfigPath, Config.FlbConfigPath, "FluentBit YAML config path for AGW-managed FluentBit instance")
	return rootCmd.Execute()
}

func main() {
	// setup logging format
	o := make(map[string]string)
	o[logger.FormatOpt] = "text-ts"
	if err := logger.SetupLogging(o, false); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if err := Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
