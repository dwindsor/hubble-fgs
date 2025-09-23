package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/spf13/cobra"

	_ "github.com/isovalent/hubble-fgs/operator/agent" // needed to init network policy schema
)

const (
	MaxProcs = 128
)

var (
	rootCmd *cobra.Command
)

func Execute() error {
	rootCmd = &cobra.Command{
		Use:   "agw",
		Short: "Hypershield AGW",
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Help()
		},
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			if Config.Debug {
				logger.SetLogLevel(slog.LevelDebug)
			}
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			executeAGW()
			return nil
		},
	}

	rootCmd.SetOut(os.Stdout)

	flags := rootCmd.PersistentFlags()
	flags.StringVar(&Config.DafConfig, keyDafConfig, "/opt/cisco/daf/etc/dafconfig", "Path to config file")
	flags.BoolVar(&Config.EnableKubernetes, keyEnableK8s, true, "Enable Kubernetes control plane")
	flags.BoolVar(&Config.EnableNXOS, keyEnableNXOS, true, "Enable Nexus smartswitch")
	flags.StringSliceVar(&Config.NetworkPolicies, keyNetworkPolicy, []string{}, "network policy files")
	flags.StringVar(&Config.DPUServerAddress, keyDPUServerAddress, "", "DPU server address")
	flags.StringSliceVar(&Config.VrfMap, keyVrfMap, []string{}, "Prepopulate VRF map")
	flags.BoolVar(&Config.Debug, keyDebug, false, "Enable debug")
	flags.StringVar(&Config.K8sServiceAccountAuth, keyK8sServiceAccountAuth, "", "Base64 encoded of <API_SERVER>|<TOKEN>|<CA_CERT> to access the k8s API server")
	return rootCmd.Execute()
}

func main() {
	if err := Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
