package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/pkg/logger"
)

var (
	rootCmd *cobra.Command
)

func Execute() error {
	rootCmd = &cobra.Command{
		Use:   "fwa",
		Short: "Hypershield FWA",
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Help()
		},
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			if Config.Debug {
				logger.SetLogLevel(slog.LevelDebug)
			}
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			executeFWA()
			return nil
		},
	}

	rootCmd.SetOut(os.Stdout)

	flags := rootCmd.PersistentFlags()
	flags.StringVar(&Config.DafConfig, keyDafConfig, "/opt/cisco/daf/etc/dafconfig", "Path to config file")
	flags.StringSliceVar(&Config.NetworkPolicies, keyNetworkPolicy, []string{}, "network policy files")
	flags.StringVar(&Config.ServerAddress, keyServerAddress, "", "server address")
	flags.BoolVar(&Config.Debug, keyDebug, false, "debug level")
	return rootCmd.Execute()
}

func main() {
	if err := Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
