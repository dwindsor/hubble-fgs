package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/version"
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
		Use:     "fwa",
		Short:   "Hypershield FWA",
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
			logger.GetLogger().Info("Starting SmartSwitch FWA", "version", getVersion())
			return executeFWA()
		},
	}

	rootCmd.SetOut(os.Stdout)

	flags := rootCmd.PersistentFlags()
	flags.StringVar(&Config.DafConfig, keyDafConfig, Config.DafConfig, "Path to config file")
	flags.StringSliceVar(&Config.NetworkPolicies, keyNetworkPolicy, Config.NetworkPolicies, "network policy files")
	flags.StringVar(&Config.ServerAddress, keyServerAddress, Config.ServerAddress, "server address")
	flags.StringVar(&Config.DpSocketPath, keyDpSocketPath, Config.DpSocketPath, "dp-app socket path")
	flags.BoolVar(&Config.EnableDataplane, keyEnableDataplane, Config.EnableDataplane, "Enable dataplane")
	flags.BoolVar(&Config.EnableAgw, keyEnableAgw, Config.EnableAgw, "Enable AGW connection")
	flags.BoolVar(&Config.EnableLogger, keyEnableLogger, Config.EnableLogger, "Enable fluentbit logger export")
	flags.BoolVar(&Config.Debug, keyDebug, Config.Debug, "debug level")
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
