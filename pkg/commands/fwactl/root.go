package fwactl

import (
	"errors"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/pkg/logger"
)

const (
	version = "0.0.1"
)

var (
	JSON        = false
	CONFIG_LIST = []string{"/tmp/fwactl.json", "/opt/cisco/daf/etc/dafconfig", "/opt/cisco/hypershield/etc/dafconfig", "/nic/conf/hypershield/firewall.json"}
	CONFIG      = "/tmp/fwactl.json"
)

// rootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:          "fwactl",
	SilenceUsage: true,
	Version:      version,
	Short:        "Interact directly with the Hypershield packet dispatcher and dataplanes",
	Long: `
+--------------------------------------------------------------+
|            ______ _       __ ___    ______ ______ __         |
|           / ____/| |     / //   |  / ____//_  __// /         |
|          / /_    | | /| / // /| | / /      / /  / /          |
|         / __/    | |/ |/ // ___ |/ /___   / /  / /___        |
|        /_/       |__/|__//_/  |_|\____/  /_/  /_____/        |
+--------------------------------------------------------------+	
    FWACTL is a command line tool used to interact with the
  Hypershield packet dispatcher and dataplanes without the need
   for a control plane agent.  It can send control messages to
        the packet dispatcher, obtain additional debugging
    information, and communicate directly with the dataplanes.

`,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		// Checking if command is loadconfig
		if cmd.Annotations["command"] == "loadconfig" {
			return nil
		}

		// Iterate through CONFIG_LIST to check if any of the files exist
		for _, configPath := range CONFIG_LIST {
			_, err := os.Stat(configPath)
			if err == nil {
				// File exists, set it as the current CONFIG and return
				CONFIG = configPath
				return nil
			} else if !os.IsNotExist(err) {
				// Error other than file not existing
				return err
			}
		}
		return errors.New("fwactl config file not found, please run loadconfig")
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	logger.SetLogLevel(slog.LevelError)
	err := RootCmd.Execute()
	if err != nil {
		// fmt.Fprintf(os.Stderr, "Error: %s", err)
		os.Exit(1)
	}
}

func init() {
	// Allowing chained persistent pre run hooks
	cobra.EnableTraverseRunHooks = true

	RootCmd.PersistentFlags().BoolVar(&JSON, "json", false, "prints output in JSON format")
}
