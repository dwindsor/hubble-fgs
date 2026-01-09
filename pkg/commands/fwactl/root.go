// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package fwactl

import (
	"errors"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/version"
)

var (
	JSON           = false
	CONFIG_LIST    = []string{"/tmp/fwactl.json", "/opt/cisco/daf/etc/dafconfig", "/opt/cisco/hypershield/etc/dafconfig", "/nic/conf/hypershield/firewall.json"}
	CONFIG         = "/tmp/fwactl.json"
	DP_SOCKET_PATH = "/tmp/daf_dp0_cpa.sock"
)

func getVersion() string {
	if version.Version == "" {
		return "dev"
	}
	return version.Version
}

// rootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:          "fwactl",
	SilenceUsage: true,
	Version:      getVersion(),
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
