// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package agwctl

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/pkg/version"
)

var (
	JSON     = false
	CONFIG   = "/tmp/agwctl.json"
	CLI_SOCK = "/run/agw.sock"
)

func getVersion() string {
	if version.Version == "" {
		return "dev"
	}
	return version.Version
}

// rootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:          "agwctl",
	SilenceUsage: true,
	Version:      getVersion(),
	Short:        "Interact directly with the Hypershield SmartSwitch agent",
	Long: `agwctl is a command line tool used to interact with the
 Hypershield SmartSwitch Agent. It can send control messages to the agent and 
 apply policy directly.
`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
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
