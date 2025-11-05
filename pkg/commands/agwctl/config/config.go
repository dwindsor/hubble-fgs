package config

import (
	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
)

func init() {
	agwctl.RootCmd.AddCommand(ConfigCmd)
}

var ConfigCmd = &cobra.Command{
	Use:          "config",
	SilenceUsage: true,
	Short:        "Manage config",
	Long:         `Manage config - load dpu config.`,
}
