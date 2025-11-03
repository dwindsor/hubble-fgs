package config

import (
	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/spf13/cobra"
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
