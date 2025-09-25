package policer

import (
	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/fwactl/dataplane"
)

var polCmd = &cobra.Command{
	Use:          "pol",
	SilenceUsage: true,
	Short:        "policer commands",
	Long:         "policer commands",
}

func init() {
	// fwactl dataplane pol [enable,disable]
	dataplane.DataplaneCmd.AddCommand(polCmd)
}
