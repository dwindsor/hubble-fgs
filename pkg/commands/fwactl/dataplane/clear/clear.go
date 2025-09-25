package clear

import (
	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/fwactl/dataplane"
)

// clearCmd represents the clear command
var clearCmd = &cobra.Command{
	Use:          "clear",
	SilenceUsage: true,
	Aliases:      []string{"c"},
	Short:        "Sends a debug request to clear/reset",
	Long:         `Send a debug request in order to clear/reset statistics to the dataplanes`,
}

func init() {
	dataplane.DataplaneCmd.AddCommand(clearCmd)
}
