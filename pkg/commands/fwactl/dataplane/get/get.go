package get

import (
	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/fwactl/dataplane"
)

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:          "get",
	SilenceUsage: true,
	Aliases:      []string{"g"},
	Short:        "Sends a debug request",
	Long: `Send a debug request in order to obtain additional
information that can be useful when debugging the dataplanes.`,
}

func init() {
	dataplane.DataplaneCmd.AddCommand(getCmd)
}
