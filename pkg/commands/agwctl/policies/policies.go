package policies

import (
	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
)

func init() {
	agwctl.RootCmd.AddCommand(PoliciesCmd)
}

// PoliciesCmd represents the policies command
var PoliciesCmd = &cobra.Command{
	Use:          "policies",
	SilenceUsage: true,
	Short:        "Manage policies",
	Long:         `Manage policies - add, remove, or show policies.`,
}
