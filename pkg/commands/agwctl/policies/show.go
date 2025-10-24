package policies

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
)

func init() {
	showCmd.Flags().StringP("filter", "", "", "ResourceID filter for listing policies")
	PoliciesCmd.AddCommand(showCmd)
}

var showCmd = &cobra.Command{
	Use:          "show",
	SilenceUsage: true,
	Short:        "Show policies by ResourceID, which is kubernetes 'kind/namespace/name'",
	Long:         `Show one or all policies, which is kubernetes 'kind/namespace/name'.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		filter, err := cmd.Flags().GetString("filter")
		if err != nil {
			return err
		}

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_POLICIES_SHOW, filter)
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, false)
		return nil
	},
}
