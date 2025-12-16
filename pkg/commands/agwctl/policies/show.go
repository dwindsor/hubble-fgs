package policies

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
)

func init() {
	showCmd.Flags().StringP("filter", "", "", "ResourceID filter for listing policies, uses regex")
	PoliciesCmd.AddCommand(showCmd)
}

var showCmd = &cobra.Command{
	Use:          "show",
	SilenceUsage: true,
	Short:        "Show policies by ResourceID, which is kubernetes 'kind/namespace/name'",
	Long: `Show one or all policies, which is kubernetes 'kind/namespace/name'.  The --filter flag uses
regex strings to filter policy ResourceIDs.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		filter, err := cmd.Flags().GetString("filter")
		if err != nil {
			return err
		}

		data := ipc.MessageData{
			Flags: map[string]string{
				"filter": filter,
				"json":   fmt.Sprintf("%t", agwctl.JSON),
			},
		}

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_POLICIES_SHOW, data)
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, agwctl.JSON)
		return nil
	},
}
