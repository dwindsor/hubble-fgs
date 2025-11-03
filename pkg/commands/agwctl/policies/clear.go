package policies

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
)

func init() {
	PoliciesCmd.AddCommand(clearCmd)
}

var clearCmd = &cobra.Command{
	Use:          "clear",
	SilenceUsage: true,
	Short:        "Clear all policies",
	Long:         `Clear all policies.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_POLICIES_CLEAR, ipc.MessageData{})
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, false)
		return nil
	},
}
