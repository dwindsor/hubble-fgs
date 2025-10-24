package policies

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
)

func init() {
	removeCmd.Flags().StringP("file", "f", "", "Path to policy YAML file")
	removeCmd.MarkFlagRequired("file")
	PoliciesCmd.AddCommand(removeCmd)
}

var removeCmd = &cobra.Command{
	Use:          "remove",
	SilenceUsage: true,
	Short:        "Remove a policy defined a YAML file",
	Long:         `Remove a policy that is defined in a YAML file.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		filePath, err := cmd.Flags().GetString("file")
		if err != nil {
			return err
		}

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_POLICIES_DEL, filePath)
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, false)
		return nil
	},
}
