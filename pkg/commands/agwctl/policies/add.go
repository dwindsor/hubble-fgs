package policies

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
)

func init() {
	addCmd.Flags().StringP("file", "f", "", "Path to policy YAML file")
	addCmd.MarkFlagRequired("file")
	PoliciesCmd.AddCommand(addCmd)
}

var addCmd = &cobra.Command{
	Use:          "add",
	SilenceUsage: true,
	Short:        "Add a policy from a YAML file",
	Long:         `Add a new policy from a YAML file.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		filePath, err := cmd.Flags().GetString("file")
		if err != nil {
			return err
		}

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_POLICIES_ADD, filePath)
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, false)
		return nil
	},
}
