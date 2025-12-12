package policies

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
)

func init() {
	PoliciesCmd.AddCommand(infoCmd)
}

var infoCmd = &cobra.Command{
	Use:          "info",
	SilenceUsage: true,
	Short:        "Show a summary of all loaded policies",
	Long: `Display a summary of all loaded policies including:
  - Total number of policies and rules
  - Number of allow vs deny rules
  - Policies and rules per namespace
  - VRFs and VLANs in use
  - Protocol distribution`,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		data := ipc.MessageData{
			Flags: map[string]string{
				"json": fmt.Sprintf("%t", agwctl.JSON),
			},
		}

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_POLICIES_INFO, data)
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, agwctl.JSON)
		return nil
	},
}
