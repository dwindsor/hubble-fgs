package policies

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
)

func init() {
	translateCmd.Flags().StringP("file", "f", "", "Path to policy YAML file")
	translateCmd.MarkFlagRequired("file")
	PoliciesCmd.AddCommand(translateCmd)
}

var translateCmd = &cobra.Command{
	Use:          "translate",
	SilenceUsage: true,
	Short:        "Translate policies in a YAML file to DPU json format",
	Long: `Reads all policies defined in a YAML file and translates it into the json rule format
that is used by the dataplane on the DPU.  This prints rules based on the active
vrfs defined in the AGW.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		filePath, err := cmd.Flags().GetString("file")
		if err != nil {
			return err
		}

		data := ipc.MessageData{
			Flags: map[string]string{
				"file": filePath,
				"json": fmt.Sprintf("%t", agwctl.JSON),
			},
		}

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_POLICIES_TRANSLATE, data)
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, agwctl.JSON)
		return nil
	},
}
