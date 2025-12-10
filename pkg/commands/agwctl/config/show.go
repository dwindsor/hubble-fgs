package config

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
)

func init() {
	ConfigCmd.AddCommand(showCmd)
}

var showCmd = &cobra.Command{
	Use:          "show",
	SilenceUsage: true,
	Short:        "Show all config",
	Long:         `Show all config objects currently active.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		data := ipc.MessageData{
			Flags: map[string]string{
				"json": fmt.Sprintf("%t", agwctl.JSON),
			},
		}

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_CONFIG_SHOW, data)
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, agwctl.JSON)
		return nil
	},
}
