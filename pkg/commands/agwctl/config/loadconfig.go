package config

import (
	"context"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
	"github.com/spf13/cobra"
)

var loadDpuConfigCmd = &cobra.Command{
	Use:          "load_dpu_config <file>",
	SilenceUsage: true,
	Short:        "Load DPU configuration from file",
	Long: `Load DPU configuration from file.  This replaces
			any existing DPU configuration.  It is in the format:
					{
			 			"service_ip": "192.168.1.101",
						"service_mac": "00:0c:0c:0c:0c:0c",
						"port_low": 28501,
						"port_high" : 28600
					}`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		filePath, err := cmd.Flags().GetString("file")
		if err != nil {
			return err
		}

		data := ipc.MessageData{
			Flags: map[string]string{
				"file": filePath,
			},
		}
		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_LOAD_DPU_CFG, data)
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, agwctl.JSON)
		return nil
	},
}

func init() {
	ConfigCmd.AddCommand(loadDpuConfigCmd)
}
