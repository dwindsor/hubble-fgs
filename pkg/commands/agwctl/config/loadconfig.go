// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package config

import (
	"context"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"

	"github.com/spf13/cobra"
)

var loadDpuConfigCmd = &cobra.Command{
	Use:          "load_dpu_config --file <file>",
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
	loadDpuConfigCmd.Flags().StringP("file", "f", "", "DPU config file path")
	loadDpuConfigCmd.MarkFlagRequired("file")
	ConfigCmd.AddCommand(loadDpuConfigCmd)
}
