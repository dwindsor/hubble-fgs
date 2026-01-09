// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package add

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
)

func init() {
	dpuCmd.Flags().StringP("file", "f", "", "Path to DPU config JSON file")
	dpuCmd.MarkFlagRequired("file")
	AddCmd.AddCommand(dpuCmd)
}

var dpuCmd = &cobra.Command{
	Use:          "dpu",
	SilenceUsage: true,
	Short:        "Add DPU configuration from a JSON file",
	Long:         `Add DPU configuration from a JSON file.`,
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

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_CONFIG_ADD_DPU, data)
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, false)
		return nil
	},
}
