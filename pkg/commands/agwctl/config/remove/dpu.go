// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package remove

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
)

func init() {
	RemoveCmd.AddCommand(dpuCmd)
}

var dpuCmd = &cobra.Command{
	Use:          "dpu",
	SilenceUsage: true,
	Short:        "Remove DPU configuration",
	Long:         `Remove DPU configuration.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		data := ipc.MessageData{}

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_CONFIG_REMOVE_DPU, data)
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, false)
		return nil
	},
}
