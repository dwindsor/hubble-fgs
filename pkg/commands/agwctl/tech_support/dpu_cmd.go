// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package techsupport

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
)

var withCores bool

func init() {
	TechSupportCmd.AddCommand(dpuCmd)
	dpuCmd.Flags().BoolVar(&withCores, "with-cores", false, "Include core dumps in collection")
}

var dpuCmd = &cobra.Command{
	Use:          "dpu",
	SilenceUsage: true,
	Short:        "Collect DPU tech support data",
	Long:         `Collect comprehensive tech support data from all DPUs including logs, configuration files, and optionally core dumps.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Build command data with flags
		var args []string
		if withCores {
			args = append(args, "--with-cores")
		}

		messageData := ipc.MessageData{
			Args: args,
		}

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_TECH_SUPPORT_DPU, messageData)
		if err != nil {
			return err
		}

		if ret.ReturnCode != "ok" {
			return fmt.Errorf("command failed: %s", ret.Data)
		}

		fmt.Print(ret.Data)
		return nil
	},
}
