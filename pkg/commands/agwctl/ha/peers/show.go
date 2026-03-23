// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package peers

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
)

func init() {
	showCmd.Flags().StringP("filter", "", "", "Regex filter on peer IP")
	PeersCmd.AddCommand(showCmd)
}

var showCmd = &cobra.Command{
	Use:          "show",
	SilenceUsage: true,
	Short:        "Show HA peer details",
	Long:         `Show per-peer HA state details. Use --filter to match peer IPs by regex.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		filter, err := cmd.Flags().GetString("filter")
		if err != nil {
			return err
		}

		data := ipc.MessageData{
			Flags: map[string]string{
				"filter": filter,
				"json":   fmt.Sprintf("%t", agwctl.JSON),
			},
		}

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_HA_PEERS, data)
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, agwctl.JSON)
		return nil
	},
}
