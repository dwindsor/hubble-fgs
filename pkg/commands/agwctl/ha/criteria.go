// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package ha

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
)

func init() {
	HaCmd.AddCommand(CriteriaCmd)
	CriteriaCmd.AddCommand(criteriaFailCmd)
	CriteriaCmd.AddCommand(criteriaOkCmd)
}

// CriteriaCmd groups "ha criteria" subcommands.
var CriteriaCmd = &cobra.Command{
	Use:          "criteria",
	SilenceUsage: true,
	Short:        "Manage HA debug criteria",
	Long:         `Manage HA debug criteria for testing and diagnostics.`,
}

var criteriaFailCmd = &cobra.Command{
	Use:          "fail",
	SilenceUsage: true,
	Short:        "Set debug_override criterion to false (force ha-switchover)",
	Long:         `Set the debug_override HA criterion to false, forcing the local node into ha-switchover state.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_HA_CRITERIA_FAIL, ipc.MessageData{})
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, agwctl.JSON)
		return nil
	},
}

var criteriaOkCmd = &cobra.Command{
	Use:          "ok",
	SilenceUsage: true,
	Short:        "Set debug_override criterion to true (allow normal evaluation)",
	Long:         `Set the debug_override HA criterion to true, allowing normal criteria evaluation to resume.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_HA_CRITERIA_OK, ipc.MessageData{})
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, agwctl.JSON)
		return nil
	},
}
