// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package vrf

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
)

func init() {
	addCmd.Flags().StringP("name", "n", "", "VRF name")
	addCmd.Flags().Uint16P("affinity", "a", 0, "DPU affinity (0=dynamic, 1..N=specific DPU; defaults to 0)")
	VrfCmd.AddCommand(addCmd)
}

var addCmd = &cobra.Command{
	Use:          "add",
	SilenceUsage: true,
	Short:        "Add a VRF to the mock gNMI handler",
	Long:         `Send global and service VRF gNMI notifications so the VRF becomes active in the domain store.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		name, err := cmd.Flags().GetString("name")
		if err != nil {
			return err
		}
		if name == "" {
			return errors.New("--name is required")
		}

		flags := map[string]string{
			"name": name,
			"json": fmt.Sprintf("%t", agwctl.JSON),
		}

		if cmd.Flags().Changed("affinity") {
			affinity, err := cmd.Flags().GetUint16("affinity")
			if err != nil {
				return err
			}
			flags["affinity"] = fmt.Sprintf("%d", affinity)
		}

		data := ipc.MessageData{Flags: flags}
		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_MOCK_VRF_ADD, data)
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, agwctl.JSON)
		return nil
	},
}
