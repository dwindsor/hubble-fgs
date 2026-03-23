// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package gnmi

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
)

func init() {
	deleteCmd.Flags().StringP("path", "p", "", "gNMI path to delete")
	GnmiCmd.AddCommand(deleteCmd)
}

var deleteCmd = &cobra.Command{
	Use:          "delete",
	SilenceUsage: true,
	Short:        "Delete a path from the mock gNMI handler and notify subscribers",
	Long:         `Remove a gNMI path from the mock handler and fire gNMI notifications to registered subscribers.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		path, err := cmd.Flags().GetString("path")
		if err != nil {
			return err
		}
		if path == "" {
			return errors.New("--path is required")
		}

		data := ipc.MessageData{
			Flags: map[string]string{
				"path": path,
				"json": fmt.Sprintf("%t", agwctl.JSON),
			},
		}

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_MOCK_GNMI_DELETE, data)
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, agwctl.JSON)
		return nil
	},
}
