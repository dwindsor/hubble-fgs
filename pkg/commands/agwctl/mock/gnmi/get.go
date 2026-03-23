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
	getCmd.Flags().StringP("path", "p", "", "gNMI path to retrieve")
	GnmiCmd.AddCommand(getCmd)
}

var getCmd = &cobra.Command{
	Use:          "get",
	SilenceUsage: true,
	Short:        "Get a value from the mock gNMI handler by path",
	Long:         `Retrieve the value stored at a specific gNMI path in the mock handler.`,
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

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_MOCK_GNMI_GET, data)
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, agwctl.JSON)
		return nil
	},
}
