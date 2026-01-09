// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package policies

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
)

func init() {
	removeCmd.Flags().StringP("file", "f", "", "Path to policy YAML file")
	PoliciesCmd.AddCommand(removeCmd)
}

var removeCmd = &cobra.Command{
	Use:          "remove [resourceId]",
	SilenceUsage: true,
	Short:        "Remove a policy by resourceId or from a YAML file",
	Long:         `Remove a policy by providing its resourceId as an argument, or from a YAML file using the --file flag.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		filePath, err := cmd.Flags().GetString("file")
		if err != nil {
			return err
		}

		data := ipc.MessageData{
			Args: args,
			Flags: map[string]string{
				"file": filePath,
			},
		}

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_POLICIES_DEL, data)
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, agwctl.JSON)
		return nil
	},
}
