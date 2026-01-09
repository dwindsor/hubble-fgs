// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package logging

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
)

func init() {
	loggingCmd.Flags().StringP("level", "l", "", "Logging level")
	loggingCmd.MarkFlagRequired("level")
	agwctl.RootCmd.AddCommand(loggingCmd)
}

var loggingCmd = &cobra.Command{
	Use:          "logging",
	SilenceUsage: true,
	Short:        "Set logging level for agw process",
	Long: `Set the logging level for the agw process to any of the following:
	- debug
	- info (default)
	- warn
	- error`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		level, err := cmd.Flags().GetString("level")
		if err != nil {
			return err
		}

		switch level {
		case "debug":
		case "info":
		case "warn":
		case "error":
		default:
			return fmt.Errorf("invalid log level %s", level)
		}

		data := ipc.MessageData{
			Flags: map[string]string{
				"level": level,
				"json":  fmt.Sprintf("%t", agwctl.JSON),
			},
		}

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_LOGGING, data)
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, agwctl.JSON)
		return nil
	},
}
