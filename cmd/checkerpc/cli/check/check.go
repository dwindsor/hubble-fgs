//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package check

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/isovalent/hubble-fgs/cmd/checkerpc/check"
	"github.com/isovalent/hubble-fgs/cmd/checkerpc/cli/flags"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func New(ctx context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check <check.yaml>",
		Short: "Run eventchecker over gRPC",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return err
			}

			if _, err := os.Stat(args[0]); err != nil {
				return fmt.Errorf("Invalid path `%s`: %w", args[0], err)
			}

			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			checkStr := args[0]
			serverAddresses := viper.GetStringSlice(flags.KeyServerAddresses)
			connectTimeout := viper.GetDuration(flags.KeyConnectTimeout)
			kernelVersion, _ := cmd.LocalFlags().GetString(flags.KeyKernelVersion)
			checkTimeout, _ := cmd.LocalFlags().GetDuration(flags.KeyEventsTimeout)
			eventLimit, _ := cmd.LocalFlags().GetUint64(flags.KeyEventsLimit)

			if err := check.RunChecks(ctx, checkStr, kernelVersion, serverAddresses, connectTimeout,
				checkTimeout, eventLimit); err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(1)
			}
		},
	}

	cliFlags := cmd.Flags()

	_, detectedVersion, _ := kernels.GetKernelVersion("", "/proc")
	cliFlags.StringP(flags.KeyKernelVersion, "k", detectedVersion,
		"kernel version string under which events are being generated")

	cliFlags.Uint64P(flags.KeyEventsLimit, "e", 1000000,
		"maximum number of events to check, 0 implies no limit")

	cliFlags.DurationP(flags.KeyEventsTimeout, "t", 5*time.Minute,
		"timeout for runnings checks, 0 implies no time limit")

	return cmd
}
