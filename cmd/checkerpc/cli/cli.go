//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package cli

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"time"

	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/isovalent/hubble-fgs/cmd/checkerpc/cli/flags"
	"github.com/isovalent/hubble-fgs/cmd/checkerpc/rpccheck"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// New creates a new cobra.Command struct for checkerpc.
func New(ctx context.Context) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "checkerpc",
		Short: "Run eventchecker over gRPC",
		RunE: func(cmd *cobra.Command, args []string) error {
			check := viper.GetString(flags.KeyCheck)
			if check == "" {
				return fmt.Errorf("you must provide a value for --check")
			}

			_, ok := rpccheck.Checks[check]
			if !ok {
				return fmt.Errorf("check \"%s\" is not in %v", check, reflect.ValueOf(rpccheck.Checks).MapKeys())
			}

			if err := rpccheck.RunChecks(ctx); err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(1)
			}

			return nil
		},
	}

	cliFlags := rootCmd.PersistentFlags()

	cliFlags.StringSliceP(flags.KeyServerAddresses, "a", []string{"localhost:54321"}, "gRPC server address(es) to connect to")

	cliFlags.Duration(flags.KeyConnectTimeout, 1*time.Minute,
		"timeout for connecting to the gRPC servers, 0 implies no time limit")

	cliFlags.StringP(flags.KeyCheck, "c", "", fmt.Sprintf("check to perform, can be one of %v",
		reflect.ValueOf(rpccheck.Checks).MapKeys()))

	_, detectedVersion, _ := kernels.GetKernelVersion("", "/proc")
	cliFlags.StringP(flags.KeyKernelVersion, "k", detectedVersion,
		"kernel version string under which events are being generated")

	cliFlags.Uint64P(flags.KeyEventsLimit, "e", 1000000,
		"maximum number of events to check, 0 implies no limit")

	cliFlags.DurationP(flags.KeyEventsTimeout, "t", 5*time.Minute,
		"timeout for runnings checks, 0 implies no time limit")

	viper.BindPFlags(cliFlags)

	return rootCmd
}
