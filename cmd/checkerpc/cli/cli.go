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
	"time"

	"github.com/isovalent/hubble-fgs/cmd/checkerpc/cli/check"
	"github.com/isovalent/hubble-fgs/cmd/checkerpc/cli/flags"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// New creates a new cobra.Command struct for checkerpc.
func New(ctx context.Context) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "checkerpc",
		Short: "Run eventchecker over gRPC",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	rootCmd.AddCommand(check.New(ctx))

	cliFlags := rootCmd.PersistentFlags()

	cliFlags.StringSliceP(flags.KeyServerAddresses, "s", []string{"localhost:54321"},
		"gRPC server address(es) to connect to")

	cliFlags.DurationP(flags.KeyConnectTimeout, "T", 1*time.Minute,
		"timeout for connecting to the gRPC servers, 0 implies no time limit")

	viper.BindPFlags(cliFlags)

	return rootCmd
}
