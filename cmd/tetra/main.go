// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.
package tetra

import (
	"log/slog"
	"os"
	"time"

	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/spf13/cobra"
)

var (
	rootCmd *cobra.Command
)

func New() *cobra.Command {
	rootCmd = &cobra.Command{
		Use:   "tetra",
		Short: "Tetra Enterprise CLI",
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Help()
		},
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			if common.Debug {
				logger.SetLogLevel(slog.LevelDebug)
			}
		},
	}

	// by default, it fallbacks to stderr
	rootCmd.SetOut(os.Stdout)

	addCommands(rootCmd)

	flags := rootCmd.PersistentFlags()
	flags.BoolVarP(&common.Debug, common.KeyDebug, "d", false, "Enable debug messages")
	flags.StringVar(&common.ServerAddress, common.KeyServerAddress, "", "gRPC server address")
	flags.DurationVar(&common.Timeout, common.KeyTimeout, 30*time.Second, "Connection timeout")
	flags.IntVar(&common.Retries, common.KeyRetries, 1, "Connection retries with exponential backoff")
	return rootCmd
}
