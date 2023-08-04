package main

import (
	"fmt"
	"os"

	"github.com/cilium/tetragon/cmd/tetra/bugtool"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/cmd/tetra/sensors"
	"github.com/cilium/tetragon/cmd/tetra/stacktracetree"
	"github.com/cilium/tetragon/cmd/tetra/status"
	"github.com/cilium/tetragon/cmd/tetra/tracingpolicy"
	"github.com/cilium/tetragon/cmd/tetra/version"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/cmd/tetra/file"
	"github.com/isovalent/hubble-fgs/cmd/tetra/getevents"
	"github.com/isovalent/hubble-fgs/cmd/tetra/record"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	rootCmd *cobra.Command
)

func main() {
	if err := New().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func New() *cobra.Command {
	rootCmd = &cobra.Command{
		Use:   "tetra",
		Short: "Tetra Enterprise CLI",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if viper.GetBool(common.KeyDebug) {
				logger.DefaultLogger.SetLevel(logrus.DebugLevel)
			}
		},
	}

	rootCmd.AddCommand(bugtool.New())
	rootCmd.AddCommand(getevents.New())
	rootCmd.AddCommand(sensors.New())
	rootCmd.AddCommand(stacktracetree.New())
	rootCmd.AddCommand(status.New())
	rootCmd.AddCommand(tracingpolicy.New())
	rootCmd.AddCommand(file.New())
	rootCmd.AddCommand(record.New())
	rootCmd.AddCommand(version.New())

	flags := rootCmd.PersistentFlags()
	flags.BoolP(common.KeyDebug, "d", false, "Enable debug messages")
	flags.String(common.KeyServerAddress, "localhost:54321", "gRPC server address")
	viper.BindPFlags(flags)
	return rootCmd
}
