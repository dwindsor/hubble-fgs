package main

import (
	"github.com/isovalent/hubble-fgs/cmd/hubble-enterprise/bugtool"
	"github.com/isovalent/hubble-fgs/cmd/hubble-enterprise/common"
	"github.com/isovalent/hubble-fgs/cmd/hubble-enterprise/getevents"
	"github.com/isovalent/hubble-fgs/cmd/hubble-enterprise/sensors"
	"github.com/isovalent/hubble-fgs/cmd/hubble-enterprise/stacktracetree"
	"github.com/isovalent/hubble-fgs/cmd/hubble-enterprise/status"
	"github.com/isovalent/hubble-fgs/cmd/hubble-enterprise/tracingpolicy"
	"github.com/isovalent/hubble-fgs/cmd/hubble-enterprise/version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	rootCmd *cobra.Command
)

func init() {
	rootCmd = &cobra.Command{
		Use:   "hubble-enterprise",
		Short: "Hubble Enterprise CLI",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	rootCmd.AddCommand(bugtool.New())
	rootCmd.AddCommand(getevents.New())
	rootCmd.AddCommand(sensors.New())
	rootCmd.AddCommand(stacktracetree.New())
	rootCmd.AddCommand(status.New())
	rootCmd.AddCommand(tracingpolicy.New())
	rootCmd.AddCommand(version.New())

	flags := rootCmd.PersistentFlags()
	flags.BoolP(common.KeyDebug, "d", true, "Enable debug messages")
	flags.String(common.KeyServerAddress, "localhost:54321", "gRPC server address")
	viper.BindPFlags(flags)

}

func hubbleEnterpriseMain() {
	rootCmd.Execute()
}
