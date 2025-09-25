//-----------------------------------------------------------------------------
// {C} Copyright 2023 AMD Inc. All rights reserved
//-----------------------------------------------------------------------------

package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/dpu/pensando/dpctl/cli/utils"
)

var (
	cfgFile string
	dscURL  string
	dscPort string
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "dpctl",
	Short: "DPCTL CLI",
	Long:  "\n----------------------\n AMD/Pensando Dataplane Services CLI \n----------------------\n",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the RootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	RootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	RootCmd.PersistentFlags().StringVar(&dscURL, "dsc-svc-ip",
		utils.GRPCDefaultBaseURL,
		"Remote DSC's service URL")
	RootCmd.PersistentFlags().StringVar(&dscPort, "dsc-svc-port",
		utils.PDSGRPCDefaultPort,
		"Remote DSC's service port")
}

// NewPdsctlCommand exports the RootCmd for bash-completion
func NewPdsctlCommand() *cobra.Command {
	return RootCmd
}

func initConfig() {
	utils.GRPCDefaultBaseURL = dscURL
	utils.PDSGRPCDefaultPort = dscPort
}
