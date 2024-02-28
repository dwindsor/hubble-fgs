// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os"

	"github.com/cilium/tetragon/operator/cmd"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/isovalent/hubble-fgs/operator/daemon"
	"github.com/isovalent/hubble-fgs/operator/options"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func main() {
	ossCmd := cmd.New()
	ossCmdRun := ossCmd.Run
	ossCmd.Run = func(cmd *cobra.Command, args []string) {
		// NB: ossCmdRun is where CRDs are registered.
		if viper.GetBool(options.SkipPolicySandboxCRD) {
			client.RemoveSandboxPolicyCRDs()
		}
		ossCmdRun(cmd, args)
	}

	ossServe := serveCmd(ossCmd)
	ossServeRunE := ossServe.RunE
	ossServe.RunE = func(cmd *cobra.Command, args []string) error {
		options.ConfigPopulate()
		if options.Config.InstallDaemonSet {
			go func() {
				if err := daemon.InstallTetragonDaemonSet(); err != nil {
					panic(err)
				}
			}()
		}
		return ossServeRunE(cmd, args)
	}

	ossCmd.Flags().Bool(
		options.SkipPolicySandboxCRD,
		true,
		"When true, PolicySandbox CRD will not be created",
	)

	if err := ossCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

const serveCmdName = "serve"

func serveCmd(cmd *cobra.Command) *cobra.Command {
	for i := range cmd.Commands() {
		if cmd.Commands()[i].Use == serveCmdName {
			return cmd.Commands()[i]
		}
	}
	panic(fmt.Errorf("operator %s command not found", serveCmdName))
}
