// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/operator/cmd"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"

	"github.com/isovalent/hubble-fgs/operator/daemon"
	"github.com/isovalent/hubble-fgs/operator/options"
)

func main() {
	log := logging.DefaultLogger.WithField(logfields.LogSubsys, "tetragon-operator")
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
		if options.Config.ManageDaemonSet {
			if err := daemon.Manage(); err != nil {
				return err
			}
		} else {
			// TODO (FGI): the constant in options package should be used after it has been made public
			log.Info("Tetragon daemon set manager deactivated, set manage-agent to true for its activation")
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
