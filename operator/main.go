// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cilium/tetragon/operator/cmd"
	logging "github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"

	"github.com/isovalent/hubble-fgs/operator/agent"
	"github.com/isovalent/hubble-fgs/operator/options"
)

func main() {
	log := logging.DefaultSlogLogger.With(logfields.LogSubsys, "tetragon-operator")
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
		cfg := options.NewConfig()
		if cfg.ManageAgent {
			if err := agent.Manage(cfg); err != nil {
				return err
			}
		} else {
			log.Info(fmt.Sprintf("Tetragon daemon set manager deactivated, set %s to true for its activation", options.ManageAgentKey))
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
