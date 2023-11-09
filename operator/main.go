// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os"

	"github.com/cilium/tetragon/operator/cmd"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
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
			client.RemoveSandboxPolicyCRD()
		}
		ossCmdRun(cmd, args)
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
