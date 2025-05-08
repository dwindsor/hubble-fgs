// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package probe

import (
	"strings"

	ossprobe "github.com/cilium/tetragon/cmd/tetra/probe"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	"github.com/spf13/cobra"
)

func newNet() *cobra.Command {
	osscmd := ossprobe.New()
	cmd := cobra.Command{
		Use:    "net",
		Short:  "Probe features relevant to network uses",
		Long:   "Probe kernel features relevant to network uses",
		PreRun: osscmd.PreRun,
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Println(strings.ReplaceAll(utils.LogLayer3Features(), ", ", "\n"))
		},
	}
	return &cmd
}

func New() *cobra.Command {
	osscmd := ossprobe.New()
	cmd := cobra.Command{
		Use:    osscmd.Use,
		Short:  osscmd.Short,
		Long:   osscmd.Long,
		PreRun: osscmd.PreRun,
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Println(strings.ReplaceAll(bpf.LogFeatures(), ", ", "\n"))
		},
	}
	cmd.AddCommand(newNet())
	return &cmd
}
