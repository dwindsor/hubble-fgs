// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !windows

package probe

import (
	"strings"

	ossprobe "github.com/cilium/tetragon/cmd/tetra/probe"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
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
