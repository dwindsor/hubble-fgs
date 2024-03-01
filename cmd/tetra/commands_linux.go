// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package main

import (
	"github.com/cilium/tetragon/cmd/tetra/bugtool"
	"github.com/cilium/tetragon/cmd/tetra/policyfilter"
	"github.com/cilium/tetragon/cmd/tetra/probe"
	"github.com/cilium/tetragon/cmd/tetra/rthooks"
	"github.com/cilium/tetragon/cmd/tetra/tracingpolicy"
	"github.com/isovalent/hubble-fgs/cmd/tetra/file"
	"github.com/isovalent/hubble-fgs/cmd/tetra/metrics"
	"github.com/isovalent/hubble-fgs/cmd/tetra/sandboxpolicy"
	"github.com/spf13/cobra"
)

func addCommands(rootCmd *cobra.Command) {
	addBaseCommands(rootCmd)
	rootCmd.AddCommand(bugtool.New())
	rootCmd.AddCommand(tracingpolicy.New())
	rootCmd.AddCommand(file.New())
	rootCmd.AddCommand(policyfilter.New())
	rootCmd.AddCommand(rthooks.New())
	rootCmd.AddCommand(probe.New())
	rootCmd.AddCommand(sandboxpolicy.New())
	rootCmd.AddCommand(metrics.New())
}
