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
	"github.com/cilium/tetragon/cmd/tetra/sensors"
	"github.com/cilium/tetragon/cmd/tetra/stacktracetree"
	"github.com/cilium/tetragon/cmd/tetra/status"
	"github.com/cilium/tetragon/cmd/tetra/version"
	"github.com/isovalent/hubble-fgs/cmd/tetra/getevents"
	"github.com/isovalent/hubble-fgs/cmd/tetra/mandate"
	"github.com/isovalent/hubble-fgs/cmd/tetra/record"
	"github.com/spf13/cobra"
)

// addBaseCommands adds commands that build and make sense on all platform:
// getevents, version, sensors, stacktracetree, status, rthooks
func addBaseCommands(rootCmd *cobra.Command) {
	rootCmd.AddCommand(getevents.New())
	rootCmd.AddCommand(version.New())
	rootCmd.AddCommand(sensors.New())
	rootCmd.AddCommand(stacktracetree.New())
	rootCmd.AddCommand(status.New())
	rootCmd.AddCommand(record.New())
	rootCmd.AddCommand(mandate.New())

	// bugtool technically builds on darwin and windows but makes no sense since
	// it's supposed to be run on the machine running Tetragon, using
	// Linux-specific files and tools like bpftool
	// rootCmd.AddCommand(bugtool.New())

	// tracingpolicy does not build on windows because of unix-specific
	// constants used in the kernels package
	// rootCmd.AddCommand(tracingpolicy.New())

	// file does not build on windows and darwin because it imports
	// github.com/cilium/tetragon/pkg/cgroups that have build constraints
	// rootCmd.AddCommand(file.New())
}
