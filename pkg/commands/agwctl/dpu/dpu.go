// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dpu

import (
	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
)

func init() {
	agwctl.RootCmd.AddCommand(DpuCmd)
}

// DpuCmd represents the dpu command
var DpuCmd = &cobra.Command{
	Use:          "dpu",
	SilenceUsage: true,
	Short:        "Manage DPU data",
	Long:         `Manage DPU data - show DPU store contents.`,
}
