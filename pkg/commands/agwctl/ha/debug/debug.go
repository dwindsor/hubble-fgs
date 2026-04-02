// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package debug

import (
	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl/ha"
)

func init() {
	ha.HaCmd.AddCommand(DebugCmd)
}

// DebugCmd represents the debug command
var DebugCmd = &cobra.Command{
	Use:          "debug",
	SilenceUsage: true,
	Short:        "HA debug tools",
	Long:         `HA debug tools for injecting and clearing failures for testing.`,
}
