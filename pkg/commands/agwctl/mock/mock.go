// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package mock

import (
	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
)

func init() {
	agwctl.RootCmd.AddCommand(MockCmd)
}

// MockCmd represents the mock parent command.
var MockCmd = &cobra.Command{
	Use:          "mock",
	SilenceUsage: true,
	Short:        "Interact with mock subsystems",
	Long:         `Interact with mock subsystems for development and testing.`,
}
