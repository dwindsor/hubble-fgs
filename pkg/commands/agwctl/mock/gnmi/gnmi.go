// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package gnmi

import (
	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl/mock"
)

func init() {
	mock.MockCmd.AddCommand(GnmiCmd)
}

// GnmiCmd represents the mock gnmi parent command.
var GnmiCmd = &cobra.Command{
	Use:          "gnmi",
	SilenceUsage: true,
	Short:        "Interact with the mock gNMI handler",
	Long:         `View and modify mock gNMI path/value data for development and testing.`,
}
