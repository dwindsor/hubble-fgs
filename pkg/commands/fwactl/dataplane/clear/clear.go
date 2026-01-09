// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package clear

import (
	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/fwactl/dataplane"
)

// clearCmd represents the clear command
var clearCmd = &cobra.Command{
	Use:          "clear",
	SilenceUsage: true,
	Aliases:      []string{"c"},
	Short:        "Sends a debug request to clear/reset",
	Long:         `Send a debug request in order to clear/reset statistics to the dataplanes`,
}

func init() {
	dataplane.DataplaneCmd.AddCommand(clearCmd)
}
