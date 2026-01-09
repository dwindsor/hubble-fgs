// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package get

import (
	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/fwactl/dataplane"
)

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:          "get",
	SilenceUsage: true,
	Aliases:      []string{"g"},
	Short:        "Sends a debug request",
	Long: `Send a debug request in order to obtain additional
information that can be useful when debugging the dataplanes.`,
}

func init() {
	dataplane.DataplaneCmd.AddCommand(getCmd)
}
