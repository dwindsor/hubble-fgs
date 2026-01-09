// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package policies

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
)

func init() {
	translateCmd.Flags().StringP("file", "f", "", "Path to policy YAML file (if not provided, translates current AGW policy set)")
	translateCmd.Flags().Bool("no-vrfs", false, "Translate all policies ignoring actively configured VRFs")
	PoliciesCmd.AddCommand(translateCmd)
}

var translateCmd = &cobra.Command{
	Use:          "translate",
	SilenceUsage: true,
	Short:        "Translate policies to DPU json format",
	Long: `Translates policies into the json rule format used by the dataplane on the DPU.
If a file is provided, reads policies from the YAML file. Otherwise, translates the
current policy set in the AGW. By default, prints rules based on the active VRFs
defined in the AGW. Use --no-vrfs to translate all policies ignoring active VRFs.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		filePath, err := cmd.Flags().GetString("file")
		if err != nil {
			return err
		}

		noVrfs, err := cmd.Flags().GetBool("no-vrfs")
		if err != nil {
			return err
		}

		data := ipc.MessageData{
			Flags: map[string]string{
				"file":    filePath,
				"json":    fmt.Sprintf("%t", agwctl.JSON),
				"no-vrfs": fmt.Sprintf("%t", noVrfs),
			},
		}

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_POLICIES_TRANSLATE, data)
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, agwctl.JSON)
		return nil
	},
}
