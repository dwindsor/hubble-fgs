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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/mock"
)

func init() {
	setCmd.Flags().StringP("path", "p", "", "gNMI path to set")
	setCmd.Flags().StringP("value", "v", "", "JSON value to store at the path")
	setCmd.Flags().StringP("file", "f", "", "JSON file with nested gNMI tree to bulk-load (mutually exclusive with --path/--value)")
	GnmiCmd.AddCommand(setCmd)
}

var setCmd = &cobra.Command{
	Use:          "set",
	SilenceUsage: true,
	Short:        "Set a value in the mock gNMI handler and notify subscribers",
	Long: `Store a value at a gNMI path in the mock handler and fire gNMI notifications
to registered subscribers. Use --path and --value for a single entry, or --file
to bulk-load from a nested JSON tree (same format as 'mock gnmi show --json').`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		file, _ := cmd.Flags().GetString("file")
		path, _ := cmd.Flags().GetString("path")
		value, _ := cmd.Flags().GetString("value")

		if file != "" && (path != "" || value != "") {
			return errors.New("--file is mutually exclusive with --path/--value")
		}

		if file != "" {
			return setBulkFromFile(ctx, file)
		}

		if path == "" {
			return errors.New("--path is required (or use --file)")
		}
		if value == "" {
			return errors.New("--value is required")
		}

		data := ipc.MessageData{
			Flags: map[string]string{
				"path":  path,
				"value": value,
				"json":  fmt.Sprintf("%t", agwctl.JSON),
			},
		}

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_MOCK_GNMI_SET, data)
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, agwctl.JSON)
		return nil
	},
}

func setBulkFromFile(ctx context.Context, filePath string) error {
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	var tree map[string]interface{}
	if err := json.Unmarshal(raw, &tree); err != nil {
		return fmt.Errorf("parsing JSON: %w", err)
	}

	flat := mock.TreeToFlat(tree)

	entriesJSON, err := json.Marshal(flat)
	if err != nil {
		return fmt.Errorf("marshaling entries: %w", err)
	}

	data := ipc.MessageData{
		Flags: map[string]string{
			"entries": string(entriesJSON),
			"json":    fmt.Sprintf("%t", agwctl.JSON),
		},
	}

	ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_MOCK_GNMI_SET_BULK, data)
	if err != nil {
		return err
	}
	ipc.PrintResponse(ret, agwctl.JSON)
	return nil
}
