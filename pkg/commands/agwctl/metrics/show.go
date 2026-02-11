// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
)

func init() {
	MetricsCmd.AddCommand(showCmd)
}

var showCmd = &cobra.Command{
	Use:          "show",
	SilenceUsage: true,
	Short:        "Show AGW metrics",
	Long:         `Display current AGW metrics including memory, CPU usage, policy counts, and error statistics.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_SHOW_METRICS, ipc.MessageData{})
		if err != nil {
			return err
		}

		if agwctl.JSON {
			fmt.Println(ret.Data)
			return nil
		}

		// Parse and display in human-readable format
		var metrics map[string]interface{}
		if err := json.Unmarshal([]byte(ret.Data), &metrics); err != nil {
			return fmt.Errorf("failed to parse metrics: %w", err)
		}

		var result strings.Builder

		// System metrics
		result.WriteString("AGW Resources:\n")
		result.WriteString(fmt.Sprintf("  Total Physical Memory Usage: %.1f kB\n", metrics["total_physical_memory_kb_usage"]))
		result.WriteString(fmt.Sprintf("  CPU Usage: %.1f%%\n\n", metrics["cpu_usage_percent"]))

		// Policy metrics
		result.WriteString("Policy Statistics:\n")
		result.WriteString(fmt.Sprintf("  Policy K8s IDs: %v\n", metrics["policy_k8s_ids"]))
		result.WriteString(fmt.Sprintf("  Policy DPU Rules: %v\n\n", metrics["policy_dpu_rules"]))

		// Error metrics
		result.WriteString("Error Statistics:\n")
		result.WriteString(fmt.Sprintf("  Policy DPU Insert Errors: %v\n", metrics["policy_dpu_insert_errors"]))
		result.WriteString(fmt.Sprintf("  Policy DPU Update Errors: %v\n", metrics["policy_dpu_update_errors"]))
		result.WriteString(fmt.Sprintf("  Policy DPU Delete Errors: %v\n", metrics["policy_dpu_delete_errors"]))

		fmt.Print(result.String())

		return nil
	},
}
