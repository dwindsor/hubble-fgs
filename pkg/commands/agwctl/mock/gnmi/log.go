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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
	mocknxos "github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/mock"
)

const mockGnmiLogPath = "/iox_data/mock_gnmi.log"

func init() {
	GnmiCmd.AddCommand(logCmd)
	logCmd.Flags().StringP("path", "p", "", "Filter entries by exact path match")
	logCmd.Flags().String("prefix", "", "Filter entries by path prefix match")
	logCmd.Flags().StringP("operation", "o", "", "Filter entries by operation (get, set, delete, set_notify, delete_notify, subscribe, route, startup)")
	logCmd.Flags().IntP("n", "n", 0, "Show only the last N entries (0 = all)")
	logCmd.Flags().BoolP("follow", "f", false, "Follow log output (stream new entries)")
}

var logCmd = &cobra.Command{
	Use:          "log",
	SilenceUsage: true,
	Short:        "Show mock gNMI transaction log",
	Long: `Display the mock gNMI transaction log with optional filtering.

Examples:
  agwctl mock gnmi log                            # show all entries
  agwctl mock gnmi log -n 20                      # last 20 entries
  agwctl mock gnmi log -f                         # follow/stream new entries
  agwctl mock gnmi log -f -n 10                   # last 10 entries then follow
  agwctl mock gnmi log --path "System/foo/bar"    # exact path match
  agwctl mock gnmi log --prefix "System/sas"      # path prefix match
  agwctl mock gnmi log --operation set            # filter by operation`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		pathExact, _ := cmd.Flags().GetString("path")
		pathPrefix, _ := cmd.Flags().GetString("prefix")
		operation, _ := cmd.Flags().GetString("operation")
		n, _ := cmd.Flags().GetInt("n")
		follow, _ := cmd.Flags().GetBool("follow")

		if follow {
			return runFollowLog(cmd, pathExact, pathPrefix, operation, n)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		data := ipc.MessageData{
			Flags: map[string]string{
				"path":      pathExact,
				"prefix":    pathPrefix,
				"operation": operation,
				"json":      fmt.Sprintf("%t", agwctl.JSON),
			},
		}
		if n > 0 {
			data.Flags["n"] = fmt.Sprintf("%d", n)
		}

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_MOCK_GNMI_LOG, data)
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, agwctl.JSON)
		return nil
	},
}

// runFollowLog reads the log file directly (like tail -f), printing existing
// matching entries (-n controls how many history lines) then streaming new ones.
func runFollowLog(cmd *cobra.Command, pathExact, pathPrefix, operation string, n int) error {
	f, err := os.Open(mockGnmiLogPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(cmd.OutOrStderr(), "Log file not found, waiting for %s...\n", mockGnmiLogPath)
			// Wait for file to appear.
			for {
				time.Sleep(500 * time.Millisecond)
				f, err = os.Open(mockGnmiLogPath)
				if err == nil {
					break
				}
			}
		} else {
			return err
		}
	}
	defer f.Close()

	opLower := strings.ToLower(operation)

	matchEntry := func(line string) (string, bool) {
		if line == "" {
			return "", false
		}
		var e mocknxos.TxEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return "", false
		}
		if pathExact != "" && e.Path != pathExact {
			return "", false
		}
		if pathPrefix != "" && !strings.HasPrefix(e.Path, pathPrefix) {
			return "", false
		}
		if opLower != "" && strings.ToLower(e.Action) != opLower {
			return "", false
		}
		return formatEntry(e), true
	}

	// Collect existing lines from file.
	var existing []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if formatted, ok := matchEntry(scanner.Text()); ok {
			existing = append(existing, formatted)
		}
	}

	// Apply -n tail to existing lines.
	if n > 0 && n < len(existing) {
		existing = existing[len(existing)-n:]
	}
	for _, line := range existing {
		fmt.Print(line)
	}

	// Seek to end for new entries.
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}

	reader := bufio.NewReader(f)
	var partial string
	for {
		line, err := reader.ReadString('\n')
		partial += line
		if err != nil {
			if err == io.EOF {
				time.Sleep(200 * time.Millisecond)
				continue
			}
			return err
		}
		formatted, ok := matchEntry(strings.TrimRight(partial, "\n"))
		partial = ""
		if ok {
			fmt.Print(formatted)
		}
	}
}

func formatEntry(e mocknxos.TxEntry) string {
	errPart := ""
	if e.Error != "" {
		errPart = fmt.Sprintf(" [error: %s]", e.Error)
	}
	valuePart := ""
	if e.Value != "" {
		valuePart = fmt.Sprintf(" = %s", e.Value)
	}
	pathPart := ""
	if e.Path != "" {
		pathPart = fmt.Sprintf(" %s", e.Path)
	}
	return fmt.Sprintf("%s  %-14s%s%s%s\n", e.Timestamp, e.Action, pathPart, valuePart, errPart)
}
