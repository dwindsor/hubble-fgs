// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/isovalent/ipa/application_model/v1alpha"
)

func RegisterModelDump(tb testing.TB, model *v1alpha.ApplicationModel) {
	tb.Helper()
	tb.Cleanup(func() {
		// Check if test failed or panicked
		if r := recover(); r != nil || tb.Failed() {
			if model != nil {
				dumpAppModel(tb, model)
			} else {
				tb.Errorf("no application model to dump")
			}
			if r != nil {
				panic(r) // Re-panic if we caught a panic
			}
		}
	})
}

// relevantBPFMaps contains the names of BPF maps that are relevant to the application model
var relevantBPFMaps = []string{
	"execve_map",
	"tg_process_tree_config_map",
	"tg_tree_id",
	"process_tree_binary_uid_map",
	"process_tree_uid_binary_map",
	"tg_cgroup_namespace_map",
	"tg_ee_pid_data",
	"process_tree_map",
	"tg_endpoint_id_map",
	"tg_bpf_endpoint_id_map",
	"destination_endpoint_map",
	"tg_conf_map",
	"tg_h_ps_keys",
	"tg_h_ps_value",
	"tg_h_ps_buidkey",
	"tg_h_ps_lstnval",
	"tg_h_ps_dstval",
	"tg_h_ps_dfltkey",
	"tg_h_ps_epid",
}

func dumpAppModel(tb testing.TB, model *v1alpha.ApplicationModel) {
	// Sanitize test name for use as directory name
	testName := strings.ReplaceAll(tb.Name(), "/", "_")

	// Create a directory for this test's dumps
	dumpDir, err := os.MkdirTemp("", fmt.Sprintf("%s-*", testName))
	if err != nil {
		tb.Errorf("failed to create temp directory: %v", err)
		return
	}

	// Make the directory world-readable
	if err := os.Chmod(dumpDir, 0755); err != nil {
		tb.Errorf("failed to set directory permissions: %v", err)
		// Continue anyway - the directory is still created
	}

	// Dump the application model
	if err := dumpApplicationModel(tb, model, dumpDir); err != nil {
		tb.Errorf("failed to dump application model: %v", err)
	}

	// Dump relevant BPF maps
	if err := dumpBPFMaps(tb, dumpDir); err != nil {
		tb.Errorf("failed to dump BPF maps: %v", err)
	}

	tb.Logf("dumps created in directory: %s", dumpDir)
}

func dumpApplicationModel(tb testing.TB, model *v1alpha.ApplicationModel, dumpDir string) error {
	m, err := json.Marshal(model)
	if err != nil {
		tb.Errorf("failed to marshal model: %v", err)
		tb.Errorf("dumping model string as a fallback:")
		fmt.Println(model.String())
		return fmt.Errorf("failed to marshal model: %v", err)
	}

	modelFile := filepath.Join(dumpDir, "model.json")
	file, err := os.Create(modelFile)
	if err != nil {
		return fmt.Errorf("failed to create model file: %v", err)
	}
	defer file.Close()

	// Make the file world-readable
	if err := file.Chmod(0644); err != nil {
		tb.Logf("failed to set model file permissions: %v", err)
		// Continue anyway - the file is still created
	}

	if _, err := file.Write(m); err != nil {
		return fmt.Errorf("failed to write model to file: %v", err)
	}

	return nil
}

func dumpBPFMaps(tb testing.TB, dumpDir string) error {
	// Get all BPF map information
	cmd := exec.Command("bpftool", "map", "show", "--json")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to list BPF maps: %v", err)
	}

	var maps []map[string]any
	if err := json.Unmarshal(output, &maps); err != nil {
		return fmt.Errorf("failed to parse BPF map list: %v", err)
	}

	// Create a map from map names to IDs for quick lookup
	nameToID := make(map[string]int)
	for _, mapInfo := range maps {
		if name, ok := mapInfo["name"].(string); ok {
			if id, ok := mapInfo["id"].(float64); ok {
				nameToID[name] = int(id)
			}
		}
	}

	// Dump each relevant map
	for _, mapName := range relevantBPFMaps {
		if mapID, exists := nameToID[mapName]; exists {
			if err := dumpSingleBPFMap(tb, dumpDir, mapName, mapID); err != nil {
				tb.Logf("failed to dump map %s (ID: %d): %v", mapName, mapID, err)
				// Continue with other maps even if one fails
			}
		} else {
			tb.Logf("map %s not found in current BPF maps", mapName)
		}
	}

	return nil
}

func dumpSingleBPFMap(tb testing.TB, dumpDir, mapName string, mapID int) error {
	// Dump the map contents
	cmd := exec.Command("bpftool", "map", "dump", "id", strconv.Itoa(mapID))
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to dump map %s: %v", mapName, err)
	}

	// Create file for this map dump
	mapFile := filepath.Join(dumpDir, fmt.Sprintf("%s.json", mapName))
	file, err := os.Create(mapFile)
	if err != nil {
		return fmt.Errorf("failed to create map file: %v", err)
	}
	defer file.Close()

	// Make the file world-readable
	if err := file.Chmod(0644); err != nil {
		tb.Logf("failed to set map file permissions: %v", err)
		// Continue anyway - the file is still created
	}

	if _, err := file.Write(output); err != nil {
		return fmt.Errorf("failed to write map dump to file: %v", err)
	}

	return nil
}
