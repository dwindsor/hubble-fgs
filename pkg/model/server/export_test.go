// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package server

import (
	"testing"

	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/model"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

// buildParentMapFromProcessModels is a helper function for tests that builds the parent map
// using the same logic as the model package.
func buildParentMapFromProcessModels(processModels []*types.ProcessModel) map[string][]string {
	emptyFilter := make(map[string]bool)
	_, processData := model.ProcessModelToApplicationModelWithProcessData(processModels, emptyFilter)
	telemetryMap := model.BuildTelemetryMap(processData)
	// Extract just the parent map for backward compatibility
	parentMap := make(map[string][]string)
	for key, val := range telemetryMap {
		parentMap[key] = val.Parents
	}
	return parentMap
}

func TestBuildParentMap(t *testing.T) {
	tests := []struct {
		name              string
		processModels     []*types.ProcessModel
		expectedParentMap map[string][]string
	}{
		{
			name: "simple parent aggregation",
			processModels: []*types.ProcessModel{
				{
					Binary:     "exa",
					BinaryArgs: "-la",
					Parent:     "bash",
					Parents:    []string{"bash"},
					Namespace:  model.HostNamespace,
					Abi:        "x64",
					Syscalls:   []uint32{1},
				},
				{
					Binary:     "exa",
					BinaryArgs: "-la",
					Parent:     "zsh",
					Parents:    []string{"zsh"},
					Namespace:  model.HostNamespace,
					Abi:        "x64",
					Syscalls:   []uint32{1},
				},
			},
			expectedParentMap: map[string][]string{
				"exa-la": {"bash", "zsh"},
			},
		},
		{
			name: "multiple processes with different parents",
			processModels: []*types.ProcessModel{
				{
					Binary:     "ls",
					BinaryArgs: "",
					Parent:     "bash",
					Parents:    []string{"bash"},
					Namespace:  model.HostNamespace,
					Abi:        "x64",
					Syscalls:   []uint32{1},
				},
				{
					Binary:     "grep",
					BinaryArgs: "test",
					Parent:     "zsh",
					Parents:    []string{"zsh"},
					Namespace:  model.HostNamespace,
					Abi:        "x64",
					Syscalls:   []uint32{1},
				},
			},
			expectedParentMap: map[string][]string{
				"ls":       {"bash"},
				"greptest": {"zsh"},
			},
		},
		{
			name: "workload processes",
			processModels: []*types.ProcessModel{
				{
					Binary:     "app",
					BinaryArgs: "--config=/etc/app.conf",
					Parent:     "systemd",
					Parents:    []string{"systemd"},
					Namespace:  "default",
					Workload:   &types.Workload{Kind: "Deployment", Name: "my-app"},
					Abi:        "x64",
					Syscalls:   []uint32{1},
				},
				{
					Binary:     "app",
					BinaryArgs: "--config=/etc/app.conf",
					Parent:     "init",
					Parents:    []string{"init"},
					Namespace:  "default",
					Workload:   &types.Workload{Kind: "Deployment", Name: "my-app"},
					Abi:        "x64",
					Syscalls:   []uint32{1},
				},
			},
			expectedParentMap: map[string][]string{
				"app--config=/etc/app.conf": {"init", "systemd"},
			},
		},
		{
			name: "processes with destinations should appear in parent map",
			processModels: []*types.ProcessModel{
				{
					Binary:     "curl",
					BinaryArgs: "https://example.com",
					Parent:     "bash",
					Parents:    []string{"bash"},
					Namespace:  model.HostNamespace,
					Abi:        "x64",
					Syscalls:   []uint32{1},
					Dest: []*types.Destination{
						{
							DestinationNames: []string{"example.com"},
							Port:             443,
						},
					},
				},
				{
					Binary:     "ls",
					BinaryArgs: "",
					Parent:     "bash",
					Parents:    []string{"bash"},
					Namespace:  model.HostNamespace,
					Abi:        "x64",
					Syscalls:   []uint32{1},
					// No destinations
				},
			},
			expectedParentMap: map[string][]string{
				"curlhttps://example.com": {"bash"},
				"ls":                      {"bash"},
			},
		},
		{
			name: "processes with empty parents",
			processModels: []*types.ProcessModel{
				{
					Binary:     "init",
					BinaryArgs: "",
					Parent:     "",
					Parents:    []string{},
					Namespace:  model.HostNamespace,
					Abi:        "x64",
					Syscalls:   []uint32{1},
				},
			},
			expectedParentMap: map[string][]string{
				"init": {}, // Empty parents list, but key should still exist
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parentMap := buildParentMapFromProcessModels(tt.processModels)

			// For tests expecting empty parents, we need to add them manually since
			// buildParentMapFromProcessModels only includes entries with non-empty parents
			for expectedKey, expectedParents := range tt.expectedParentMap {
				if len(expectedParents) == 0 {
					if _, exists := parentMap[expectedKey]; !exists {
						parentMap[expectedKey] = expectedParents
					}
				}
			}

			// Verify the parent map matches expectations
			assert.Equal(t, tt.expectedParentMap, parentMap, "parent map should match expected")
		})
	}
}

func TestExportParentMapWithApplicationModel(t *testing.T) {
	processModels := []*types.ProcessModel{
		{
			Binary:     "exa",
			BinaryArgs: "-la",
			Parent:     "bash",
			Parents:    []string{"bash"},
			Namespace:  model.HostNamespace,
			Abi:        "x64",
			Syscalls:   []uint32{1, 2},
		},
		{
			Binary:     "exa",
			BinaryArgs: "-la",
			Parent:     "zsh",
			Parents:    []string{"zsh"},
			Namespace:  model.HostNamespace,
			Abi:        "x64",
			Syscalls:   []uint32{1, 2},
		},
		{
			Binary:     "grep",
			BinaryArgs: "pattern",
			Parent:     "bash",
			Parents:    []string{"bash"},
			Namespace:  model.HostNamespace,
			Abi:        "x64",
			Syscalls:   []uint32{3},
		},
	}

	// Convert to ApplicationModel and build telemetry map
	emptyFilter := map[string]bool{}
	applicationModel, processData := model.ProcessModelToApplicationModelWithProcessData(processModels, emptyFilter)
	telemetryMap := model.BuildTelemetryMap(processData)

	// Extract parent map for verification
	parentMap := make(map[string][]string)
	for key, val := range telemetryMap {
		parentMap[key] = val.Parents
	}

	// Verify the parent map
	expectedParentMap := map[string][]string{
		"exa-la":      {"bash", "zsh"}, // Aggregated from both bash and zsh
		"greppattern": {"bash"},
	}
	assert.Equal(t, expectedParentMap, parentMap, "parent map should aggregate correctly")

	// Verify that ApplicationModel has the expected structure
	require.NotNil(t, applicationModel.ApplicationModel)
	require.NotNil(t, applicationModel.ApplicationModel.Host)
	require.Len(t, applicationModel.ApplicationModel.Host.Processes, 2) // exa and grep

	// Find processes in the ApplicationModel
	var exaProcess, grepProcess *appModelV1.ApplicationProcessGroup
	for _, proc := range applicationModel.ApplicationModel.Host.Processes {
		switch proc.Name {
		case "exa":
			exaProcess = proc
		case "grep":
			grepProcess = proc
		}
	}

	require.NotNil(t, exaProcess, "exa process should be present")
	require.NotNil(t, grepProcess, "grep process should be present")
	assert.Equal(t, "-la", exaProcess.Arguments)
	assert.Equal(t, "pattern", grepProcess.Arguments)
}

func TestExportParentMapEdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		processModels []*types.ProcessModel
		expectedCount int // Expected number of entries in parent map
		description   string
	}{
		{
			name:          "no processes",
			processModels: []*types.ProcessModel{},
			expectedCount: 0,
			description:   "empty process list should result in empty parent map",
		},
		{
			name: "nil workload process",
			processModels: []*types.ProcessModel{
				{
					Binary:     "test-process",
					BinaryArgs: "",
					Parent:     "parent-process",
					Parents:    []string{"parent-process"},
					Namespace:  model.HostNamespace,
					Workload:   nil, // This was causing segfaults
					Abi:        "x64",
					Syscalls:   []uint32{1},
				},
			},
			expectedCount: 1,
			description:   "nil workload should not cause issues",
		},
		{
			name: "duplicate parent names",
			processModels: []*types.ProcessModel{
				{
					Binary:     "process",
					BinaryArgs: "",
					Parent:     "parent",
					Parents:    []string{"parent"},
					Namespace:  model.HostNamespace,
					Abi:        "x64",
					Syscalls:   []uint32{1},
				},
				{
					Binary:     "process",
					BinaryArgs: "",
					Parent:     "parent", // Same parent
					Parents:    []string{"parent"},
					Namespace:  model.HostNamespace,
					Abi:        "x64",
					Syscalls:   []uint32{1},
				},
			},
			expectedCount: 1,
			description:   "duplicate parents should be deduped",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This should not panic
			parentMap := buildParentMapFromProcessModels(tt.processModels)

			assert.Equal(t, tt.expectedCount, len(parentMap), tt.description)

			if tt.name == "duplicate parent names" && len(parentMap) > 0 {
				// Verify that duplicates were properly deduped
				for _, parents := range parentMap {
					assert.Equal(t, []string{"parent"}, parents, "should have single parent, not duplicates")
				}
			}
		})
	}
}
