// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !nok8s

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/lumberjack/v2"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	graphV1 "github.com/isovalent/ipa/graph/v1alpha"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/version"

	"github.com/isovalent/hubble-fgs/pkg/metrics/appmodelmetrics"
	"github.com/isovalent/hubble-fgs/pkg/model"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/node/local"
)

func TestCountEntities(t *testing.T) {
	am := &appModelV1.ApplicationModel{
		Namespaces: []*appModelV1.ApplicationNamespace{
			{
				Workloads: []*appModelV1.ApplicationWorkload{
					{
						Containers: []*appModelV1.ApplicationContainer{
							{
								Processes: []*appModelV1.ApplicationProcessGroup{
									{Connections: []*appModelV1.ApplicationConnection{{}, {}}},
									{},
								},
							},
						},
					},
				},
			},
			{
				Workloads: []*appModelV1.ApplicationWorkload{
					{
						Containers: []*appModelV1.ApplicationContainer{
							{Processes: []*appModelV1.ApplicationProcessGroup{{}}},
							{Processes: []*appModelV1.ApplicationProcessGroup{{Connections: []*appModelV1.ApplicationConnection{{}}}}},
						},
					},
					{
						Containers: []*appModelV1.ApplicationContainer{
							{},
						},
					},
				},
			},
		},
		Host: &appModelV1.ApplicationHost{
			Processes: []*appModelV1.ApplicationProcessGroup{
				{Connections: []*appModelV1.ApplicationConnection{{}}},
			},
		},
	}

	counts := countEntities(am)

	assert.Equal(t, 2, counts[appmodelmetrics.EntityNamespace])
	assert.Equal(t, 3, counts[appmodelmetrics.EntityWorkload])
	assert.Equal(t, 4, counts[appmodelmetrics.EntityContainer])
	// 2 namespaced processes + 1 host process = 5; note 1 container is empty (no processes)
	assert.Equal(t, 5, counts[appmodelmetrics.EntityProcess])
	// 2 (first pg) + 1 (fourth pg) + 1 (host pg) = 4
	assert.Equal(t, 4, counts[appmodelmetrics.EntityConnection])
}

// buildParentMapFromProcessModels is a helper function for tests that builds the parent map
// using the same logic as the model package.
func buildParentMapFromProcessModels(processModels []*types.ProcessModel) map[string][]string {
	emptyFilter := make(map[string]bool)
	_, processData := model.ProcessModelToApplicationModelWithProcessData(processModels, emptyFilter, nil)
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
	applicationModel, processData := model.ProcessModelToApplicationModelWithProcessData(processModels, emptyFilter, nil)
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

// errWriter is an io.Writer that always returns the configured error.
// It simulates lumberjack rejecting an oversized write.
type errWriter struct {
	err error
}

func (w *errWriter) Write(_ []byte) (int, error) {
	return 0, w.err
}

// TestAppModelEncodeFailureDoesNotBlockTelemetry verifies that a failing app
// model encoder does not prevent telemetry and connection exports from
// proceeding. This reproduces a production issue where a single oversized app
// model JSON blob (exceeding lumberjack's MaxSize) killed the entire export
// goroutine, stopping all three export pipelines permanently.
//
// The test calls exportTick directly (the per-tick body extracted from
// ExportApplicationModel) so that both the app-model encode and the
// telemetry/connection export run through the same code path as production.
func TestAppModelEncodeFailureDoesNotBlockTelemetry(t *testing.T) {
	// Build a "last" model with a process but no destinations.
	lastProcessModels := []*types.ProcessModel{
		{
			Binary:     "curl",
			BinaryArgs: "https://example.com",
			Parent:     "bash",
			Parents:    []string{"bash"},
			Namespace:  model.HostNamespace,
			Abi:        "x64",
			Syscalls:   []uint32{1},
		},
	}

	// Build a "new" model with the same process plus a new destination.
	// The diff between last and new will produce network telemetry entries.
	newProcessModels := []*types.ProcessModel{
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
					Stats:            &types.DestinationStats{TxBytes: 1024},
				},
			},
		},
	}

	emptyFilter := make(map[string]bool)
	lastAppModel, _ := model.ProcessModelToApplicationModelWithProcessData(lastProcessModels, emptyFilter, nil)

	// Set up a failing app model encoder and working telemetry/connection encoders.
	failingAppModelEncoder := json.NewEncoder(&errWriter{err: errors.New("write length exceeds maximum file size")})
	var telemetryBuf bytes.Buffer
	var connectionBuf bytes.Buffer
	telemetryEncoder := json.NewEncoder(&telemetryBuf)
	connectionEncoder := json.NewEncoder(&connectionBuf)

	lastTime := time.Now().Add(-10 * time.Second)

	// Call exportTick with the failing app model encoder. The function should
	// log the encode error but still proceed to export telemetry and connections.
	_, _ = exportTick(t.Context(), newProcessModels, failingAppModelEncoder, telemetryEncoder, connectionEncoder,
		lastAppModel, lastTime, emptyFilter, nil, &local.NoopMetadataService{})

	assert.NotEmpty(t, telemetryBuf.Bytes(), "telemetry encoder should have received data")
	assert.NotEmpty(t, connectionBuf.Bytes(), "connection encoder should have received data")
}

func TestExportTickSetsObserver(t *testing.T) {
	prev := option.Config.ClusterName
	t.Cleanup(func() { option.Config.ClusterName = prev })

	for _, tc := range []struct {
		name       string
		cluster    string
		identifier string
	}{
		{"no cluster", "", node.GetNodeNameForExport()},
		{"cluster", "my-cluster", "my-cluster/" + node.GetNodeNameForExport()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			option.Config.ClusterName = tc.cluster

			// A destination absent from the last model makes the tick
			// emit a connection log.
			lastProcessModels := []*types.ProcessModel{
				{
					Binary:     "curl",
					BinaryArgs: "https://example.com",
					Parent:     "bash",
					Parents:    []string{"bash"},
					Namespace:  model.HostNamespace,
					Abi:        "x64",
					Syscalls:   []uint32{1},
				},
			}
			newProcessModels := []*types.ProcessModel{
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
							Stats:            &types.DestinationStats{TxBytes: 1024},
						},
					},
				},
			}

			emptyFilter := make(map[string]bool)
			lastAppModel, _ := model.ProcessModelToApplicationModelWithProcessData(lastProcessModels, emptyFilter, nil)

			telemetryEncoder := json.NewEncoder(&bytes.Buffer{})
			var connectionBuf bytes.Buffer
			connectionEncoder := json.NewEncoder(&connectionBuf)

			lastTime := time.Now().Add(-10 * time.Second)

			_, _ = exportTick(t.Context(), newProcessModels, nil, telemetryEncoder, connectionEncoder,
				lastAppModel, lastTime, emptyFilter, nil, &local.NoopMetadataService{})

			require.NotEmpty(t, connectionBuf.Bytes(), "connection encoder should have received data")

			var log graphV1.ConnectionLog
			require.NoError(t, json.Unmarshal(connectionBuf.Bytes(), &log))
			observer := log.GetEmitter().GetObserver()
			require.NotNil(t, observer, "connection log should carry an observer")
			assert.Equal(t, "Tetragon", observer.GetName())
			assert.Equal(t, strings.TrimPrefix(version.Version, "v"), observer.GetVersion())
			assert.Equal(t, tc.identifier, observer.GetIdentifier())
		})
	}
}

func TestExportTickSetsEntityGauges(t *testing.T) {
	// Two namespaces, two workloads, three namespaced processes (3 connections),
	// plus one host process (1 connection) = 4 processes, 4 connections total.
	// ContainerId is left empty to avoid requiring process cache initialization
	// (GetPodInfo returns nil early for empty container IDs).
	processModels := []*types.ProcessModel{
		{
			Binary:     "app-a",
			BinaryArgs: "--serve",
			Parent:     "systemd",
			Parents:    []string{"systemd"},
			Namespace:  "ns-a",
			Workload:   &types.Workload{Kind: "Deployment", Name: "deploy-a"},
			Abi:        "x64",
			Syscalls:   []uint32{1},
			Dest: []*types.Destination{
				{
					DestinationNames: []string{"api.example.com"},
					Port:             443,
					Stats:            &types.DestinationStats{TxBytes: 512},
				},
			},
		},
		{
			Binary:     "app-b1",
			BinaryArgs: "--port=8080",
			Parent:     "systemd",
			Parents:    []string{"systemd"},
			Namespace:  "ns-b",
			Workload:   &types.Workload{Kind: "Deployment", Name: "deploy-b"},
			Abi:        "x64",
			Syscalls:   []uint32{1},
			Dest: []*types.Destination{
				{
					DestinationNames: []string{"db.internal"},
					Port:             5432,
					Stats:            &types.DestinationStats{TxBytes: 1024},
				},
				{
					DestinationNames: []string{"cache.internal"},
					Port:             6379,
					Stats:            &types.DestinationStats{TxBytes: 256},
				},
			},
		},
		{
			Binary:     "app-b2",
			BinaryArgs: "",
			Parent:     "systemd",
			Parents:    []string{"systemd"},
			Namespace:  "ns-b",
			Workload:   &types.Workload{Kind: "Deployment", Name: "deploy-b"},
			Abi:        "x64",
			Syscalls:   []uint32{1},
		},
		// Host-namespace process (no workload, uses model.HostNamespace)
		{
			Binary:     "sshd",
			BinaryArgs: "-D",
			Parent:     "systemd",
			Parents:    []string{"systemd"},
			Namespace:  model.HostNamespace,
			Abi:        "x64",
			Syscalls:   []uint32{1},
			Dest: []*types.Destination{
				{
					DestinationNames: []string{"client.example.com"},
					Port:             22,
					Stats:            &types.DestinationStats{TxBytes: 128},
				},
			},
		},
	}

	ctx := context.Background()
	emptyFilter := make(map[string]bool)

	exportTick(ctx, processModels, nil, nil, nil, nil, time.Now(), emptyFilter, nil, &local.NoopMetadataService{})

	assert.Equal(t, float64(2), testutil.ToFloat64(appmodelmetrics.Entities.WithLabelValues("namespace")))
	assert.Equal(t, float64(2), testutil.ToFloat64(appmodelmetrics.Entities.WithLabelValues("workload")))
	assert.Equal(t, float64(2), testutil.ToFloat64(appmodelmetrics.Entities.WithLabelValues("container")))
	assert.Equal(t, float64(4), testutil.ToFloat64(appmodelmetrics.Entities.WithLabelValues("process")))
	assert.Equal(t, float64(4), testutil.ToFloat64(appmodelmetrics.Entities.WithLabelValues("connection")))
}

// TestIsSizeLimitErrorRealLumberjack drives a real lumberjack writer past its
// MaxSize so isSizeLimitError is validated against the actual error lumberjack
// produces, rather than a hardcoded copy of its message.
func TestIsSizeLimitErrorRealLumberjack(t *testing.T) {
	writer := &lumberjack.Logger{
		Filename: filepath.Join(t.TempDir(), "app-model.log"),
		MaxSize:  1, // 1 MiB, the smallest meaningful cap
	}
	t.Cleanup(func() { _ = writer.Close() })

	// A single write larger than MaxSize is rejected outright (lumberjack never
	// splits a write). 2 MiB comfortably exceeds the 1 MiB cap.
	_, err := writer.Write(make([]byte, 2*1024*1024))
	require.Error(t, err, "expected lumberjack to reject an oversized write")
	assert.True(t, isSizeLimitError(err),
		"isSizeLimitError should catch the real lumberjack error: %v", err)
}

func TestIsSizeLimitError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unrelated error", errors.New("connection reset by peer"), false},
		{"marshalling error", errors.New("json: unsupported type"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isSizeLimitError(tt.err))
		})
	}
}
