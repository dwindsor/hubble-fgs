// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package model

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	common "github.com/isovalent/ipa/common/k8s/type/v1alpha"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

func TestNetworkMonitorKey_String(t *testing.T) {
	key := NetworkKey{
		SourceNamespace:  HostNamespace,
		DestinationNames: "cisco.com",
		DestinationPort:  443,
	}
	assert.Equal(t, "host > cisco.com:443", key.String())
	key.SourceNamespace = "kube-system"
	key.SourceWorkloadKind = common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT
	key.SourceWorkloadName = "nginx"
	assert.Equal(t, "kube-system/Deployment:nginx > cisco.com:443", key.String())
}

func TestNetworkMonitorValue_String(t *testing.T) {
	val := NetworkMonitorValue{
		TXBytes: 24 * 1024 * 1024,
		RXBytes: 145 * 1024 * 1024 * 1024,
		TXDrops: 12 * 1024 * 1024,
	}
	assert.Equal(t, "24MB sent 145GB received 12MB dropped", val.String())
}

func TestConvertToNetworkMonitorData(t *testing.T) {
	res := []*types.ProcessModel{
		{
			Namespace: HostNamespace,
			Binary:    "curl",
			Dest: []*types.Destination{
				{
					DestinationNames: []string{"cisco.com."},
					Port:             443,
					Stats:            &types.DestinationStats{TxBytes: 10, RxBytes: 20},
				},
			},
		},
		{
			Namespace: HostNamespace,
			Binary:    "wget",
			Dest: []*types.Destination{
				{
					DestinationNames: []string{"cisco.com."},
					Port:             443,
					Stats:            &types.DestinationStats{TxBytes: 30, RxBytes: 40},
				},
			},
		},
		{
			Namespace: HostNamespace,
			Binary:    "wget",
			Dest: []*types.Destination{
				{
					DestinationNames: []string{"cisco.com."},
					Port:             80,
					Stats:            &types.DestinationStats{TxBytes: 100, RxBytes: 200},
				},
			},
		},
		{
			Binary:    "wget",
			Namespace: "client",
			Workload:  &types.Workload{Kind: "Deployment", Name: "my-app"},
			Dest: []*types.Destination{
				{
					DestinationPod: &types.Pod{
						Namespace:    "server",
						WorkloadKind: "Deployment",
						Workload:     "nginx",
					},
					Port:  8080,
					Stats: &types.DestinationStats{TxBytes: 200, RxBytes: 400},
				},
			},
		},
		{
			Binary:    "wget",
			Namespace: "client",
			Workload:  &types.Workload{Kind: "Deployment", Name: "my-app"},
			Dest: []*types.Destination{
				{
					DestinationService: &types.Service{
						Namespace: "default",
						Name:      "kubernetes",
					},
					Port:  443,
					Stats: &types.DestinationStats{TxBytes: 300, RxBytes: 500},
				},
			},
		},
		// This is quota
		{
			Namespace: "client",
			Workload:  &types.Workload{Kind: "Deployment", Name: "my-app"},
			Dest: []*types.Destination{
				{
					DestinationPod: &types.Pod{
						Namespace:    "server",
						WorkloadKind: "Deployment",
						Workload:     "nginx",
					},
					Stats: &types.DestinationStats{
						TxBytes:        200,
						RxBytes:        400,
						TxDrops:        600,
						TxLimit:        800,
						TxQuota:        1000,
						KtimeTxReset:   &timestamppb.Timestamp{Seconds: 1200, Nanos: 1400},
						KtimeLastReset: &timestamppb.Timestamp{Seconds: 1000, Nanos: 1400},
					},
				},
			},
		},
	}
	data, quota, _ := ConvertToMonitorData(res, false)
	expected := NetworkMonitorData{
		NetworkKey{
			SourceNamespace:  HostNamespace,
			DestinationNames: "cisco.com.",
			DestinationPort:  443,
		}: NetworkMonitorValue{
			TXBytes: 40,
			RXBytes: 60,
		},
		NetworkKey{
			SourceNamespace:  HostNamespace,
			DestinationNames: "cisco.com.",
			DestinationPort:  80,
		}: NetworkMonitorValue{
			TXBytes: 100,
			RXBytes: 200,
		},
		NetworkKey{
			SourceNamespace:              "client",
			SourceWorkloadKind:           common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
			SourceWorkloadName:           "my-app",
			DestinationWorkloadName:      "kubernetes",
			DestinationWorkloadNamespace: "default",
			DestinationWorkloadKind:      common.WorkloadKind_WORKLOAD_KIND_UNSPECIFIED,
			DestinationPort:              443,
		}: NetworkMonitorValue{
			TXBytes: 300,
			RXBytes: 500,
		}, NetworkKey{
			SourceNamespace:              "client",
			SourceWorkloadKind:           common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
			SourceWorkloadName:           "my-app",
			DestinationWorkloadName:      "nginx",
			DestinationWorkloadNamespace: "server",
			DestinationWorkloadKind:      common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
			DestinationPort:              8080,
		}: NetworkMonitorValue{
			TXBytes: 200,
			RXBytes: 400,
		},
	}
	expectedQuota := NetworkQuotaData{
		NetworkKey{
			SourceNamespace:              "client",
			SourceWorkloadKind:           common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
			SourceWorkloadName:           "my-app",
			DestinationWorkloadName:      "nginx",
			DestinationWorkloadNamespace: "server",
			DestinationWorkloadKind:      common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
		}: NetworkQuotaValue{
			TXBytes:   200,
			RXBytes:   400,
			TXDrops:   600,
			TXQuota:   800,
			TXUsage:   1000,
			NextReset: time.Unix(1200, 1400).UTC(),
			LastReset: time.Unix(1000, 1400).UTC(),
		},
	}
	assert.Empty(t, cmp.Diff(expected, data, protocmp.Transform()))
	assert.Empty(t, cmp.Diff(expectedQuota, quota, protocmp.Transform()))
}

func TestDiff(t *testing.T) {
	currentData := NetworkMonitorData{
		NetworkKey{
			SourceNamespace:  HostNamespace,
			DestinationNames: "cisco.com",
			DestinationPort:  443,
		}: NetworkMonitorValue{
			TXBytes: 10,
			RXBytes: 20,
		},
		NetworkKey{
			SourceNamespace:              "client",
			SourceWorkloadKind:           common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
			SourceWorkloadName:           "my-app",
			DestinationWorkloadName:      "nginx",
			DestinationWorkloadNamespace: "server",
			DestinationWorkloadKind:      common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
			DestinationPort:              8080,
		}: NetworkMonitorValue{
			TXBytes: 100,
			RXBytes: 200,
		},
	}
	newData := NetworkMonitorData{
		// no change
		NetworkKey{
			SourceNamespace:  HostNamespace,
			DestinationNames: "cisco.com",
			DestinationPort:  443,
		}: NetworkMonitorValue{
			TXBytes: 10,
			RXBytes: 20,
		},
		// an existing entry with updated stats
		NetworkKey{
			SourceNamespace:              "client",
			SourceWorkloadKind:           common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
			SourceWorkloadName:           "my-app",
			DestinationWorkloadName:      "nginx",
			DestinationWorkloadNamespace: "server",
			DestinationWorkloadKind:      common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
			DestinationPort:              8080,
		}: NetworkMonitorValue{
			TXBytes: 1000,
			RXBytes: 2000,
		},
		// new entry
		NetworkKey{
			SourceNamespace:    "client",
			SourceWorkloadKind: common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
			SourceWorkloadName: "another-app",
			DestinationNames:   "isovalent.com",
			DestinationPort:    80,
		}: NetworkMonitorValue{
			TXBytes: 10000,
			RXBytes: 20000,
		},
	}
	diff := Diff(currentData, newData)
	assert.Equal(t, NetworkMonitorData{
		NetworkKey{
			SourceNamespace:              "client",
			SourceWorkloadKind:           common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
			SourceWorkloadName:           "my-app",
			DestinationWorkloadName:      "nginx",
			DestinationWorkloadNamespace: "server",
			DestinationWorkloadKind:      common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
			DestinationPort:              8080,
		}: NetworkMonitorValue{
			TXBytes: 900,
			RXBytes: 1800,
		},
		NetworkKey{
			SourceNamespace:    "client",
			SourceWorkloadKind: common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
			SourceWorkloadName: "another-app",
			DestinationNames:   "isovalent.com",
			DestinationPort:    80,
		}: NetworkMonitorValue{
			TXBytes: 10000,
			RXBytes: 20000,
		}}, diff)
}

func Test_sortNetworkKeys(t *testing.T) {
	a := NetworkKey{
		SourceNamespace:    "a",
		SourceWorkloadKind: common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
		SourceWorkloadName: "a",
		SourceProcessName:  "a",
		DestinationNames:   "a",
		DestinationPort:    1234,
	}
	b := a
	// namespace
	assert.Zero(t, CompareNetworkKeys(a, b))
	b.SourceNamespace = "b"
	assert.Less(t, CompareNetworkKeys(a, b), 0)
	b.SourceNamespace = "A"
	assert.Greater(t, CompareNetworkKeys(a, b), 0)
	b.SourceNamespace = a.SourceNamespace
	require.Equal(t, CompareNetworkKeys(a, b), 0)

	// workload kind
	b.SourceWorkloadKind = common.WorkloadKind_WORKLOAD_KIND_REPLICASET
	assert.Less(t, CompareNetworkKeys(a, b), 0)
	b.SourceWorkloadKind = common.WorkloadKind_WORKLOAD_KIND_DAEMONSET
	assert.Greater(t, CompareNetworkKeys(a, b), 0)
	b.SourceWorkloadKind = a.SourceWorkloadKind
	require.Equal(t, CompareNetworkKeys(a, b), 0)

	// workload name
	b.SourceWorkloadName = "b"
	assert.Less(t, CompareNetworkKeys(a, b), 0)
	b.SourceWorkloadName = "A"
	assert.Greater(t, CompareNetworkKeys(a, b), 0)
	b.SourceWorkloadName = a.SourceWorkloadName
	require.Equal(t, CompareNetworkKeys(a, b), 0)

	// process name
	b.SourceProcessName = "b"
	assert.Less(t, CompareNetworkKeys(a, b), 0)
	b.SourceProcessName = "A"
	assert.Greater(t, CompareNetworkKeys(a, b), 0)
	b.SourceProcessName = a.SourceProcessName
	require.Equal(t, CompareNetworkKeys(a, b), 0)

	// destination port
	b.DestinationPort = 1235
	assert.Less(t, CompareNetworkKeys(a, b), 0)
	b.DestinationPort = 1233
	assert.Greater(t, CompareNetworkKeys(a, b), 0)
	b.DestinationPort = a.DestinationPort
	require.Equal(t, CompareNetworkKeys(a, b), 0)

	// destination name
	b.DestinationNames = "b"
	assert.Less(t, CompareNetworkKeys(a, b), 0)
	b.DestinationNames = "A"
	assert.Greater(t, CompareNetworkKeys(a, b), 0)
	b.DestinationNames = ""
	b.DestinationIP = "9.9.9.9"
	assert.Greater(t, CompareNetworkKeys(a, b), 0)
	a.DestinationNames = ""
	a.DestinationIP = "10.10.10.10"
	assert.Greater(t, CompareNetworkKeys(a, b), 0)
	a.DestinationIP = ""
	a.DestinationNames = "a"
	b.DestinationIP = ""
	b.DestinationNames = "a"
	require.Equal(t, CompareNetworkKeys(a, b), 0)
}

func TestProcessKey_String(t *testing.T) {
	key := ProcessKey{
		Namespace: HostNamespace,
		Name:      "bash",
		Args:      "-c ls",
	}
	assert.Equal(t, "host bash -c ls", key.String())

	key.Namespace = "default"
	key.WorkloadKind = common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT
	key.WorkloadName = "my-app"
	assert.Equal(t, "default/Deployment:my-app bash -c ls", key.String())
}

func Test_sortProcessKeys(t *testing.T) {
	a := ProcessKey{
		Namespace:    "a",
		WorkloadKind: common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
		WorkloadName: "a",
		Name:         "a",
		Args:         "a",
	}
	b := a
	// namespace
	assert.Zero(t, CompareProcessKeys(a, b))
	b.Namespace = "b"
	assert.Less(t, CompareProcessKeys(a, b), 0)
	b.Namespace = "A"
	assert.Greater(t, CompareProcessKeys(a, b), 0)
	b.Namespace = HostNamespace
	assert.Greater(t, CompareProcessKeys(a, b), 0)
	b.Namespace = a.Namespace

	// workload kind
	b.WorkloadKind = common.WorkloadKind_WORKLOAD_KIND_REPLICASET
	assert.Less(t, CompareProcessKeys(a, b), 0)
	b.WorkloadKind = common.WorkloadKind_WORKLOAD_KIND_DAEMONSET
	assert.Greater(t, CompareProcessKeys(a, b), 0)
	b.WorkloadKind = a.WorkloadKind

	// workload name
	b.WorkloadName = "b"
	assert.Less(t, CompareProcessKeys(a, b), 0)
	b.WorkloadName = "A"
	assert.Greater(t, CompareProcessKeys(a, b), 0)
	b.WorkloadName = a.WorkloadName

	// name
	b.Name = "b"
	assert.Less(t, CompareProcessKeys(a, b), 0)
	b.Name = "A"
	assert.Greater(t, CompareProcessKeys(a, b), 0)
	b.Name = a.Name

	// args
	b.Args = "b"
	assert.Less(t, CompareProcessKeys(a, b), 0)
	b.Args = "A"
	assert.Greater(t, CompareProcessKeys(a, b), 0)
	b.Args = a.Args
}

func TestConvertToMonitorData_ParentAggregation(t *testing.T) {
	tests := []struct {
		name     string
		input    []*types.ProcessModel
		expected ProcessMonitorData
	}{
		{
			name: "single process with one parent",
			input: []*types.ProcessModel{
				{
					Binary:     "exa",
					BinaryArgs: "-la",
					Parent:     "bash",
					Parents:    []string{"bash"},
					Namespace:  HostNamespace,
					Abi:        "x64",
					Syscalls:   []uint32{1, 2},
				},
			},
			expected: ProcessMonitorData{
				ProcessKey{
					Namespace: HostNamespace,
					Name:      "exa",
					Args:      "-la",
				}: ProcessValue{
					Parents: []string{"bash"},
				},
			},
		},
		{
			name: "multiple processes with same key but different parents",
			input: []*types.ProcessModel{
				{
					Binary:     "exa",
					BinaryArgs: "-la",
					Parent:     "bash",
					Parents:    []string{"bash"},
					Namespace:  HostNamespace,
					Abi:        "x64",
					Syscalls:   []uint32{1, 2},
				},
				{
					Binary:     "exa",
					BinaryArgs: "-la",
					Parent:     "zsh",
					Parents:    []string{"zsh"},
					Namespace:  HostNamespace,
					Abi:        "x64",
					Syscalls:   []uint32{1, 2},
				},
			},
			expected: ProcessMonitorData{
				ProcessKey{
					Namespace: HostNamespace,
					Name:      "exa",
					Args:      "-la",
				}: ProcessValue{
					Parents: []string{"bash", "zsh"}, // Should be sorted and aggregated
				},
			},
		},
		{
			name: "duplicate parents are deduped",
			input: []*types.ProcessModel{
				{
					Binary:     "ls",
					BinaryArgs: "",
					Parent:     "bash",
					Parents:    []string{"bash"},
					Namespace:  HostNamespace,
					Abi:        "x64",
					Syscalls:   []uint32{1},
				},
				{
					Binary:     "ls",
					BinaryArgs: "",
					Parent:     "bash",
					Parents:    []string{"bash"},
					Namespace:  HostNamespace,
					Abi:        "x64",
					Syscalls:   []uint32{1},
				},
			},
			expected: ProcessMonitorData{
				ProcessKey{
					Namespace: HostNamespace,
					Name:      "ls",
					Args:      "",
				}: ProcessValue{
					Parents: []string{"bash"}, // Only one instance despite duplicates
				},
			},
		},
		{
			name: "process with no parent",
			input: []*types.ProcessModel{
				{
					Binary:     "init",
					BinaryArgs: "",
					Parent:     "",
					Parents:    []string{},
					Namespace:  HostNamespace,
					Abi:        "x64",
					Syscalls:   []uint32{1},
				},
			},
			expected: ProcessMonitorData{
				ProcessKey{
					Namespace: HostNamespace,
					Name:      "init",
					Args:      "",
				}: ProcessValue{
					Parents: []string{}, // Empty parents list
				},
			},
		},
		{
			name: "workload process with parent",
			input: []*types.ProcessModel{
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
			},
			expected: ProcessMonitorData{
				ProcessKey{
					Namespace:    "default",
					WorkloadKind: common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
					WorkloadName: "my-app",
					Name:         "app",
					Args:         "--config=/etc/app.conf",
				}: ProcessValue{
					Parents: []string{"systemd"},
				},
			},
		},
		{
			name: "process with destinations",
			input: []*types.ProcessModel{
				{
					Binary:     "curl",
					BinaryArgs: "https://example.com",
					Parent:     "bash",
					Parents:    []string{"bash"},
					Namespace:  HostNamespace,
					Abi:        "x64",
					Syscalls:   []uint32{1},
					Dest: []*types.Destination{
						{
							DestinationNames: []string{"example.com"},
							Port:             443,
							Stats:            &types.DestinationStats{TxBytes: 10, RxBytes: 20},
						},
					},
				},
			},
			expected: ProcessMonitorData{
				ProcessKey{
					Namespace:    HostNamespace,
					WorkloadKind: common.WorkloadKind_WORKLOAD_KIND_UNSPECIFIED,
					WorkloadName: "",
					Name:         "curl",
					Args:         "https://example.com",
				}: ProcessValue{
					Parents: []string{"bash"},
				},
			},
		},
		{
			name: "process with destinations but nil stats (should not crash and should appear)",
			input: []*types.ProcessModel{
				{
					Binary:     "curl",
					BinaryArgs: "https://example.com",
					Parent:     "bash",
					Parents:    []string{"bash"},
					Namespace:  HostNamespace,
					Abi:        "x64",
					Syscalls:   []uint32{1},
					Dest: []*types.Destination{
						{
							DestinationNames: []string{"example.com"},
							Port:             443,
							Stats:            nil, // This should not cause a segfault
						},
					},
				},
			},
			expected: ProcessMonitorData{
				ProcessKey{
					Namespace:    HostNamespace,
					WorkloadKind: common.WorkloadKind_WORKLOAD_KIND_UNSPECIFIED,
					WorkloadName: "",
					Name:         "curl",
					Args:         "https://example.com",
				}: ProcessValue{
					Parents: []string{"bash"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, processData := ConvertToMonitorData(tt.input, false)

			// Check that we got the expected number of process entries
			assert.Equal(t, len(tt.expected), len(processData), "unexpected number of process entries")

			// Check each expected entry
			for expectedKey, expectedValue := range tt.expected {
				actualValue, found := processData[expectedKey]
				require.True(t, found, "expected process key not found: %v", expectedKey)

				// Check parents (main thing we're testing)
				assert.Equal(t, expectedValue.Parents, actualValue.Parents, "parents mismatch for key %v", expectedKey)

				// Basic sanity checks on other fields
				assert.NotNil(t, actualValue.Syscalls, "syscalls should not be nil")
				assert.False(t, actualValue.InInitTree, "inInitTree should be false for test data")
			}
		})
	}
}

func TestConvertToMonitorData_ParentWithWorkloadNil(t *testing.T) {
	// Test the nil workload case that was causing segmentation faults
	input := []*types.ProcessModel{
		{
			Binary:     "test-binary",
			BinaryArgs: "",
			Parent:     "parent-binary",
			Parents:    []string{"parent-binary"},
			Namespace:  HostNamespace,
			Workload:   nil, // This was causing the segfault
			Abi:        "x64",
			Syscalls:   []uint32{1},
		},
	}

	// This should not panic
	_, _, processData := ConvertToMonitorData(input, false)

	expected := ProcessKey{
		Namespace:    HostNamespace,
		WorkloadKind: common.WorkloadKind_WORKLOAD_KIND_UNSPECIFIED, // Default when workload is nil
		WorkloadName: "",                                            // Empty when workload is nil
		Name:         "test-binary",
		Args:         "",
	}

	value, found := processData[expected]
	require.True(t, found, "process should be found")
	assert.Equal(t, []string{"parent-binary"}, value.Parents)
}
