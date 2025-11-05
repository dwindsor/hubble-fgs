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

	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	common "github.com/isovalent/ipa/common/k8s/type/v1alpha"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

func TestMerge(t *testing.T) {
	m1 := appModelV1.ApplicationModel{
		Namespaces: nil,
		Host: &appModelV1.ApplicationHost{
			Processes: []*appModelV1.ApplicationProcessGroup{{Name: "curl"}},
		},
	}
	m2 := appModelV1.ApplicationModel{
		Namespaces: nil,
		Host: &appModelV1.ApplicationHost{
			Processes: []*appModelV1.ApplicationProcessGroup{{Name: "curl"}, {Name: "wget"}},
		},
	}
	res := Merge(&m1, &m2)
	res.Id = "" // Clear the UUID for unit test.
	merged, err := res.MarshalJSON()
	assert.NoError(t, err)
	expected := `{"host":{"processes":[{"in_init_tree":false,"name":"curl"},{"in_init_tree":false,"name":"wget"}]}}`

	assert.JSONEq(t, expected, string(merged))
}

func TestMergeArgs(t *testing.T) {
	m1 := appModelV1.ApplicationModel{
		Namespaces: nil,
		Host: &appModelV1.ApplicationHost{
			Processes: []*appModelV1.ApplicationProcessGroup{
				{Name: "curl", Arguments: "-v ebpf.io"},
				{Name: "curl", Arguments: "-v tetragon.io"},
			},
		},
	}
	m2 := appModelV1.ApplicationModel{
		Namespaces: nil,
		Host: &appModelV1.ApplicationHost{
			Processes: []*appModelV1.ApplicationProcessGroup{
				{Name: "curl", Arguments: "-v ebpf.io"},
				{Name: "wget"},
			},
		},
	}
	res := Merge(&m1, &m2)
	res.Id = "" // Clear the UUID for unit test.
	merged, err := res.MarshalJSON()
	assert.NoError(t, err)
	expected := `{"host":{"processes":[{"in_init_tree":false,"name":"curl", "arguments":"-v ebpf.io"},{"in_init_tree":false,"name":"curl", "arguments":"-v tetragon.io"},{"in_init_tree":false,"name":"wget"}]}}`
	assert.JSONEq(t, expected, string(merged))
}

func TestModelToMonitorData(t *testing.T) {
	app := &appModelV1.ApplicationModel{
		Namespaces: []*appModelV1.ApplicationNamespace{
			{
				Name: "default",
				Workloads: []*appModelV1.ApplicationWorkload{
					{
						Name: "workload1",
						Kind: common.WorkloadKind_WORKLOAD_KIND_POD,
						Processes: []*appModelV1.ApplicationProcessGroup{
							{
								Name:      "process1",
								Arguments: "arg1",
								Connections: []*appModelV1.ApplicationConnection{
									{
										Destination: &appModelV1.Destination{
											Type: &appModelV1.Destination_Dns{
												Dns: &appModelV1.DestinationDns{
													DestinationNames: []string{"dest1"},
												},
											},
											Port: 80,
										},
										Stats: &appModelV1.ConnectionStats{
											TxBytes: 100,
											RxBytes: 200,
										},
									},
								},
							},
							{
								Name:      "process2",
								Arguments: "arg2",
							},
						},
					},
				},
			},
		},
		Host: &appModelV1.ApplicationHost{
			Processes: []*appModelV1.ApplicationProcessGroup{
				{
					Name:      "hostprocess1",
					Arguments: "arg1",
					Connections: []*appModelV1.ApplicationConnection{
						{
							Destination: &appModelV1.Destination{
								Type: &appModelV1.Destination_Dns{
									Dns: &appModelV1.DestinationDns{
										DestinationNames: []string{"dest2"},
									},
								},
								Port: 443,
							},
							Stats: &appModelV1.ConnectionStats{
								TxBytes: 300,
								RxBytes: 400,
							},
						},
					},
				},
				{
					Name:      "hostprocess2",
					Arguments: "arg2",
				},
			},
		},
	}

	nmd := NetworkMonitorData{}
	pmd := ProcessMonitorData{}
	ToMonitorData(nmd, pmd, app)

	expectedNMD := NetworkMonitorData{
		NetworkKey{
			SourceNamespace:    "default",
			SourceWorkloadKind: common.WorkloadKind_WORKLOAD_KIND_POD,
			SourceWorkloadName: "workload1",
			SourceProcessName:  "process1",
			SourceProcessArgs:  "arg1",
			DestinationNames:   "dest1",
			DestinationPort:    80,
		}: NetworkMonitorValue{
			TXBytes: 100,
			RXBytes: 200,
		},
		NetworkKey{
			SourceNamespace:    HostNamespace,
			SourceWorkloadKind: common.WorkloadKind_WORKLOAD_KIND_UNSPECIFIED,
			SourceWorkloadName: HostWorkload,
			SourceProcessName:  "hostprocess1",
			SourceProcessArgs:  "arg1",
			DestinationNames:   "dest2",
			DestinationPort:    443,
		}: NetworkMonitorValue{
			TXBytes: 300,
			RXBytes: 400,
		},
	}

	expectedPMD := ProcessMonitorData{
		ProcessKey{
			Namespace:    "default",
			WorkloadKind: common.WorkloadKind_WORKLOAD_KIND_POD,
			WorkloadName: "workload1",
			Name:         "process1",
			Args:         "arg1",
		}: ProcessValue{},
		ProcessKey{
			Namespace:    "default",
			WorkloadKind: common.WorkloadKind_WORKLOAD_KIND_POD,
			WorkloadName: "workload1",
			Name:         "process2",
			Args:         "arg2",
		}: ProcessValue{},
		ProcessKey{
			Namespace:    HostNamespace,
			WorkloadKind: common.WorkloadKind_WORKLOAD_KIND_UNSPECIFIED,
			WorkloadName: HostWorkload,
			Name:         "hostprocess1",
			Args:         "arg1",
		}: ProcessValue{},
		ProcessKey{
			Namespace:    HostNamespace,
			WorkloadKind: common.WorkloadKind_WORKLOAD_KIND_UNSPECIFIED,
			WorkloadName: HostWorkload,
			Name:         "hostprocess2",
			Args:         "arg2",
		}: ProcessValue{},
	}
	assert.Equal(t, expectedNMD, nmd)
	assert.Equal(t, expectedPMD, pmd)
}

func TestProcessModelToApplicationModel_ParentTracking(t *testing.T) {
	// Test that parent information flows through the ProcessModel -> ApplicationModel conversion
	// properly and maintains the parent aggregation
	models := []*types.ProcessModel{
		{
			Binary:     "exa",
			BinaryArgs: "-la",
			Parent:     "bash",
			Parents:    []string{"bash"},
			Namespace:  HostNamespace,
			Workload:   nil,
		},
		{
			Binary:     "exa",
			BinaryArgs: "-la",
			Parent:     "zsh",
			Parents:    []string{"zsh"},
			Namespace:  HostNamespace,
			Workload:   nil,
		},
		{
			Binary:     "grep",
			BinaryArgs: "test",
			Parent:     "bash",
			Parents:    []string{"bash"},
			Namespace:  HostNamespace,
			Workload:   nil,
		},
	}

	emptyFilter := map[string]bool{}
	result := ProcessModelToApplicationModel(models, emptyFilter)

	// Check that we get the expected application model structure
	require.NotNil(t, result.ApplicationModel)
	require.NotNil(t, result.ApplicationModel.Host)
	require.Len(t, result.ApplicationModel.Host.Processes, 2) // exa and grep

	// Find the processes
	var exaProcess, grepProcess *appModelV1.ApplicationProcessGroup
	for _, proc := range result.ApplicationModel.Host.Processes {
		if proc.Name == "exa" && proc.Arguments == "-la" {
			exaProcess = proc
		} else if proc.Name == "grep" && proc.Arguments == "test" {
			grepProcess = proc
		}
	}

	require.NotNil(t, exaProcess, "exa process should be present")
	require.NotNil(t, grepProcess, "grep process should be present")

	// Note: The ApplicationProcessGroup doesn't currently have a Parents field in the IPA schema,
	// but we can verify that the parent information is properly tracked in the monitor data
	// by converting back to monitor data
	_, _, processData := ConvertToMonitorData(models, false)

	exaKey := ProcessKey{
		Namespace: HostNamespace,
		Name:      "exa",
		Args:      "-la",
	}
	grepKey := ProcessKey{
		Namespace: HostNamespace,
		Name:      "grep",
		Args:      "test",
	}

	exaValue, found := processData[exaKey]
	require.True(t, found, "exa process should be in monitor data")
	assert.Equal(t, []string{"bash", "zsh"}, exaValue.Parents, "exa should have both bash and zsh as parents")

	grepValue, found := processData[grepKey]
	require.True(t, found, "grep process should be in monitor data")
	assert.Equal(t, []string{"bash"}, grepValue.Parents, "grep should have bash as parent")
}

func TestProcessModelToApplicationModel_ParentTrackingWithWorkloads(t *testing.T) {
	// Test parent tracking with workload processes
	models := []*types.ProcessModel{
		{
			Binary:     "app",
			BinaryArgs: "--config=/etc/app.conf",
			Parent:     "systemd",
			Parents:    []string{"systemd"},
			Namespace:  "default",
			Workload:   &types.Workload{Kind: "Deployment", Name: "my-app"},
		},
		{
			Binary:     "app",
			BinaryArgs: "--config=/etc/app.conf",
			Parent:     "init",
			Parents:    []string{"init"},
			Namespace:  "default",
			Workload:   &types.Workload{Kind: "Deployment", Name: "my-app"},
		},
	}

	emptyFilter := map[string]bool{}
	result := ProcessModelToApplicationModel(models, emptyFilter)

	// Verify structure
	require.NotNil(t, result.ApplicationModel)
	require.Len(t, result.ApplicationModel.Namespaces, 1)
	require.Equal(t, "default", result.ApplicationModel.Namespaces[0].Name)
	require.Len(t, result.ApplicationModel.Namespaces[0].Workloads, 1)

	workload := result.ApplicationModel.Namespaces[0].Workloads[0]
	require.Equal(t, "my-app", workload.Name)
	require.Equal(t, common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT, workload.Kind)
	require.Len(t, workload.Processes, 1)

	process := workload.Processes[0]
	require.Equal(t, "app", process.Name)
	require.Equal(t, "--config=/etc/app.conf", process.Arguments)

	// Verify parent aggregation in monitor data
	_, _, processData := ConvertToMonitorData(models, false)

	appKey := ProcessKey{
		Namespace:    "default",
		WorkloadKind: common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
		WorkloadName: "my-app",
		Name:         "app",
		Args:         "--config=/etc/app.conf",
	}

	appValue, found := processData[appKey]
	require.True(t, found, "app process should be in monitor data")
	assert.Equal(t, []string{"init", "systemd"}, appValue.Parents, "app should have both init and systemd as parents")
}
