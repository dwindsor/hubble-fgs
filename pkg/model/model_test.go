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
	expected := `{"host":{"processes":[{"hash":"427e4b79b1f0fc90306cbe064b1297b21dc6835bfa656d3bf46bc156e3f24bb0","in_init_tree":false,"name":"curl"},{"hash":"570e342d0e4708dab94b2025f6b928845b659b405872d824b45473c4635d7b1d","in_init_tree":false,"name":"wget"}]}}`

	assert.JSONEq(t, expected, string(merged))
}

func TestMergeFoldsUnspecifiedObservationPoint(t *testing.T) {
	appModel := func(op appModelV1.ObservationPoint, txBytes uint64) *appModelV1.ApplicationModel {
		return &appModelV1.ApplicationModel{
			Host: &appModelV1.ApplicationHost{
				Processes: []*appModelV1.ApplicationProcessGroup{
					{
						Name: "curl",
						Connections: []*appModelV1.ApplicationConnection{
							{
								Destination: &appModelV1.Destination{
									Type: &appModelV1.Destination_Dns{
										Dns: &appModelV1.DestinationDns{
											DestinationNames: []string{"dest1"},
										},
									},
									Port: 443,
								},
								Stats:            &appModelV1.ConnectionStats{TxBytes: txBytes},
								ObservationPoint: op,
							},
						},
					},
				},
			},
		}
	}

	older := appModel(appModelV1.ObservationPoint_OBSERVATION_POINT_UNSPECIFIED, 100)
	newer := appModel(appModelV1.ObservationPoint_OBSERVATION_POINT_SOURCE, 200)

	res := Merge(older, newer)
	require.Len(t, res.GetHost().GetProcesses(), 1)
	conns := res.GetHost().GetProcesses()[0].GetConnections()
	require.Len(t, conns, 1)
	assert.Equal(t, appModelV1.ObservationPoint_OBSERVATION_POINT_SOURCE, conns[0].GetObservationPoint())
	assert.Equal(t, uint64(200), conns[0].GetStats().GetTxBytes())
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
	expected := `{"host":{"processes":[{"hash":"321311b99c11a3fa1048fb158670aab14355bf633dd302d3fed750f89e05f1c5","in_init_tree":false,"name":"curl", "arguments":"-v ebpf.io"},{"hash":"7d95c46e8e4ccede2e3963a1db6765819e2edd8546c012674d97103990e60164","in_init_tree":false,"name":"curl", "arguments":"-v tetragon.io"},{"hash":"570e342d0e4708dab94b2025f6b928845b659b405872d824b45473c4635d7b1d","in_init_tree":false,"name":"wget"}]}}`
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
						Containers: []*appModelV1.ApplicationContainer{
							{
								Id:    "04c7f6fce6aa",
								Name:  "busybox-1",
								Image: "docker.io/library/busybox:latest",
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
			SourceNamespace:            "default",
			SourceWorkloadKind:         common.WorkloadKind_WORKLOAD_KIND_POD,
			SourceWorkloadResourceKind: common.ResourceKind_RESOURCE_KIND_WORKLOAD,
			SourceWorkloadName:         "workload1",
			SourceContainer: types.ContainerInfo{
				Id:    "04c7f6fce6aa",
				Name:  "busybox-1",
				Image: "docker.io/library/busybox:latest",
			},
			SourceProcessName: "process1",
			SourceProcessArgs: "arg1",
			DestinationNames:  "dest1",
			DestinationPort:   80,
			ObservationPoint:  appModelV1.ObservationPoint_OBSERVATION_POINT_SOURCE,
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
			ObservationPoint:   appModelV1.ObservationPoint_OBSERVATION_POINT_SOURCE,
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
			Container: types.ContainerInfo{
				Id:    "04c7f6fce6aa",
				Name:  "busybox-1",
				Image: "docker.io/library/busybox:latest",
			},
			Name: "process1",
			Args: "arg1",
		}: ProcessValue{},
		ProcessKey{
			Namespace:    "default",
			WorkloadKind: common.WorkloadKind_WORKLOAD_KIND_POD,
			WorkloadName: "workload1",
			Container: types.ContainerInfo{
				Id:    "04c7f6fce6aa",
				Name:  "busybox-1",
				Image: "docker.io/library/busybox:latest",
			},
			Name: "process2",
			Args: "arg2",
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
	result := ProcessModelToApplicationModel(models, emptyFilter, map[string]string{"some-label": "some-value"})

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

	require.Equal(t, 1, len(result.NodeLabels), "Node labels should be present")
	require.Equal(t, "some-value", result.NodeLabels["some-label"], "Node label value should match")

	// Note: The ApplicationProcessGroup doesn't currently have a Parents field in the IPA schema,
	// but we can verify that the parent information is properly tracked in the monitor data
	// by converting back to monitor data
	_, processData := ConvertToMonitorData(models, false)

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
			Workload: &types.Workload{
				Kind: "Deployment",
				Name: "my-app",
				UID:  "deployment-uid",
			},
			Container: &types.ContainerInfo{
				Id:    "354f9d014f814",
				Name:  "test-container",
				Image: "docker.io/library/testapp:latest",
			},
		},
		{
			Binary:     "app",
			BinaryArgs: "--config=/etc/app.conf",
			Parent:     "init",
			Parents:    []string{"init"},
			Namespace:  "default",
			Workload: &types.Workload{
				Kind: "Deployment",
				Name: "my-app",
				UID:  "deployment-uid",
			},
			Container: &types.ContainerInfo{
				Id:    "354f9d014f814",
				Name:  "test-container",
				Image: "docker.io/library/testapp:latest",
			},
		},
	}

	emptyFilter := map[string]bool{}
	result := ProcessModelToApplicationModel(models, emptyFilter, nil)

	// Verify structure
	require.NotNil(t, result.ApplicationModel)
	require.Len(t, result.ApplicationModel.Namespaces, 1)
	require.Equal(t, "default", result.ApplicationModel.Namespaces[0].Name)
	require.Len(t, result.ApplicationModel.Namespaces[0].Workloads, 1)

	workload := result.ApplicationModel.Namespaces[0].Workloads[0]
	require.Equal(t, "my-app", workload.Name)
	require.Equal(t, common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT, workload.Kind)
	require.Equal(t, "deployment-uid", workload.Uid)
	require.Len(t, workload.Containers, 1)

	container := result.ApplicationModel.Namespaces[0].Workloads[0].Containers[0]
	require.Equal(t, "354f9d014f814", container.Id)
	require.Equal(t, "test-container", container.Name)
	require.Equal(t, "docker.io/library/testapp:latest", container.Image)
	require.Len(t, container.Processes, 1)

	process := container.Processes[0]
	require.Equal(t, "app", process.Name)
	require.Equal(t, "--config=/etc/app.conf", process.Arguments)

	// Verify parent aggregation in monitor data
	_, processData := ConvertToMonitorData(models, false)

	appKey := ProcessKey{
		Namespace:    "default",
		WorkloadKind: common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
		WorkloadName: "my-app",
		WorkloadUID:  "deployment-uid",
		Container: types.ContainerInfo{
			Id:    "354f9d014f814",
			Name:  "test-container",
			Image: "docker.io/library/testapp:latest",
		},
		Name: "app",
		Args: "--config=/etc/app.conf",
	}

	appValue, found := processData[appKey]
	require.True(t, found, "app process should be in monitor data")
	assert.Equal(t, []string{"init", "systemd"}, appValue.Parents, "app should have both init and systemd as parents")
}

func TestProcessModelToApplicationModel_ExecIDsPropagation(t *testing.T) {
	models := []*types.ProcessModel{
		{
			Binary:     "bash",
			BinaryArgs: "-c true",
			Namespace:  HostNamespace,
			ExecIDs:    []string{"id2", "id1"},
		},
		{
			Binary:     "bash",
			BinaryArgs: "-c true",
			Namespace:  HostNamespace,
			ExecIDs:    []string{"id3", "id1"},
		},
	}

	result := ProcessModelToApplicationModel(models, map[string]bool{}, map[string]string{})
	require.NotNil(t, result.ApplicationModel)
	require.NotNil(t, result.ApplicationModel.Host)
	require.Len(t, result.ApplicationModel.Host.Processes, 1)

	proc := result.ApplicationModel.Host.Processes[0]
	assert.Equal(t, "bash", proc.Name)
	assert.Equal(t, "-c true", proc.Arguments)
	assert.Equal(t, []string{"id1", "id2", "id3"}, proc.GetExecIds())

	_, processData := ConvertToMonitorData(models, false)
	key := ProcessKey{Namespace: HostNamespace, Name: "bash", Args: "-c true"}
	value, found := processData[key]
	require.True(t, found, "bash process should be in monitor data")
	assert.Equal(t, []string{"id1", "id2", "id3"}, value.ExecIDs)
}

// TestProcessModelToApplicationModel_PlainIPClassification is a regression test
// for the bug where a plain-IP destination was placed in DestinationNames and
// thus misclassified as a DNS destination. A types.Destination carrying only a
// DestinationIP (no DestinationNames) must convert to a Destination_Ip so it is
// reported as a plain IP downstream, not as a DNS name.
func TestProcessModelToApplicationModel_PlainIPClassification(t *testing.T) {
	models := []*types.ProcessModel{
		{
			Binary:    "curl",
			Namespace: HostNamespace,
			Dest: []*types.Destination{
				{
					DestinationIP: "10.0.0.1",
					Port:          443,
					Stats:         &types.DestinationStats{TxBytes: 10, RxBytes: 20},
				},
			},
		},
	}

	result := ProcessModelToApplicationModel(models, map[string]bool{}, nil)
	require.NotNil(t, result.ApplicationModel.Host)
	require.Len(t, result.ApplicationModel.Host.Processes, 1)
	conns := result.ApplicationModel.Host.Processes[0].Connections
	require.Len(t, conns, 1)

	dst := conns[0].Destination
	// Must be a plain IP, not a DNS name.
	ipDst, ok := dst.Type.(*appModelV1.Destination_Ip)
	require.Truef(t, ok, "expected Destination_Ip, got %T (plain IP misclassified)", dst.Type)
	assert.Equal(t, "10.0.0.1", ipDst.Ip.Ip)
}

// TestProcessModelToApplicationModel_ReceiveDropCounters checks that the six
// receive drop counters survive the whole conversion from DestinationStats to
// the ConnectionStats on the application model.
func TestProcessModelToApplicationModel_ReceiveDropCounters(t *testing.T) {
	models := []*types.ProcessModel{
		{
			Binary:    "curl",
			Namespace: HostNamespace,
			Dest: []*types.Destination{
				{
					DestinationIP: "10.0.0.1",
					Port:          443,
					Stats: &types.DestinationStats{
						RxBytes:               200,
						RxDropBytes:           40,
						RxDropPackets:         8,
						RxDefaultDropBytes:    12,
						RxDefaultDropPackets:  4,
						RxDefaultAllowBytes:   18,
						RxDefaultAllowPackets: 6,
					},
				},
			},
		},
	}

	result := ProcessModelToApplicationModel(models, map[string]bool{}, nil)
	require.NotNil(t, result.ApplicationModel.Host)
	require.Len(t, result.ApplicationModel.Host.Processes, 1)
	conns := result.ApplicationModel.Host.Processes[0].Connections
	require.Len(t, conns, 1)

	stats := conns[0].Stats
	assert.Equal(t, uint64(200), stats.RxBytes)
	assert.Equal(t, uint64(40), stats.RxDropBytes)
	assert.Equal(t, uint64(8), stats.RxDropPackets)
	assert.Equal(t, uint64(12), stats.RxDefaultDropBytes)
	assert.Equal(t, uint64(4), stats.RxDefaultDropPackets)
	assert.Equal(t, uint64(18), stats.RxDefaultAllowBytes)
	assert.Equal(t, uint64(6), stats.RxDefaultAllowPackets)
}
