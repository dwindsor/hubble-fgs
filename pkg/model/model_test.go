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
	"github.com/stretchr/testify/assert"
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
						Kind: appModelV1.WorkloadKind_WORKLOAD_KIND_POD,
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
			SourceWorkloadKind: appModelV1.WorkloadKind_WORKLOAD_KIND_POD,
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
			SourceWorkloadKind: appModelV1.WorkloadKind_WORKLOAD_KIND_UNSPECIFIED,
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
			WorkloadKind: appModelV1.WorkloadKind_WORKLOAD_KIND_POD,
			WorkloadName: "workload1",
			Name:         "process1",
			Args:         "arg1",
		}: ProcessValue{},
		ProcessKey{
			Namespace:    "default",
			WorkloadKind: appModelV1.WorkloadKind_WORKLOAD_KIND_POD,
			WorkloadName: "workload1",
			Name:         "process2",
			Args:         "arg2",
		}: ProcessValue{},
		ProcessKey{
			Namespace:    HostNamespace,
			WorkloadKind: appModelV1.WorkloadKind_WORKLOAD_KIND_UNSPECIFIED,
			WorkloadName: HostWorkload,
			Name:         "hostprocess1",
			Args:         "arg1",
		}: ProcessValue{},
		ProcessKey{
			Namespace:    HostNamespace,
			WorkloadKind: appModelV1.WorkloadKind_WORKLOAD_KIND_UNSPECIFIED,
			WorkloadName: HostWorkload,
			Name:         "hostprocess2",
			Args:         "arg2",
		}: ProcessValue{},
	}
	assert.Equal(t, expectedNMD, nmd)
	assert.Equal(t, expectedPMD, pmd)
}
