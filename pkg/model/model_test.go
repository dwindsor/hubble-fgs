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
	expected := `{"host":{"processes":[{"name":"curl"},{"name":"wget"}]}}`
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
	expected := `{"host":{"processes":[{"name":"curl", "arguments":"-v ebpf.io"},{"name":"curl", "arguments":"-v tetragon.io"},{"name":"wget"}]}}`
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
						Kind: "pod",
						Processes: []*appModelV1.ApplicationProcessGroup{
							{
								Name:      "process1",
								Arguments: "arg1",
								Connections: []*appModelV1.ApplicationConnection{
									{
										DestinationName: "dest1",
										DestinationPort: 80,
										BytesSent:       100,
										BytesReceived:   200,
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
							DestinationName: "dest2",
							DestinationPort: 443,
							BytesSent:       300,
							BytesReceived:   400,
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
			SourceWorkloadKind: "pod",
			SourceWorkloadName: "workload1",
			SourceProcessName:  "process1",
			SourceProcessArgs:  "arg1",
			DestinationName:    "dest1",
			DestinationPort:    80,
		}: NetworkMonitorValue{
			TXBytes: 100,
			RXBytes: 200,
		},
		NetworkKey{
			SourceNamespace:    HostNamespace,
			SourceWorkloadKind: HostKind,
			SourceWorkloadName: HostWorkload,
			SourceProcessName:  "hostprocess1",
			SourceProcessArgs:  "arg1",
			DestinationName:    "dest2",
			DestinationPort:    443,
		}: NetworkMonitorValue{
			TXBytes: 300,
			RXBytes: 400,
		},
	}

	expectedPMD := ProcessMonitorData{
		ProcessKey{
			Namespace:    "default",
			WorkloadKind: "pod",
			WorkloadName: "workload1",
			Name:         "process1",
			Args:         "arg1",
		}: ProcessValue{},
		ProcessKey{
			Namespace:    "default",
			WorkloadKind: "pod",
			WorkloadName: "workload1",
			Name:         "process2",
			Args:         "arg2",
		}: ProcessValue{},
		ProcessKey{
			Namespace:    HostNamespace,
			WorkloadKind: HostKind,
			WorkloadName: HostWorkload,
			Name:         "hostprocess1",
			Args:         "arg1",
		}: ProcessValue{},
		ProcessKey{
			Namespace:    HostNamespace,
			WorkloadKind: HostKind,
			WorkloadName: HostWorkload,
			Name:         "hostprocess2",
			Args:         "arg2",
		}: ProcessValue{},
	}
	assert.Equal(t, expectedNMD, nmd)
	assert.Equal(t, expectedPMD, pmd)
}
