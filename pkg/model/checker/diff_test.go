// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package checker

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/isovalent/ipa/application_model/v1alpha"
	common "github.com/isovalent/ipa/common/k8s/type/v1alpha"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/model.json
var testModelJSON []byte

func TestDiffSimple(t *testing.T) {
	var diff string
	var err error

	diff, err = PrettyJsonDiff(
		&v1alpha.ApplicationModel{Namespaces: []*v1alpha.ApplicationNamespace{
			{Name: "foo"},
			{Name: "bar"},
		}},
		&v1alpha.ApplicationModel{Namespaces: []*v1alpha.ApplicationNamespace{
			{Name: "bar"},
			{Name: "foo"},
		}},
	)
	require.NoError(t, err)
	assert.Empty(t, diff)

	diff, err = PrettyJsonDiff(
		&v1alpha.ApplicationModel{Namespaces: []*v1alpha.ApplicationNamespace{
			{Name: "foo"},
			{Name: "bar"},
		}},
		&v1alpha.ApplicationModel{Namespaces: []*v1alpha.ApplicationNamespace{
			{Name: "oof"},
			{Name: "car"},
		}},
	)
	require.NoError(t, err)
	assert.NotEmpty(t, diff)
	assert.Contains(t, diff, "foo")
	assert.Contains(t, diff, "bar")
	assert.Contains(t, diff, "car")
	assert.Contains(t, diff, "oof")
}

func TestDiffComplex(t *testing.T) {
	var diff string
	var err error

	diff, err = PrettyJsonDiff(
		&v1alpha.ApplicationModel{Namespaces: []*v1alpha.ApplicationNamespace{
			{Name: "foo", Workloads: []*v1alpha.ApplicationWorkload{
				{
					Name: "workload1",
					Kind: common.WorkloadKind_WORKLOAD_KIND_DAEMONSET,
					Containers: []*v1alpha.ApplicationContainer{
						{
							Id:    "325790f3086f4",
							Name:  "my-app-container",
							Image: "docker.io/library/someapp:latest",
							Processes: []*v1alpha.ApplicationProcessGroup{
								{
									Name: "/bin/bash",
								},
								{
									Name: "/bin/fish",
								},
							},
						},
					},
				},
				{
					Name: "workload2",
					Kind: common.WorkloadKind_WORKLOAD_KIND_DAEMONSET,
					Containers: []*v1alpha.ApplicationContainer{
						{
							Id:    "e673699fa9961",
							Name:  "my-second-container",
							Image: "docker.io/library/otherapp:latest",
							Processes: []*v1alpha.ApplicationProcessGroup{
								{
									Name: "/bin/foo",
								},
								{
									Name: "/bin/bar",
								},
							},
						},
					},
				},
			}},
			{Name: "bar"},
		}},
		&v1alpha.ApplicationModel{Namespaces: []*v1alpha.ApplicationNamespace{
			{Name: "bar"},
			{Name: "foo", Workloads: []*v1alpha.ApplicationWorkload{
				{
					Name: "workload2",
					Kind: common.WorkloadKind_WORKLOAD_KIND_DAEMONSET,
					Containers: []*v1alpha.ApplicationContainer{
						{
							Id:    "e673699fa9961",
							Name:  "my-second-container",
							Image: "docker.io/library/otherapp:latest",
							Processes: []*v1alpha.ApplicationProcessGroup{
								{
									Name: "/bin/foo",
								},
								{
									Name: "/bin/bar",
								},
							},
						},
					},
				},
				{
					Name: "workload1",
					Kind: common.WorkloadKind_WORKLOAD_KIND_DAEMONSET,
					Containers: []*v1alpha.ApplicationContainer{
						{
							Id:    "325790f3086f4",
							Name:  "my-app-container",
							Image: "docker.io/library/someapp:latest",
							Processes: []*v1alpha.ApplicationProcessGroup{
								{
									Name: "/bin/fish",
								},
								{
									Name: "/bin/bash",
								},
							},
						},
					},
				},
			}},
		}},
	)
	require.NoError(t, err)
	assert.Empty(t, diff)
}

func TestDiffLarge(t *testing.T) {
	var diff string
	var err error

	a := &v1alpha.ApplicationModelEvent{}
	err = json.Unmarshal(testModelJSON, a)
	require.NoError(t, err)

	b := &v1alpha.ApplicationModelEvent{}
	err = json.Unmarshal(testModelJSON, b)
	require.NoError(t, err)

	diff, err = PrettyJsonDiff(a.ApplicationModel, b.ApplicationModel)
	require.NoError(t, err)
	assert.Empty(t, diff)

	b.ApplicationModel.Namespaces[1].Name = "Whoopsie Doopsie"
	b.ApplicationModel.Namespaces[2].Workloads[0].Containers[0].Processes[0].Name = "Foo"

	diff, err = PrettyJsonDiff(a.ApplicationModel, b.ApplicationModel)
	require.NoError(t, err)
	assert.Contains(t, diff, "Foo")
	assert.Contains(t, diff, "Whoopsie Doopsie")
}

func TestDiffIgnoreBytesSent(t *testing.T) {
	var err error
	var changed bool
	var diff []byte

	diff, changed, err = JsonDiff(
		&v1alpha.ApplicationModel{Namespaces: []*v1alpha.ApplicationNamespace{
			{
				Workloads: []*v1alpha.ApplicationWorkload{
					{
						Containers: []*v1alpha.ApplicationContainer{
							{
								Id:    "b1a8c6f707935",
								Name:  "my-third-container",
								Image: "docker.io/library/thirdapp:latest",
								Processes: []*v1alpha.ApplicationProcessGroup{
									{
										Connections: []*v1alpha.ApplicationConnection{
											{
												Destination: &v1alpha.Destination{
													Type: &v1alpha.Destination_Dns{
														Dns: &v1alpha.DestinationDns{
															DestinationNames: []string{"google.ca"},
														},
													},
													Port: 80,
												},
												Stats: &v1alpha.ConnectionStats{
													TxBytes: 1337,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}},
		&v1alpha.ApplicationModel{Namespaces: []*v1alpha.ApplicationNamespace{
			{
				Workloads: []*v1alpha.ApplicationWorkload{
					{
						Containers: []*v1alpha.ApplicationContainer{
							{
								Id:    "b1a8c6f707935",
								Name:  "my-third-container",
								Image: "docker.io/library/thirdapp:latest",
								Processes: []*v1alpha.ApplicationProcessGroup{
									{
										Connections: []*v1alpha.ApplicationConnection{
											{
												Destination: &v1alpha.Destination{
													Type: &v1alpha.Destination_Dns{
														Dns: &v1alpha.DestinationDns{
															DestinationNames: []string{"google.ca"},
														},
													},
													Port: 80,
												},
												Stats: &v1alpha.ConnectionStats{
													TxBytes: 1338,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}},
		IgnoreFields(
			"namespaces.workloads.containers.processes.connections.stats",
			"namespaces.workloads.containers.processes.children.connections.stats",
			"host.processes.connections.stats",
			"host.processes.children.connections.stats",
		),
	)
	fmt.Println(string(diff))
	require.NoError(t, err)
	assert.False(t, changed)
}
