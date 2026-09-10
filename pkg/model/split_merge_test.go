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

	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/google/go-cmp/cmp"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	common "github.com/isovalent/ipa/common/k8s/type/v1alpha"
	"github.com/stretchr/testify/assert"

	"github.com/isovalent/hubble-fgs/pkg/option"
)

var emptyUnifiedModel *appModelV1.ApplicationModel = &appModelV1.ApplicationModel{
	Id:         "019c49c4-8b93-7828-9b0b-e2796c732aae",
	Namespaces: []*appModelV1.ApplicationNamespace{},
	Host: &appModelV1.ApplicationHost{
		Processes: []*appModelV1.ApplicationProcessGroup{},
	},
}

var emptyUnifiedModelEvent *appModelV1.ApplicationModelEvent = &appModelV1.ApplicationModelEvent{
	ClusterName: "test-cluster",
	NodeName:    "test-node",
	Time: &timestamppb.Timestamp{
		Seconds: 11323237,
		Nanos:   2315,
	},
	ApplicationModel: emptyUnifiedModel,
	NodeLabels: map[string]string{
		"topology.kubernetes.io/region": "us-west-2",
	},
}

var emptyUnifiedModelFragment *appModelV1.ApplicationModelFragment = &appModelV1.ApplicationModelFragment{
	ClusterName: "test-cluster",
	NodeName:    "test-node",
	Time: &timestamppb.Timestamp{
		Seconds: 11323237,
		Nanos:   2315,
	},
	ApplicationModelFragment: emptyUnifiedModel,
	FragmentTotal:            1,
	FragmentIndex:            1,
	NodeLabels: map[string]string{
		"topology.kubernetes.io/region": "us-west-2",
	},
}

var expectedUnifiedApplicationModel *appModelV1.ApplicationModel = &appModelV1.ApplicationModel{
	Id: "019c49c4-8b93-7828-9b0b-e2796c732aae",
	Namespaces: []*appModelV1.ApplicationNamespace{
		{
			Name: "namespace1",
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
							},
						},
					},
				},
				{
					Name: "workload2",
					Kind: common.WorkloadKind_WORKLOAD_KIND_DAEMONSET,
					Containers: []*appModelV1.ApplicationContainer{
						{
							Id:    "c1dbc2d6bf3a",
							Name:  "busybox-2",
							Image: "docker.io/library/busybox:dev",
							Processes: []*appModelV1.ApplicationProcessGroup{
								{
									Name:      "process2",
									Arguments: "arg2",
								},
							},
						},
						{
							Id:    "7171c97a5162",
							Name:  "busybox-3",
							Image: "docker.io/library/busybox:test",
							Processes: []*appModelV1.ApplicationProcessGroup{
								{
									Name:      "process3",
									Arguments: "arg3",
								},
							},
						},
					},
				},
			},
		},
		{
			Name: "namespace2",
			Workloads: []*appModelV1.ApplicationWorkload{
				{
					Name: "workload3",
					Kind: common.WorkloadKind_WORKLOAD_KIND_JOB,
					Containers: []*appModelV1.ApplicationContainer{
						{
							Id:    "18b0fda1fa3d",
							Name:  "busybox-4",
							Image: "docker.io/library/busybox:experimental",
							Processes: []*appModelV1.ApplicationProcessGroup{
								{
									Name:      "process4",
									Arguments: "arg4",
								},
								{
									Name:      "process5",
									Arguments: "arg5",
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
			},
			{
				Name:      "hostprocess2",
				Arguments: "arg2",
			},
			{
				Name:      "hostprocess3",
				Arguments: "arg3",
			},
			{
				Name:      "hostprocess4",
				Arguments: "arg4",
			},
			{
				Name:      "hostprocess5",
				Arguments: "arg5",
			},
		},
	},
}

var expectedUnifiedModelEvent *appModelV1.ApplicationModelEvent = &appModelV1.ApplicationModelEvent{
	ClusterName: "test-cluster",
	NodeName:    "test-node",
	Time: &timestamppb.Timestamp{
		Seconds: 11323237,
		Nanos:   2315,
	},
	ApplicationModel: expectedUnifiedApplicationModel,
	NodeLabels: map[string]string{
		"topology.kubernetes.io/region": "us-west-2",
	},
}

var expectedUnifiedModelFragment *appModelV1.ApplicationModelFragment = &appModelV1.ApplicationModelFragment{
	ClusterName: "test-cluster",
	NodeName:    "test-node",
	Time: &timestamppb.Timestamp{
		Seconds: 11323237,
		Nanos:   2315,
	},
	ApplicationModelFragment: expectedUnifiedApplicationModel,
	FragmentTotal:            1,
	FragmentIndex:            1,
	NodeLabels: map[string]string{
		"topology.kubernetes.io/region": "us-west-2",
	},
}

var expectedSplitModelFragments = []*appModelV1.ApplicationModelFragment{
	&appModelV1.ApplicationModelFragment{
		ClusterName: "test-cluster",
		NodeName:    "test-node",
		Time: &timestamppb.Timestamp{
			Seconds: 11323237,
			Nanos:   2315,
		},
		ApplicationModelFragment: &appModelV1.ApplicationModel{
			Id: "019c49c4-8b93-7828-9b0b-e2796c732aae",
			Host: &appModelV1.ApplicationHost{
				Processes: []*appModelV1.ApplicationProcessGroup{
					{
						Name:      "hostprocess1",
						Arguments: "arg1",
					},
					{
						Name:      "hostprocess2",
						Arguments: "arg2",
					},
				},
			},
		},
		FragmentTotal: 6,
		FragmentIndex: 1,
		NodeLabels: map[string]string{
			"topology.kubernetes.io/region": "us-west-2",
		},
	},
	&appModelV1.ApplicationModelFragment{
		ClusterName: "test-cluster",
		NodeName:    "test-node",
		Time: &timestamppb.Timestamp{
			Seconds: 11323237,
			Nanos:   2315,
		},
		ApplicationModelFragment: &appModelV1.ApplicationModel{
			Id: "019c49c4-8b93-7828-9b0b-e2796c732aae",
			Host: &appModelV1.ApplicationHost{
				Processes: []*appModelV1.ApplicationProcessGroup{
					{
						Name:      "hostprocess3",
						Arguments: "arg3",
					},
					{
						Name:      "hostprocess4",
						Arguments: "arg4",
					},
				},
			},
		},
		FragmentTotal: 6,
		FragmentIndex: 2,
		NodeLabels: map[string]string{
			"topology.kubernetes.io/region": "us-west-2",
		},
	},
	&appModelV1.ApplicationModelFragment{
		ClusterName: "test-cluster",
		NodeName:    "test-node",
		Time: &timestamppb.Timestamp{
			Seconds: 11323237,
			Nanos:   2315,
		},
		ApplicationModelFragment: &appModelV1.ApplicationModel{
			Id: "019c49c4-8b93-7828-9b0b-e2796c732aae",
			Host: &appModelV1.ApplicationHost{
				Processes: []*appModelV1.ApplicationProcessGroup{
					{
						Name:      "hostprocess5",
						Arguments: "arg5",
					},
				},
			},
		},
		FragmentTotal: 6,
		FragmentIndex: 3,
		NodeLabels: map[string]string{
			"topology.kubernetes.io/region": "us-west-2",
		},
	},
	&appModelV1.ApplicationModelFragment{
		ClusterName: "test-cluster",
		NodeName:    "test-node",
		Time: &timestamppb.Timestamp{
			Seconds: 11323237,
			Nanos:   2315,
		},
		ApplicationModelFragment: &appModelV1.ApplicationModel{
			Id: "019c49c4-8b93-7828-9b0b-e2796c732aae",
			Namespaces: []*appModelV1.ApplicationNamespace{
				{
					Name: "namespace1",
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
									},
								},
							},
						},
					},
				},
			},
		},
		FragmentTotal: 6,
		FragmentIndex: 4,
		NodeLabels: map[string]string{
			"topology.kubernetes.io/region": "us-west-2",
		},
	},
	&appModelV1.ApplicationModelFragment{
		ClusterName: "test-cluster",
		NodeName:    "test-node",
		Time: &timestamppb.Timestamp{
			Seconds: 11323237,
			Nanos:   2315,
		},
		ApplicationModelFragment: &appModelV1.ApplicationModel{
			Id: "019c49c4-8b93-7828-9b0b-e2796c732aae",
			Namespaces: []*appModelV1.ApplicationNamespace{
				{
					Name: "namespace1",
					Workloads: []*appModelV1.ApplicationWorkload{
						{
							Name: "workload2",
							Kind: common.WorkloadKind_WORKLOAD_KIND_DAEMONSET,
							Containers: []*appModelV1.ApplicationContainer{
								{
									Id:    "c1dbc2d6bf3a",
									Name:  "busybox-2",
									Image: "docker.io/library/busybox:dev",
									Processes: []*appModelV1.ApplicationProcessGroup{
										{
											Name:      "process2",
											Arguments: "arg2",
										},
									},
								},
								{
									Id:    "7171c97a5162",
									Name:  "busybox-3",
									Image: "docker.io/library/busybox:test",
									Processes: []*appModelV1.ApplicationProcessGroup{
										{
											Name:      "process3",
											Arguments: "arg3",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		FragmentTotal: 6,
		FragmentIndex: 5,
		NodeLabels: map[string]string{
			"topology.kubernetes.io/region": "us-west-2",
		},
	},
	&appModelV1.ApplicationModelFragment{
		ClusterName: "test-cluster",
		NodeName:    "test-node",
		Time: &timestamppb.Timestamp{
			Seconds: 11323237,
			Nanos:   2315,
		},
		ApplicationModelFragment: &appModelV1.ApplicationModel{
			Id: "019c49c4-8b93-7828-9b0b-e2796c732aae",
			Namespaces: []*appModelV1.ApplicationNamespace{
				{
					Name: "namespace2",
					Workloads: []*appModelV1.ApplicationWorkload{
						{
							Name: "workload3",
							Kind: common.WorkloadKind_WORKLOAD_KIND_JOB,
							Containers: []*appModelV1.ApplicationContainer{
								{
									Id:    "18b0fda1fa3d",
									Name:  "busybox-4",
									Image: "docker.io/library/busybox:experimental",
									Processes: []*appModelV1.ApplicationProcessGroup{
										{
											Name:      "process4",
											Arguments: "arg4",
										},
										{
											Name:      "process5",
											Arguments: "arg5",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		FragmentTotal: 6,
		FragmentIndex: 6,
		NodeLabels: map[string]string{
			"topology.kubernetes.io/region": "us-west-2",
		},
	},
}

func TestSplitApplicationModelEvent(t *testing.T) {
	option.Config.ApplicationModelSplitMaxHostProcs = 2
	fragments := SplitApplicationModelEvent(expectedUnifiedModelEvent)
	for _, fragment := range fragments {
		assert.Equal(t, expectedUnifiedModelEvent.NodeLabels, fragment.NodeLabels)
	}

	if diff := cmp.Diff(expectedSplitModelFragments, fragments, protocmp.Transform()); diff != "" {
		t.Errorf("SplitApplicationModelEvent() mismatch (-want +got):\n%s", diff)
	}
}

func TestSplitAndMergeApplicationModelExecIDs(t *testing.T) {
	oldMaxHostProcs := option.Config.ApplicationModelSplitMaxHostProcs
	option.Config.ApplicationModelSplitMaxHostProcs = 1
	defer func() {
		option.Config.ApplicationModelSplitMaxHostProcs = oldMaxHostProcs
	}()

	event := &appModelV1.ApplicationModelEvent{
		ApplicationModel: &appModelV1.ApplicationModel{
			Id: "model-id",
			Host: &appModelV1.ApplicationHost{
				Processes: []*appModelV1.ApplicationProcessGroup{
					{Name: "host-process", ExecIds: []string{"host-exec-id"}},
				},
			},
			Namespaces: []*appModelV1.ApplicationNamespace{
				{
					Name: "default",
					Workloads: []*appModelV1.ApplicationWorkload{
						{
							Name: "workload",
							Containers: []*appModelV1.ApplicationContainer{
								{
									Processes: []*appModelV1.ApplicationProcessGroup{
										{Name: "workload-process", ExecIds: []string{"workload-exec-id"}},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	fragments := SplitApplicationModelEvent(event)
	assert.Len(t, fragments, 2)
	assert.Equal(t, []string{"host-exec-id"}, fragments[0].ApplicationModelFragment.Host.Processes[0].GetExecIds())
	assert.Equal(t, []string{"workload-exec-id"}, fragments[1].ApplicationModelFragment.Namespaces[0].Workloads[0].Containers[0].Processes[0].GetExecIds())

	merged, err := MergeApplicationModelFragments(fragments)
	assert.NoError(t, err)
	assert.Equal(t, []string{"host-exec-id"}, merged.ApplicationModel.Host.Processes[0].GetExecIds())
	assert.Equal(t, []string{"workload-exec-id"}, merged.ApplicationModel.Namespaces[0].Workloads[0].Containers[0].Processes[0].GetExecIds())
}

func TestMergeApplicationModelFragments(t *testing.T) {
	merged, err := MergeApplicationModelFragments(expectedSplitModelFragments)
	assert.Nil(t, err)
	assert.Equal(t, expectedSplitModelFragments[0].NodeLabels, merged.NodeLabels)

	if diff := cmp.Diff(expectedUnifiedModelEvent, merged, protocmp.Transform()); diff != "" {
		t.Errorf("MergeApplicationModelFragments() mismatch (-want +got):\n%s", diff)
	}
}

func TestMergeApplicationModelFragmentsUsesFirstNodeLabels(t *testing.T) {
	option.Config.ApplicationModelSplitMaxHostProcs = 2
	fragments := SplitApplicationModelEvent(expectedUnifiedModelEvent)
	fragments[1].NodeLabels = map[string]string{"topology.kubernetes.io/zone": "us-west-2a"}

	merged, err := MergeApplicationModelFragments(fragments)
	assert.NoError(t, err)
	assert.Equal(t, expectedUnifiedModelEvent.NodeLabels, merged.NodeLabels)
}

func TestMergeApplicationModelFragmentsSingle(t *testing.T) {
	merged, err := MergeApplicationModelFragments([]*appModelV1.ApplicationModelFragment{expectedUnifiedModelFragment})
	assert.Nil(t, err)

	if diff := cmp.Diff(expectedUnifiedModelEvent, merged, protocmp.Transform()); diff != "" {
		t.Errorf("MergeApplicationModelFragments() mismatch (-want +got):\n%s", diff)
	}
}

func TestSplitEmptyApplicationModelEvent(t *testing.T) {
	fragments := SplitApplicationModelEvent(emptyUnifiedModelEvent)

	assert.NotNil(t, fragments)
	assert.Len(t, fragments, 1)

	if diff := cmp.Diff(emptyUnifiedModelFragment, fragments[0], protocmp.Transform()); diff != "" {
		t.Errorf("SplitEmptyApplicationModelEvent() mismatch (-want +got):\n%s", diff)
	}
}

func TestMergeEmptyApplicationModelFragments(t *testing.T) {
	merged, err := MergeApplicationModelFragments([]*appModelV1.ApplicationModelFragment{emptyUnifiedModelFragment})
	assert.Nil(t, err)

	if diff := cmp.Diff(emptyUnifiedModelEvent, merged, protocmp.Transform()); diff != "" {
		t.Errorf("MergeApplicationModelFragments() mismatch (-want +got):\n%s", diff)
	}
}

func TestMergeApplicationModelFragmentsEmptyArray(t *testing.T) {
	_, err := MergeApplicationModelFragments([]*appModelV1.ApplicationModelFragment{})
	assert.EqualError(t, err, "fragments must be non-empty")
}

func TestMergeApplicationModelFragmentsNoAppModel(t *testing.T) {
	fragments := []*appModelV1.ApplicationModelFragment{
		{
			ClusterName: "test-cluster",
		},
	}
	_, err := MergeApplicationModelFragments(fragments)
	assert.EqualError(t, err, "nil ApplicationModelFragment")
}

func TestMergeApplicationModelFragmentsEmptyAppModelId(t *testing.T) {
	fragments := []*appModelV1.ApplicationModelFragment{
		{
			ClusterName: "test-cluster",
			ApplicationModelFragment: &appModelV1.ApplicationModel{
				Id: "",
			},
		},
	}
	_, err := MergeApplicationModelFragments(fragments)
	assert.EqualError(t, err, "empty ApplicationModelFragment.Id")
}

func TestMergeApplicationModelFragmentsMismatchAppModelIds(t *testing.T) {
	fragments := []*appModelV1.ApplicationModelFragment{
		{
			ClusterName: "test-cluster",
			ApplicationModelFragment: &appModelV1.ApplicationModel{
				Id: "Id1",
			},
		},
		{
			ClusterName: "test-cluster",
			ApplicationModelFragment: &appModelV1.ApplicationModel{
				Id: "Id2",
			},
		},
	}
	_, err := MergeApplicationModelFragments(fragments)
	assert.EqualError(t, err, "mismatched ApplicationModelFragment ids")
}

func TestMergeApplicationModelFragmentsMismatchFragmentTotal(t *testing.T) {
	fragments := []*appModelV1.ApplicationModelFragment{
		{
			ClusterName: "test-cluster",
			ApplicationModelFragment: &appModelV1.ApplicationModel{
				Id: "Id1",
			},
			FragmentTotal: 2,
			FragmentIndex: 1,
		},
	}
	_, err := MergeApplicationModelFragments(fragments)
	assert.EqualError(t, err, "number of fragments does not match FragmentTotal")
}
