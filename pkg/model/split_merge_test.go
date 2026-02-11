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

var emptyUnifiedModelEvent *appModelV1.ApplicationModelEvent = &appModelV1.ApplicationModelEvent{
	ClusterName: "test-cluster",
	NodeName:    "test-node",
	Time: &timestamppb.Timestamp{
		Seconds: 11323237,
		Nanos:   2315,
	},
	ApplicationModel: &appModelV1.ApplicationModel{
		Id:         "019c49c4-8b93-7828-9b0b-e2796c732aae",
		Namespaces: []*appModelV1.ApplicationNamespace{},
		Host: &appModelV1.ApplicationHost{
			Processes: []*appModelV1.ApplicationProcessGroup{},
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
	ApplicationModel: &appModelV1.ApplicationModel{
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
	},
}

var expectedSplitModelEvents = []*appModelV1.ApplicationModelEvent{
	&appModelV1.ApplicationModelEvent{
		ClusterName: "test-cluster",
		NodeName:    "test-node",
		Time: &timestamppb.Timestamp{
			Seconds: 11323237,
			Nanos:   2315,
		},
		ApplicationModel: &appModelV1.ApplicationModel{
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
	},
	&appModelV1.ApplicationModelEvent{
		ClusterName: "test-cluster",
		NodeName:    "test-node",
		Time: &timestamppb.Timestamp{
			Seconds: 11323237,
			Nanos:   2315,
		},
		ApplicationModel: &appModelV1.ApplicationModel{
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
	},
	&appModelV1.ApplicationModelEvent{
		ClusterName: "test-cluster",
		NodeName:    "test-node",
		Time: &timestamppb.Timestamp{
			Seconds: 11323237,
			Nanos:   2315,
		},
		ApplicationModel: &appModelV1.ApplicationModel{
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
	},
	&appModelV1.ApplicationModelEvent{
		ClusterName: "test-cluster",
		NodeName:    "test-node",
		Time: &timestamppb.Timestamp{
			Seconds: 11323237,
			Nanos:   2315,
		},
		ApplicationModel: &appModelV1.ApplicationModel{
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
	},
	&appModelV1.ApplicationModelEvent{
		ClusterName: "test-cluster",
		NodeName:    "test-node",
		Time: &timestamppb.Timestamp{
			Seconds: 11323237,
			Nanos:   2315,
		},
		ApplicationModel: &appModelV1.ApplicationModel{
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
	},
	&appModelV1.ApplicationModelEvent{
		ClusterName: "test-cluster",
		NodeName:    "test-node",
		Time: &timestamppb.Timestamp{
			Seconds: 11323237,
			Nanos:   2315,
		},
		ApplicationModel: &appModelV1.ApplicationModel{
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
	},
}

func TestSplitApplicationModelEvent(t *testing.T) {

	option.Config.ApplicationModelSplitMaxHostProcs = 2
	split := SplitApplicationModelEvent(expectedUnifiedModelEvent)

	if diff := cmp.Diff(expectedSplitModelEvents, split, protocmp.Transform()); diff != "" {
		t.Errorf("SplitApplicationModelEvent() mismatch (-want +got):\n%s", diff)
	}
}

func TestMergeApplicationModelEvents(t *testing.T) {

	merged, err := MergeApplicationModelEvents(expectedSplitModelEvents)
	assert.Nil(t, err)

	if diff := cmp.Diff(expectedUnifiedModelEvent, merged, protocmp.Transform()); diff != "" {
		t.Errorf("MergeApplicationModelEvent() mismatch (-want +got):\n%s", diff)
	}
}

func TestMergeApplicationModelEventsSingle(t *testing.T) {

	merged, err := MergeApplicationModelEvents([]*appModelV1.ApplicationModelEvent{expectedUnifiedModelEvent})
	assert.Nil(t, err)

	if diff := cmp.Diff(expectedUnifiedModelEvent, merged, protocmp.Transform()); diff != "" {
		t.Errorf("MergeApplicationModelEvent() mismatch (-want +got):\n%s", diff)
	}
}

func TestSplitEmptyApplicationModelEvent(t *testing.T) {

	split := SplitApplicationModelEvent(emptyUnifiedModelEvent)

	assert.NotNil(t, split)
	assert.Len(t, split, 1)

	if diff := cmp.Diff(emptyUnifiedModelEvent, split[0], protocmp.Transform()); diff != "" {
		t.Errorf("SplitEmptyApplicationModelEvent() mismatch (-want +got):\n%s", diff)
	}
}

func TestMergeEmptyApplicationModelEvent(t *testing.T) {

	merged, err := MergeApplicationModelEvents([]*appModelV1.ApplicationModelEvent{emptyUnifiedModelEvent})
	assert.Nil(t, err)

	if diff := cmp.Diff(emptyUnifiedModelEvent, merged, protocmp.Transform()); diff != "" {
		t.Errorf("MergeApplicationModelEvent() mismatch (-want +got):\n%s", diff)
	}
}

func TestMergeApplicationModelEventsEmptyArray(t *testing.T) {

	_, err := MergeApplicationModelEvents([]*appModelV1.ApplicationModelEvent{})
	assert.EqualError(t, err, "models must be non-empty")
}

func TestMergeApplicationModelEventsNoAppModel(t *testing.T) {

	split := []*appModelV1.ApplicationModelEvent{
		{
			ClusterName: "test-cluster",
		},
	}
	_, err := MergeApplicationModelEvents(split)
	assert.EqualError(t, err, "nil ApplicationModel")
}

func TestMergeApplicationModelEventsEmptyAppModelId(t *testing.T) {

	split := []*appModelV1.ApplicationModelEvent{
		{
			ClusterName: "test-cluster",
			ApplicationModel: &appModelV1.ApplicationModel{
				Id: "",
			},
		},
	}
	_, err := MergeApplicationModelEvents(split)
	assert.EqualError(t, err, "empty ApplicationModel.Id")
}

func TestMergeApplicationModelEventsMismatchAppModelIds(t *testing.T) {

	split := []*appModelV1.ApplicationModelEvent{
		{
			ClusterName: "test-cluster",
			ApplicationModel: &appModelV1.ApplicationModel{
				Id: "Id1",
			},
		},
		{
			ClusterName: "test-cluster",
			ApplicationModel: &appModelV1.ApplicationModel{
				Id: "Id2",
			},
		},
	}
	_, err := MergeApplicationModelEvents(split)
	assert.EqualError(t, err, "mismatched ApplicationModel ids")
}
