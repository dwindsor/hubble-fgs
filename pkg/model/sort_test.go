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

	"github.com/google/go-cmp/cmp"
	"github.com/isovalent/ipa/application_model/v1alpha"
	common "github.com/isovalent/ipa/common/k8s/type/v1alpha"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestEnsureSorted(t *testing.T) {
	model := &v1alpha.ApplicationModel{
		Namespaces: []*v1alpha.ApplicationNamespace{
			{
				Name: "b",
				Workloads: []*v1alpha.ApplicationWorkload{
					{
						Name: "bworkload",
						Kind: common.WorkloadKind_WORKLOAD_KIND_DAEMONSET,
						Containers: []*v1alpha.ApplicationContainer{
							{
								Id:    "b25790f3086f4",
								Name:  "my-other-middle-container",
								Image: "zzzdocker.io/library/someapp:latest",
								Processes: []*v1alpha.ApplicationProcessGroup{
									{
										Name: "/bin/fish",
									},
									{
										Name: "/bin/bash",
									},
								},
							},
							{
								Id:    "b25790f3086f4",
								Name:  "my-other-middle-container",
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
							{
								Id:    "b25790f3086f4",
								Name:  "my-middle-container",
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
							{
								Id:    "a25790f3086f4",
								Name:  "my-first-container",
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
					{
						Name: "aworkload",
						Kind: common.WorkloadKind_WORKLOAD_KIND_DAEMONSET,
						Containers: []*v1alpha.ApplicationContainer{
							{
								Id:    "e673699fa9961",
								Name:  "my-third-container",
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
				},
			},
			{Name: "a"},
			{Name: "c"},
		},
		Host: &v1alpha.ApplicationHost{
			Processes: []*v1alpha.ApplicationProcessGroup{
				{
					Name: "b",
				},
				{
					Name: "a",
					Connections: []*v1alpha.ApplicationConnection{
						{
							Destination: &v1alpha.Destination{
								Type: &v1alpha.Destination_Dns{
									Dns: &v1alpha.DestinationDns{
										DestinationNames: []string{"b.com"},
									},
								},
							},
						},
						{
							Destination: &v1alpha.Destination{
								Type: &v1alpha.Destination_Dns{
									Dns: &v1alpha.DestinationDns{
										DestinationNames: []string{"a.com"},
									},
								},
							},
						},
					},
				},
				{
					Name: "c",
				},
			},
		},
	}
	sortedModel := &v1alpha.ApplicationModel{
		Namespaces: []*v1alpha.ApplicationNamespace{
			{Name: "a"},
			{
				Name: "b",
				Workloads: []*v1alpha.ApplicationWorkload{
					{
						Name: "aworkload",
						Kind: common.WorkloadKind_WORKLOAD_KIND_DAEMONSET,
						Containers: []*v1alpha.ApplicationContainer{
							{
								Id:    "e673699fa9961",
								Name:  "my-third-container",
								Image: "docker.io/library/otherapp:latest",
								Processes: []*v1alpha.ApplicationProcessGroup{
									{
										Name: "/bin/bar",
									},
									{
										Name: "/bin/foo",
									},
								},
							},
						},
					},
					{
						Name: "bworkload",
						Kind: common.WorkloadKind_WORKLOAD_KIND_DAEMONSET,
						Containers: []*v1alpha.ApplicationContainer{
							{
								Id:    "a25790f3086f4",
								Name:  "my-first-container",
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
							{
								Id:    "b25790f3086f4",
								Name:  "my-middle-container",
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
							{
								Id:    "b25790f3086f4",
								Name:  "my-other-middle-container",
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
							{
								Id:    "b25790f3086f4",
								Name:  "my-other-middle-container",
								Image: "zzzdocker.io/library/someapp:latest",
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
				},
			},
			{Name: "c"},
		},
		Host: &v1alpha.ApplicationHost{
			Processes: []*v1alpha.ApplicationProcessGroup{
				{
					Name: "a",
					Connections: []*v1alpha.ApplicationConnection{
						{
							Destination: &v1alpha.Destination{
								Type: &v1alpha.Destination_Dns{
									Dns: &v1alpha.DestinationDns{
										DestinationNames: []string{"a.com"},
									},
								},
							},
						},
						{
							Destination: &v1alpha.Destination{
								Type: &v1alpha.Destination_Dns{
									Dns: &v1alpha.DestinationDns{
										DestinationNames: []string{"b.com"},
									},
								},
							},
						},
					},
				},
				{
					Name: "b",
				},
				{
					Name: "c",
				},
			},
		},
	}
	require.NotEmpty(t, cmp.Diff(model, sortedModel, protocmp.Transform()))
	EnsureSorted(model)
	assert.Empty(t, cmp.Diff(model, sortedModel, protocmp.Transform()))
}
