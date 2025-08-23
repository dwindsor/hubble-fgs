//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package checker_test

import (
	"context"
	_ "embed"
	"testing"

	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	common "github.com/isovalent/ipa/common/k8s/type/v1alpha"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/isovalent/hubble-fgs/pkg/model/checker"
)

//go:embed testdata/model.json
var testModelJSON []byte

func TestGenerate(t *testing.T) {
	model := &appModelV1.ApplicationModelEvent{
		ClusterName: "foo",
		NodeName:    "foo-a5cf729e",
		Time: &timestamppb.Timestamp{
			Seconds: 13333337,
			Nanos:   123,
		},
		ApplicationModel: &appModelV1.ApplicationModel{
			Host: &appModelV1.ApplicationHost{
				Processes: []*appModelV1.ApplicationProcessGroup{
					{
						Name: "/bin/foobar",
					},
					{
						Name: "/bin/baz",
						Connections: []*appModelV1.ApplicationConnection{
							{
								Destination: &appModelV1.Destination{
									Type: &appModelV1.Destination_Dns{
										Dns: &appModelV1.DestinationDns{
											DestinationNames: []string{"isovalent.com"},
										},
									},
									Port: 443,
								},
								Stats: &appModelV1.ConnectionStats{
									TxBytes: 1337,
									RxBytes: 1337,
								},
							},
						},
					},
				},
			},
			Namespaces: []*appModelV1.ApplicationNamespace{
				{
					Name:      "ns1",
					Workloads: []*appModelV1.ApplicationWorkload{},
				},
				{
					Name: "ns2",
					Workloads: []*appModelV1.ApplicationWorkload{
						{
							Name: "quxbaz",
							Kind: common.WorkloadKind_WORKLOAD_KIND_DAEMONSET,
							Processes: []*appModelV1.ApplicationProcessGroup{
								{
									Name: "/bin/bash",
									Connections: []*appModelV1.ApplicationConnection{
										{
											Destination: &appModelV1.Destination{
												Type: &appModelV1.Destination_Dns{
													Dns: &appModelV1.DestinationDns{
														DestinationNames: []string{"isovalent.com"},
													},
												},
												Port: 443,
											},
											Stats: &appModelV1.ConnectionStats{
												TxBytes: 1337,
												RxBytes: 1337,
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

	chk, exprs, err := checker.GenerateChecker(model)
	require.NoError(t, err)

	res, err := chk.CheckApplicationModelEvent(context.Background(), model, exprs)
	require.NoError(t, err)
	assert.True(t, res.Ok())
}

func TestGenerateComplex(t *testing.T) {
	model := &appModelV1.ApplicationModelEvent{}
	err := protojson.Unmarshal(testModelJSON, model)
	require.NoError(t, err)

	chk, exprs, err := checker.GenerateChecker(model)
	require.NoError(t, err)

	res, err := chk.CheckApplicationModelEvent(context.Background(), model, exprs)
	require.NoError(t, err)
	assert.True(t, res.Ok())
}
