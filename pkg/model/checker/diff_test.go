//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package checker

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/isovalent/ipa/application_model/v1alpha"
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
					Kind: "DaemonSet",
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
					Name: "workload2",
					Kind: "DaemonSet",
					Processes: []*v1alpha.ApplicationProcessGroup{
						{
							Name: "/bin/foo",
						},
						{
							Name: "/bin/bar",
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
					Kind: "DaemonSet",
					Processes: []*v1alpha.ApplicationProcessGroup{
						{
							Name: "/bin/foo",
						},
						{
							Name: "/bin/bar",
						},
					},
				},
				{
					Name: "workload1",
					Kind: "DaemonSet",
					Processes: []*v1alpha.ApplicationProcessGroup{
						{
							Name: "/bin/fish",
						},
						{
							Name: "/bin/bash",
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
	b.ApplicationModel.Namespaces[2].Workloads[0].Processes[0].Name = "Foo"

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
						Processes: []*v1alpha.ApplicationProcessGroup{
							{
								Connections: []*v1alpha.ApplicationConnection{
									{
										DestinationName: "google.ca",
										BytesSent:       1337,
										BytesReceived:   1337,
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
						Processes: []*v1alpha.ApplicationProcessGroup{
							{
								Connections: []*v1alpha.ApplicationConnection{
									{
										DestinationName: "google.ca",
										BytesSent:       1338,
										BytesReceived:   1338,
									},
								},
							},
						},
					},
				},
			},
		}},
		IgnoreFields(
			"namespaces.workloads.processes.connections.bytes_sent",
			"namespaces.workloads.processes.connections.bytes_received",
			"namespaces.workloads.processes.children.connections.bytes_sent",
			"namespaces.workloads.processes.children.connections.bytes_received",
			"host.processes.connections.bytes_sent",
			"host.processes.connections.bytes_received",
			"host.processes.children.connections.bytes_sent",
			"host.processes.children.connections.bytes_received",
		),
	)
	fmt.Println(string(diff))
	require.NoError(t, err)
	assert.False(t, changed)
}
