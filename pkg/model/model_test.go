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
