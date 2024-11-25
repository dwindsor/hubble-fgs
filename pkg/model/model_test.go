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

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/stretchr/testify/assert"
)

func TestMerge(t *testing.T) {
	m1 := tetragon.ApplicationModel{
		Namespaces: nil,
		Host: &tetragon.ApplicationHost{
			Processes: []*tetragon.ApplicationProcess{{Name: "curl"}},
		},
	}
	m2 := tetragon.ApplicationModel{
		Namespaces: nil,
		Host: &tetragon.ApplicationHost{
			Processes: []*tetragon.ApplicationProcess{{Name: "curl"}, {Name: "wget"}},
		},
	}
	res := Merge(&m1, &m2)
	merged, err := res.MarshalJSON()
	assert.NoError(t, err)
	expected := `{"host":{"processes":[{"name":"curl"},{"name":"wget"}]}}`
	assert.JSONEq(t, expected, string(merged))
}
