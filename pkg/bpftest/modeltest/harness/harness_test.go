// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package harness

import (
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/image"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/model"
)

func TestNewHarness(t *testing.T) {
	_ = New(t)
}

func TestAddPod(t *testing.T) {
	harness := New(t)
	harness.AddPod(t, "foo", "bar", model.Containers{
		"qux": {
			ImageSource: image.Pull("quay.io/isovalent/busybox:1.37.0", false),
		},
	})
}
