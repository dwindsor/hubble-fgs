// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build sudo_tests

package modeltest

import (
	"strings"
	"testing"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"

	"github.com/isovalent/hubble-fgs/pkg/bpftest"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/harness"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/image"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/model"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/testcase"
)

var tests map[string]testcase.TestCase = map[string]testcase.TestCase{
	"BasicModel": {
		Host: model.Binaries{
			{
				Cmd:  "bash",
				Args: []string{"-c", "echo hello world"},
			},
		},
		Namespaces: model.Namespaces{
			"default": {
				"testificate": {
					Containers: model.Containers{
						"test-container": {
							ImageSource: image.Pull("ubuntu:latest", true),
							Cmd: model.Binary{
								Cmd:  "sleep",
								Args: []string{"infinity"},
							},
						},
					},
				},
			},
		},
	},

	"LongArg": {
		Skip: "TODO: app model currently does not support args longer than 255",
		Host: model.Binaries{
			{
				Cmd:  "echo",
				Args: []string{strings.Repeat("a", 251)},
			},
			{
				Cmd:  "echo",
				Args: []string{strings.Repeat("b", 256)},
			},
		},
	},
}

func TestModel(t *testing.T) {
	if !utils.SupportProcessTree() {
		t.Skip()
	}

	server := bpftest.StartMinimalTetragonModel(t.Context(), t)
	harness := harness.New(t)

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tc.Run(t.Context(), t, server, &harness)
		})
	}
}
