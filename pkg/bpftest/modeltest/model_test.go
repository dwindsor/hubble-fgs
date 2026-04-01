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
	"time"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"

	"github.com/isovalent/hubble-fgs/pkg/bpftest"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/deps"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/harness"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/image"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/model"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/testcase"
)

var tests map[string]testcase.TestCase = map[string]testcase.TestCase{
	"BasicModel": {
		Host: model.Binaries{
			{
				Cmd:  "/usr/bin/bash",
				Args: []string{"-c", "echo hello world"},
			},
		},
		Namespaces: model.Namespaces{
			"default": {
				"testificate": {
					Containers: model.Containers{
						"test-container": {
							ImageSource: image.Pull("quay.io/isovalent/busybox:1.37.0", true),
							Cmd: model.Binary{
								Cmd:  "/bin/sleep",
								Args: []string{"infinity"},
							},
						},
					},
				},
			},
		},
	},

	"MissingArgumentsRegression": {
		Host: model.Binaries{
			{
				Cmd:   "/usr/bin/ls",
				Args:  []string{},
				RunID: "ls-no-args",
			},
			{
				Cmd:  "/usr/bin/ls",
				Args: []string{"-la"},
				Dependencies: []deps.Dependency{
					deps.NewProcessStarted("ls-no-args"),
				},
			},
		},
	},

	"HTTPServerSimple": {
		Host: model.Binaries{
			// HTTP server process
			{
				Cmd:             "python3",
				Args:            []string{"-m", "http.server", "8080"},
				Timeout:         10 * time.Second,
				TimeoutExpected: true,
			},
			// Listener process that depends on port 8080 being open
			{
				Cmd:  "curl",
				Args: []string{"-4", "http://localhost:8080"},
				Dependencies: []deps.Dependency{
					deps.NewTCPPortOpen(8080),
				},
				Timeout: 10 * time.Second,
				ConnectionChecks: model.ConnectionChecks{
					&model.DNSConnectionCheck{
						Names: []string{"localhost."},
						Port:  model.UInt64Exactly(8080),
						Stats: model.StatsCheck{
							TxBytes: model.UInt64GreaterThan(0),
							RxBytes: model.UInt64GreaterThan(0),
							TxDrops: model.UInt64Exactly(0),
						},
					},
				},
			},
		},
	},

	"NetcatMessage": {
		Host: model.Binaries{
			// Netcat server listening on port 9999
			{
				Cmd:             "nc",
				Args:            []string{"-4", "-l", "-p", "9999"},
				Timeout:         10 * time.Second,
				TimeoutExpected: true,
			},
			// Client that sends a simple message to netcat
			{
				Cmd:  "nc",
				Args: []string{"-4", "localhost", "9999"},
				Dependencies: []deps.Dependency{
					deps.NewTCPPortOpen(9999),
				},
				Stdin:   "hello netcat",
				Timeout: 10 * time.Second,
				ConnectionChecks: model.ConnectionChecks{
					&model.DNSConnectionCheck{
						Names: []string{"localhost."},
						Port:  model.UInt64Exactly(9999),
						Stats: model.StatsCheck{
							// Exact lengths as reported
							TxBytes: model.UInt64GreaterThan(0),
							RxBytes: model.UInt64GreaterThan(0),
							TxDrops: model.UInt64Exactly(0),
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
