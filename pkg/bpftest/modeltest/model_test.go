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
	"context"
	"strings"
	"testing"
	"time"

	commonNetV1 "github.com/isovalent/ipa/common/net/v1alpha"
	"github.com/stretchr/testify/require"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"

	modelserver "github.com/isovalent/hubble-fgs/pkg/model/server"

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

	"AdditionalHostProcesses": {
		Host: model.Binaries{
			{
				Cmd:  "/usr/bin/bash",
				Args: []string{"-c", "echo dog"},
			},
		},
		Steps: []func(ctx context.Context, tb testing.TB, tc *testcase.TestCase, server *modelserver.Server, harness *harness.Harness){
			func(ctx context.Context, tb testing.TB, tc *testcase.TestCase, _ *modelserver.Server, _ *harness.Harness) {
				// Start a new process after the initial model check
				tc.Host = append(tc.Host, model.Binary{
					Cmd:  "/usr/bin/bash",
					Args: []string{"-c", "echo cat"},
				})

				err := tc.RunSingleBinary(ctx, tc.Host[len(tc.Host)-1])
				require.NoError(tb, err, "failed to run additional host command")
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
						Names:    []string{"localhost."},
						Port:     model.UInt64Exactly(8080),
						Protocol: commonNetV1.IPProtocol_IP_PROTOCOL_TCP,
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
						Names:    []string{"localhost."},
						Port:     model.UInt64Exactly(9999),
						Protocol: commonNetV1.IPProtocol_IP_PROTOCOL_TCP,
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

	"UDPNetcatMessage": {
		Host: model.Binaries{
			// UDP netcat server
			{
				Cmd:             "nc",
				Args:            []string{"-4", "-u", "-l", "-p", "9998"},
				Timeout:         10 * time.Second,
				TimeoutExpected: true,
			},
			// UDP client
			{
				Cmd:  "nc",
				Args: []string{"-4", "-u", "-w1", "localhost", "9998"},
				Dependencies: []deps.Dependency{
					deps.NewUDPPortOpen(9998),
				},
				Stdin:           "hello udp",
				Timeout:         5 * time.Second,
				TimeoutExpected: true,
				ConnectionChecks: model.ConnectionChecks{
					&model.DNSConnectionCheck{
						Names:    []string{"localhost."},
						Port:     model.UInt64Exactly(9998),
						Protocol: commonNetV1.IPProtocol_IP_PROTOCOL_UDP,
						Stats:    model.StatsCheck{TxBytes: model.UInt64GreaterThan(0)},
					},
				},
			},
		},
	},

	"TCPAndUDPSamePort": {
		Host: model.Binaries{
			// TCP server on port 9997
			{
				Cmd:             "nc",
				Args:            []string{"-4", "-l", "-p", "9997"},
				Timeout:         10 * time.Second,
				TimeoutExpected: true,
			},
			// UDP server on port 9997
			{
				Cmd:             "nc",
				Args:            []string{"-4", "-u", "-l", "-p", "9997"},
				Timeout:         10 * time.Second,
				TimeoutExpected: true,
				Dependencies:    []deps.Dependency{deps.NewTCPPortOpen(9997)},
			},
			// TCP client
			{
				Cmd:  "nc",
				Args: []string{"-4", "localhost", "9997"},
				Dependencies: []deps.Dependency{
					deps.NewUDPPortOpen(9997),
				},
				Stdin:   "hello tcp",
				Timeout: 10 * time.Second,
				ConnectionChecks: model.ConnectionChecks{
					&model.DNSConnectionCheck{
						Names:    []string{"localhost."},
						Port:     model.UInt64Exactly(9997),
						Protocol: commonNetV1.IPProtocol_IP_PROTOCOL_TCP,
						Stats:    model.StatsCheck{TxBytes: model.UInt64GreaterThan(0)},
					},
				},
			},
			// UDP client
			{
				Cmd:  "nc",
				Args: []string{"-4", "-u", "-w1", "localhost", "9997"},
				Dependencies: []deps.Dependency{
					deps.NewUDPPortOpen(9997),
				},
				Stdin:           "hello udp",
				Timeout:         5 * time.Second,
				TimeoutExpected: true,
				ConnectionChecks: model.ConnectionChecks{
					&model.DNSConnectionCheck{
						Names:    []string{"localhost."},
						Port:     model.UInt64Exactly(9997),
						Protocol: commonNetV1.IPProtocol_IP_PROTOCOL_UDP,
						Stats:    model.StatsCheck{TxBytes: model.UInt64GreaterThan(0)},
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
