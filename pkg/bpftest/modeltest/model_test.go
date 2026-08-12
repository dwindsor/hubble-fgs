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

	corev1 "k8s.io/api/core/v1"
)

var tests map[string]testcase.TestCase = map[string]testcase.TestCase{
	"BasicModel": {
		Host: model.Binaries{
			{
				Cmd:  "/usr/bin/bash",
				Args: []string{"-c", "echo hello basicmodel"},
			},
		},
		Namespaces: model.Namespaces{
			"default": {
				"testificate": {
					Containers: model.Containers{
						"test-container": {
							ImageSource: image.Pull("quay.io/isovalent/busybox:1.37.0", true),
							Cmd: model.Binary{
								Cmd:       "/bin/sleep",
								Args:      []string{"infinity"},
								LongLived: true,
							},
						},
					},
				},
			},
		},
	},

	"TestPodExec": {
		Namespaces: model.Namespaces{
			"default": {
				"exec-pod": {
					Containers: model.Containers{
						"exec-container": {
							ImageSource: image.Pull("quay.io/isovalent/busybox:1.37.0", true),
							Cmd: model.Binary{
								Cmd:       "/bin/sleep",
								Args:      []string{"infinity"},
								LongLived: true,
							},
						},
					},
				},
			},
		},
		Steps: []func(ctx context.Context, tb testing.TB, tc *testcase.TestCase, server *modelserver.Server, harness *harness.Harness){
			func(ctx context.Context, tb testing.TB, _ *testcase.TestCase, _ *modelserver.Server, harness *harness.Harness) {
				stdout, stderr, err := harness.PodExec(ctx, "default", "exec-pod", "exec-container", []string{"echo", "hello"}, 1*time.Minute)
				require.NoError(tb, err, "Could not exec into pod: %v\nstderr: %s\nstdout: %s", err, stderr, stdout)
				require.Equal(tb, "hello\n", stdout, "Unexpected stdout from pod exec")
			},
		},
	},

	"NotPresentHostBinary": {
		Host: model.Binaries{
			{
				Cmd:  "/usr/bin/bash",
				Args: []string{"-c", "echo some command"},
			},
		},
		NotInModel: model.NotPresent{
			Host: model.Binaries{
				{
					Cmd: "not-a-real-command",
				},
			},
		},
	},

	"NotPresentHostBinaryArgsMismatch": {
		Host: model.Binaries{
			{
				Cmd:  "/usr/bin/bash",
				Args: []string{"-c", "echo some other command"},
			},
		},
		NotInModel: model.NotPresent{
			Host: model.Binaries{
				{
					Cmd:  "/usr/bin/bash",
					Args: []string{"-c", "echo this command is not run"},
				},
			},
		},
	},

	"NotPresentNamespace": {
		Namespaces: model.Namespaces{
			"default": {
				"present-pod": {
					Containers: model.Containers{
						"present-container": {
							ImageSource: image.Pull("quay.io/isovalent/busybox:1.37.0", true),
							Cmd: model.Binary{
								Cmd:       "/bin/sleep",
								Args:      []string{"infinity"},
								LongLived: true,
							},
						},
					},
				},
			},
		},
		NotInModel: model.NotPresent{
			Namespaces: model.Namespaces{
				"not-a-real-namespace": {},
			},
		},
	},

	"NotPresentWorkload": {
		Namespaces: model.Namespaces{
			"default": {
				"present-pod-2": {
					Containers: model.Containers{
						"present-container": {
							ImageSource: image.Pull("quay.io/isovalent/busybox:1.37.0", true),
							Cmd: model.Binary{
								Cmd:       "/bin/sleep",
								Args:      []string{"infinity"},
								LongLived: true,
							},
						},
					},
				},
			},
		},
		NotInModel: model.NotPresent{
			Namespaces: model.Namespaces{
				"default": {
					"not-a-real-pod": {},
				},
			},
		},
	},

	"NotPresentContainer": {
		Namespaces: model.Namespaces{
			"default": {
				"present-pod-3": {
					Containers: model.Containers{
						"present-container": {
							ImageSource: image.Pull("quay.io/isovalent/busybox:1.37.0", true),
							Cmd: model.Binary{
								Cmd:       "/bin/sleep",
								Args:      []string{"infinity"},
								LongLived: true,
							},
						},
					},
				},
			},
		},
		NotInModel: model.NotPresent{
			Namespaces: model.Namespaces{
				"default": {
					"present-pod-3": {
						Containers: model.Containers{
							"not-a-real-container": {},
						},
					},
				},
			},
		},
	},

	"NotPresentContainerProcess": {
		Namespaces: model.Namespaces{
			"default": {
				"present-pod-4": {
					Containers: model.Containers{
						"present-container": {
							ImageSource: image.Pull("quay.io/isovalent/busybox:1.37.0", true),
							Cmd: model.Binary{
								Cmd:       "/bin/sleep",
								Args:      []string{"infinity"},
								LongLived: true,
							},
						},
					},
				},
			},
		},
		NotInModel: model.NotPresent{
			Namespaces: model.Namespaces{
				"default": {
					"present-pod-4": {
						Containers: model.Containers{
							"present-container": {
								ImageSource: image.Pull("quay.io/isovalent/busybox:1.37.0", true),
								Cmd: model.Binary{
									Cmd: "not-a-real-process",
								},
							},
						},
					},
				},
			},
		},
	},

	"NotPresentContainerProcessArgsMismatch": {
		Namespaces: model.Namespaces{
			"default": {
				"present-pod-5": {
					Containers: model.Containers{
						"present-container": {
							ImageSource: image.Pull("quay.io/isovalent/busybox:1.37.0", true),
							Cmd: model.Binary{
								Cmd:       "/bin/sleep",
								Args:      []string{"infinity"},
								LongLived: true,
							},
						},
					},
				},
			},
		},
		NotInModel: model.NotPresent{
			Namespaces: model.Namespaces{
				"default": {
					"present-pod-5": {
						Containers: model.Containers{
							"present-container": {
								ImageSource: image.Pull("quay.io/isovalent/busybox:1.37.0", true),
								Cmd: model.Binary{
									Cmd:  "/bin/sleep",
									Args: []string{"1"},
								},
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

	"LongLivedHostBinaries": {
		Host: model.Binaries{
			{
				Cmd:       "tail",
				Args:      []string{"-f", "/dev/null"},
				LongLived: true,
			},
			{
				Cmd:  "sleep",
				Args: []string{"1"},
				Dependencies: []deps.Dependency{
					deps.NewProcessRunningPatternMustCompile("tail -f /dev/null"),
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
						Names:    []string{"localhost."},
						Port:     model.UInt64Exactly(8080),
						Protocol: commonNetV1.IPProtocol_IP_PROTOCOL_TCP,
						Stats: model.StatsCheck{
							TxBytes:  model.UInt64GreaterThan(0),
							RxBytes:  model.UInt64GreaterThan(0),
							TxDrops:  model.UInt64Exactly(0),
							Sessions: model.UInt64Exactly(1),
						},
					},
				},
			},
		},
	},

	// python3's http.server speaks HTTP/1.0 and closes after each response, so
	// curl opens a separate connection per URL. They all land on the same
	// destination, which lets us check that the session counter accumulates
	// rather than just being set once.
	"HTTPServerRepeatConnections": {
		Host: model.Binaries{
			{
				Cmd:             "python3",
				Args:            []string{"-m", "http.server", "8081"},
				Timeout:         10 * time.Second,
				TimeoutExpected: true,
			},
			{
				Cmd:  "curl",
				Args: []string{"-4", "http://localhost:8081", "http://localhost:8081", "http://localhost:8081"},
				Dependencies: []deps.Dependency{
					deps.NewTCPPortOpen(8081),
				},
				Timeout: 10 * time.Second,
				ConnectionChecks: model.ConnectionChecks{
					&model.DNSConnectionCheck{
						Names:    []string{"localhost."},
						Port:     model.UInt64Exactly(8081),
						Protocol: commonNetV1.IPProtocol_IP_PROTOCOL_TCP,
						Stats: model.StatsCheck{
							TxBytes:  model.UInt64GreaterThan(0),
							RxBytes:  model.UInt64GreaterThan(0),
							TxDrops:  model.UInt64Exactly(0),
							Sessions: model.UInt64Exactly(3),
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
							TxBytes:  model.UInt64GreaterThan(0),
							RxBytes:  model.UInt64GreaterThan(0),
							TxDrops:  model.UInt64Exactly(0),
							Sessions: model.UInt64Exactly(1),
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
						Stats: model.StatsCheck{
							TxBytes:  model.UInt64GreaterThan(0),
							Sessions: model.UInt64Exactly(1),
						},
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
						Stats: model.StatsCheck{
							TxBytes:  model.UInt64GreaterThan(0),
							Sessions: model.UInt64Exactly(1),
						},
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
						Stats: model.StatsCheck{
							TxBytes:  model.UInt64GreaterThan(0),
							Sessions: model.UInt64Exactly(1),
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

	"GarbageCollectionHostProcesses": {
		Host: model.Binaries{
			{
				Cmd:  "/usr/bin/bash",
				Args: []string{"-c", "echo hello garbagecollectionhostprocesses"},
				Dependencies: []deps.Dependency{
					deps.NewProcessRunningPatternMustCompile("sleep infinity"),
				},
			},
			{
				Cmd:       "sleep",
				Args:      []string{"infinity"},
				LongLived: true,
			},
		},
		Namespaces: model.Namespaces{
			"default": {
				"test-garbage-collection-host-workloads": {
					Containers: model.Containers{
						"test-garbage-collection-host-workloads-container": {
							ImageSource: image.Pull("quay.io/isovalent/busybox:1.37.0", true),
							Cmd: model.Binary{
								Cmd:       "/bin/sleep",
								Args:      []string{"infinity"},
								LongLived: true,
							},
						},
					},
				},
			},
		},
		Steps: []func(ctx context.Context, tb testing.TB, tc *testcase.TestCase, server *modelserver.Server, harness *harness.Harness){
			func(_ context.Context, _ testing.TB, tc *testcase.TestCase, server *modelserver.Server, _ *harness.Harness) {
				// Set the server "now" to 96 hours in the future.
				server.TimeNow = func() time.Time {
					return time.Now().Add(96 * time.Hour)
				}

				// Remove the bash process. It should have been garbage collected.
				tc.Host = tc.Host[1:]

				// The bash process should be not present now. The container
				// will still be present.
				tc.NotInModel.Host = model.Binaries{
					{
						Cmd:  "/usr/bin/bash",
						Args: []string{"-c", "echo hello garbagecollectionhostprocesses"},
					},
				}
			},
		},
	},

	"GarbageCollectionWorkloads": {
		Namespaces: model.Namespaces{
			"default": {
				"short-lived-workload": {
					Containers: model.Containers{
						"short-lived-container": {
							ImageSource: image.Pull("quay.io/isovalent/busybox:1.37.0", true),
							Cmd: model.Binary{
								Cmd: "/bin/sleep",
								// Must outlive AddPod's cgroup scan, which can start up to
								// one PodReady poll interval (5s) after the container is
								// already gone. The step below waits for the exit.
								Args:               []string{"60"},
								SkipExecExitCounts: true, // There is a race between checking the model and the process exiting, so skip checking counts.
							},
						},
					},
				},
				"long-lived-workload": {
					Containers: model.Containers{
						"long-lived-container": {
							ImageSource: image.Pull("quay.io/isovalent/busybox:1.37.0", true),
							Cmd: model.Binary{
								Cmd:       "/bin/sleep",
								Args:      []string{"7200"},
								LongLived: true, // In the sense that it should be running through all model checks
							},
						},
					},
				},
				"killed-workload": {
					Containers: model.Containers{
						"killed-container": {
							ImageSource: image.Pull("quay.io/isovalent/busybox:1.37.0", true),
							Cmd: model.Binary{
								Cmd:       "/bin/sleep",
								Args:      []string{"infinity"},
								LongLived: true,
							},
						},
					},
				},
			},
		},
		Steps: []func(ctx context.Context, tb testing.TB, tc *testcase.TestCase, server *modelserver.Server, harness *harness.Harness){
			func(ctx context.Context, tb testing.TB, tc *testcase.TestCase, server *modelserver.Server, harness *harness.Harness) {
				harness.DeletePod(ctx, tb, "default", "killed-workload")

				harness.WaitForContainerExit(ctx, tb, "default", "short-lived-workload", "short-lived-container", 90*time.Second)
				harness.WaitForPodExit(ctx, tb, "default", "killed-workload", 90*time.Second)

				// Set the server "now" to 96 hours in the future.
				server.TimeNow = func() time.Time {
					return time.Now().Add(96 * time.Hour)
				}

				// Remove the deleted pods from the testcase
				delete(tc.Namespaces["default"], "short-lived-workload")
				delete(tc.Namespaces["default"], "killed-workload")

				// The workload should be not present now
				tc.NotInModel = model.NotPresent{
					Namespaces: model.Namespaces{
						"default": {
							"short-lived-workload": {},
							"killed-workload":      {},
						},
					},
				}
			},
		},
	},

	"TestContainerExitAndRestart": {
		Namespaces: model.Namespaces{
			"default": {
				"restarting-nc": {
					RestartPolicy: corev1.RestartPolicyAlways,
					Containers: model.Containers{
						"nc-container": {
							ImageSource: image.Pull("quay.io/isovalent/busybox:1.37.0", true),
							Cmd: model.Binary{
								Cmd:       "/bin/sh",
								Args:      []string{"-c", "/bin/nc -l -p 9182 < /dev/null"},
								LongLived: true,
							},
						},
					},
				},
			},
		},
		Steps: []func(ctx context.Context, tb testing.TB, tc *testcase.TestCase, server *modelserver.Server, harness *harness.Harness){
			func(ctx context.Context, tb testing.TB, tc *testcase.TestCase, _ *modelserver.Server, harness *harness.Harness) {
				// We exec into the pod and connect to the nc instance. This
				// will cause the nc container to exit and be restarted.
				_, stderr, err := harness.PodExec(ctx, "default", "restarting-nc", "nc-container", []string{"/bin/nc", "localhost", "9182", "-w", "1"}, 30*time.Second)
				require.NoError(tb, err, "failed to execute pod command: %s", stderr)

				harness.WaitForContainerRestart(ctx, tb, "default", "restarting-nc", "nc-container", 30*time.Second)

				// Remove the pod from the model so the harness doesn't try to
				// validate it. This is intentional. A later PR #8882 will
				// actually fix bugs in the app model server related to
				// restarting containers.
				delete(tc.Namespaces["default"], "restarting-nc")
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
			// Some tests modify the notion of "now", so reset to current time
			// after each test.
			server.TimeNow = time.Now
		})
	}
}
