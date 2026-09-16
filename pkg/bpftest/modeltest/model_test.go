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

	"github.com/isovalent/ipa/application_model/v1alpha"
	commonNetV1 "github.com/isovalent/ipa/common/net/v1alpha"
	"github.com/stretchr/testify/assert"
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
	modeldiff "github.com/isovalent/hubble-fgs/pkg/model/diff"
	"github.com/isovalent/hubble-fgs/pkg/netpol"
	"github.com/isovalent/hubble-fgs/pkg/node/local"

	corev1 "k8s.io/api/core/v1"
)

// Denies curl's egress to loopback so the transmit drop counters increment.
const curlDenyLoopback = `
apiVersion: cilium.io/v1alpha1
kind: TetragonNetworkPolicy
metadata:
  name: "modeltest-curl-deny"
spec:
  processSelector:
    operator: "In"
    values:
      - "/usr/bin/curl"
      - "/usr/sbin/curl"
  defaultAction: "deny"
  rules:
  - description: "connectDenyRule"
    hook: "connect"
    action: "deny"
    destination:
    - ipBlock:
        cidr: "127.0.0.1/32"
      ports:
        protocol: "TCP"
`

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
							TxBytes:       model.UInt64GreaterThan(0),
							RxBytes:       model.UInt64GreaterThan(0),
							TxDropBytes:   model.UInt64Exactly(0),
							TxDropPackets: model.UInt64Exactly(0),
							Sessions:      model.UInt64Exactly(1),
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
							TxBytes:       model.UInt64GreaterThan(0),
							RxBytes:       model.UInt64GreaterThan(0),
							TxDropBytes:   model.UInt64Exactly(0),
							TxDropPackets: model.UInt64Exactly(0),
							Sessions:      model.UInt64Exactly(3),
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
							TxBytes:       model.UInt64GreaterThan(0),
							RxBytes:       model.UInt64GreaterThan(0),
							TxDropBytes:   model.UInt64Exactly(0),
							TxDropPackets: model.UInt64Exactly(0),
							Sessions:      model.UInt64Exactly(1),
						},
					},
				},
			},
		},
	},

	// The no-drop cases above pin the drop counters to zero, which passes even
	// if nothing ever increments them. This case forces a policy drop so the
	// counters have to be wired to a live BPF map to come back nonzero.
	//
	// Loading a policy exposes two unrelated model bugs, worked around below.
	// The matched process is reported with empty arguments
	// (https://github.com/isovalent/hubble-fgs/issues/8915) and the connection
	// turns up a second time, zeroed
	// (https://github.com/isovalent/hubble-fgs/issues/8916). Revisit this case
	// when either is fixed.
	"PolicyDropPacketCounters": {
		Steps: []func(ctx context.Context, tb testing.TB, tc *testcase.TestCase, server *modelserver.Server, harness *harness.Harness){
			func(ctx context.Context, tb testing.TB, tc *testcase.TestCase, _ *modelserver.Server, _ *harness.Harness) {
				// The policy has to be in place before any traffic flows, so
				// the whole scenario runs as a step rather than via tc.Host.
				np, err := netpol.FromYAML(curlDenyLoopback)
				require.NoError(tb, err, "failed to parse deny policy")
				require.NoError(tb, netpol.Add(np), "failed to add deny policy")
				// Registered first so it runs last, after the removal below.
				releaseLeakedBinaryUIDs(tb, np.Spec.ProcessSelector.Values...)
				tb.Cleanup(func() { netpol.Delete(np) })

				// A denied connect() makes curl exit nonzero, so let the
				// binary fail without failing the test.
				_ = tc.RunSingleBinary(ctx, model.Binary{
					Cmd:             "curl",
					Args:            []string{"-4", "--connect-timeout", "1", "http://127.0.0.1:9996"},
					Timeout:         10 * time.Second,
					TimeoutExpected: true,
				})

				// Workaround for the empty-arguments bug
				// (https://github.com/isovalent/hubble-fgs/issues/8915): a
				// process matched by a processSelector reports empty
				// arguments, so this check declares no Args. Appending after
				// setup means the entry is only matched, not run.
				tc.Host = append(tc.Host, model.Binary{
					Cmd: "curl",
					ConnectionChecks: model.ConnectionChecks{
						// Workaround for the duplicate-connection bug
						// (https://github.com/isovalent/hubble-fgs/issues/8916):
						// this destination shows up twice, as "localhost." and
						// as a plain IP, and one copy comes back zeroed. Here
						// the IP copy holds the counters; the segments_test.go
						// case sees the DNS copy hold them instead. Check which
						// copy carries the stats rather than assuming DNS or IP.
						&model.IPConnectionCheck{
							CIDR:     "127.0.0.1/32",
							Port:     model.UInt64Exactly(9996),
							Protocol: commonNetV1.IPProtocol_IP_PROTOCOL_TCP,
							Stats: model.StatsCheck{
								// Only send() charges the transmit counters, and
								// the connection never gets past the SYN, so the
								// receive side stays empty.
								TxDropBytes: model.UInt64GreaterThan(0),
								// The kernel may retransmit the SYN within curl's
								// timeout, so the count is not exact. What matters
								// is the unit: a few packets, against the tens of
								// bytes each SYN adds.
								TxDropPackets: model.UInt64Between(1, 5),
							},
						},
					},
				})
			},
		},
	},

	// The policy-drop case above bumps the packet counters one at a time; a dropped
	// SYN is one packet however it is counted. This case pushes bulk data through
	// real segmentation, where per-skb and per-packet counts diverge. It runs as a
	// step because the setup must precede traffic and the check compares against a
	// runtime segment count. See checkSegmentPacketCounters.
	"SegmentPacketCounters": {
		Steps: []func(ctx context.Context, tb testing.TB, tc *testcase.TestCase, server *modelserver.Server, harness *harness.Harness){
			checkSegmentPacketCounters,
		},
	},

	// A socket resolves its verdict once at connect and the fast paths reuse it,
	// so a policy added mid-connection takes effect only if it forces a
	// re-resolve. See checkPolicyReResolve.
	"PolicyReResolveMidConnection": {
		Steps: []func(ctx context.Context, tb testing.TB, tc *testcase.TestCase, server *modelserver.Server, harness *harness.Harness){
			checkPolicyReResolve,
		},
	},

	// Mirror of the case above: a deny removed mid-connection must re-resolve an
	// established socket back to allow. See checkPolicyReResolveOnRemoval.
	"PolicyReResolveOnRemoval": {
		Steps: []func(ctx context.Context, tb testing.TB, tc *testcase.TestCase, server *modelserver.Server, harness *harness.Harness){
			checkPolicyReResolveOnRemoval,
		},
	},

	// A denied UDP flow reaches recv() with the fallthrough deny set. recv() must
	// route its drop onto the receive counters, never the transmit-side
	// tx_default_drop, so the receiver's row cannot break the transmit drop subset.
	// The graph edge declares that subset as a protovalidate CEL constraint
	// (network_transmit_drop_policy_subset), so a row that charges more policy
	// drops than drops is rejected before it reaches the graph.
	"DropSubsetCounters": {
		Steps: []func(ctx context.Context, tb testing.TB, tc *testcase.TestCase, server *modelserver.Server, harness *harness.Harness){
			checkDropSubsetCounters,
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
			func(ctx context.Context, tb testing.TB, tc *testcase.TestCase, server *modelserver.Server, harness *harness.Harness) {
				// We exec into the pod and connect to the nc instance. This
				// will cause the nc container to exit and be restarted.
				stdout, stderr, err := harness.PodExec(ctx, "default", "restarting-nc", "nc-container", []string{"/bin/nc", "localhost", "9182", "-w", "1"}, 30*time.Second)
				// There's a potential race between the container exit and the exec, so allow
				if err != nil && err.Error() != "command terminated with exit code 137" {
					tb.Errorf("failed to execute pod command: err=%v, stdout=%s, stderr=%s", err, stdout, stderr)
				} else {
					// This is expected if the command was terminated with exit code 137
					tb.Logf("Pod exec command terminated with exit code 137, which is expected if the container was restarted: stdout=%s, stderr=%s", stdout, stderr)
				}

				harness.WaitForContainerRestart(ctx, tb, "default", "restarting-nc", "nc-container", 30*time.Second)

				// The application model must have 2 nc-container containers.
				// One for the restarted container, and one for the container
				// that is still running. We need to check for both in the
				// application model.
				model, err := server.GetModel(ctx, &v1alpha.GetModelRequest{
					Host: false,
				})
				require.NoError(tb, err, "failed to get model")

				amodel := model.GetModel().GetApplicationModel()

				foundRestarted := false
				foundRunning := false
				var containers []*v1alpha.ApplicationContainer

				for _, ns := range amodel.GetNamespaces() {
					if ns.Name == "default" {
						for _, wl := range ns.GetWorkloads() {
							if wl.Name == "restarting-nc" {
								containers = wl.GetContainers()
							}
						}
					}
				}

				require.NotNil(tb, containers, "failed to find restarting-nc workload in application model")
				assert.Equal(tb, 2, len(containers))

				for _, cont := range containers {
					for _, proc := range cont.GetProcesses() {
						if proc.GetName() == "/bin/nc" && proc.GetArguments() == "-l -p 9182" {
							if proc.GetExitCount() > 0 {
								foundRestarted = true
							} else {
								foundRunning = true
							}
						}
					}
				}

				assert.True(tb, foundRestarted, "did not find restarted nc container in application model")
				assert.True(tb, foundRunning, "did not find running nc container in application model")

				// Remove the workload from the testcase. We already validated
				// it here and model.Check() will fail depending on the order of
				// the containers in the model.
				delete(tc.Namespaces["default"], "restarting-nc")
			},
		},
	},

	"ResourceIdentityVertices": {
		Namespaces: model.Namespaces{
			"default": {
				"identity-source": {
					Containers: model.Containers{
						"source": {
							ImageSource: image.Pull("quay.io/isovalent/busybox:1.37.0", true),
							Cmd: model.Binary{
								Cmd:       "/bin/sleep",
								Args:      []string{"infinity"},
								LongLived: true,
							},
						},
					},
				},
				"identity-destination": {
					Containers: model.Containers{
						"destination": {
							ImageSource: image.Pull("quay.io/isovalent/busybox:1.37.0", true),
							Cmd: model.Binary{
								Cmd: "/bin/nc",
								// We use -lk with -e for persistent server so that it's long lived
								Args:      []string{"-lk", "-p", "9183", "-e", "/bin/cat"},
								LongLived: true,
							},
						},
					},
				},
			},
		},
		Steps: []func(ctx context.Context, tb testing.TB, tc *testcase.TestCase, server *modelserver.Server, harness *harness.Harness){
			func(ctx context.Context, tb testing.TB, _ *testcase.TestCase, server *modelserver.Server, harness *harness.Harness) {
				sourcePod := harness.GetPod(ctx, tb, "default", "identity-source")
				destinationPod := harness.GetPod(ctx, tb, "default", "identity-destination")

				_, _, err := harness.PodExec(ctx, "default", "identity-source", "source", []string{
					"/bin/nc", destinationPod.Status.PodIP, "9183", "-w", "1",
				}, 5*time.Second)
				require.NoError(tb, err)

				response, err := server.GetModel(ctx, &v1alpha.GetModelRequest{Host: false})
				require.NoError(tb, err)

				telemetry, err := modeldiff.ApplicationModelToNetworkFlat(
					ctx, response.GetModel().GetApplicationModel(), &local.NoopMetadataService{})
				require.NoError(tb, err)

				for _, event := range telemetry {
					if event.GetKubernetesWorkloadName() != sourcePod.Name ||
						event.GetDestinationKubernetesResourceName() != destinationPod.Name {
						continue
					}

					connection := modeldiff.TelemetryToConnection(event)
					require.NotNil(tb, connection, "expected telemetry to produce a graph connection")

					source := connection.GetSource().GetKubernetes()
					require.NotNil(tb, source, "expected a Kubernetes source vertex")
					assert.Equal(tb, string(sourcePod.UID), source.GetUid(), "source vertex UID should match the source Pod")

					destination := connection.GetDestination().GetKubernetes()
					require.NotNil(tb, destination, "expected a Kubernetes destination vertex")
					assert.Equal(tb, string(destinationPod.UID), destination.GetUid(), "destination vertex UID should match the destination Pod")
					return
				}

				require.Fail(tb, "Kubernetes connection not found", "expected a connection from %s to %s", sourcePod.Name, destinationPod.Name)
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
