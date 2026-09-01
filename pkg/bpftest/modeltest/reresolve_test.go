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
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/harness"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/testcase"
	modelutils "github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/utils"
	modelserver "github.com/isovalent/hubble-fgs/pkg/model/server"
	"github.com/isovalent/hubble-fgs/pkg/netpol"
)

// Denies the sender's egress to loopback. Added mid-connection, it exercises the
// re-resolve path. The socket cached an allow verdict at connect, and a CIDR rule
// never trips the identity rekey that would otherwise refresh it.
const reResolveDenyLoopback = `
apiVersion: cilium.io/v1alpha1
kind: TetragonNetworkPolicy
metadata:
  name: "modeltest-reresolve-deny"
spec:
  processSelector:
    operator: "In"
    values:
      - %q
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

const (
	// One phase's payload. Small enough to fit the loopback send buffer, so
	// sendall() returns without waiting for ACKs, which the deny path stops the
	// peer from ever sending.
	reResolvePhaseBytes = 4096
	// How long to wait for a phase-2 byte before concluding none will arrive. The
	// allow path delivers phase 1 in milliseconds, so a byte still missing after
	// this window was dropped, not delayed.
	reResolveDrainWindow = time.Second
)

// reResolveSendScript connects to the loopback sink, sends a run of 'A' bytes,
// waits on stdin until the test releases it, then sends a run of 'B' bytes. It
// waits on stdin rather than the socket because the deny also drops the socket's
// ingress, so a signal sent back over the connection would never arrive. Takes
// the phase byte count twice.
const reResolveSendScript = `import socket, sys
port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port))
s.sendall(b"A" * %d)
sys.stdin.readline()
try:
    s.settimeout(3)
    s.sendall(b"B" * %d)
except OSError:
    pass
`

// reResolveSink drains the one connection it accepts and counts the bytes of
// each phase. Phase 1 is all 'A' and phase 2 all 'B', so scanning bytes tells
// them apart however TCP coalesces them.
type reResolveSink struct {
	aBytes atomic.Int64
	bBytes atomic.Int64
}

// startReResolveSink listens on loopback and drains its one connection in the
// background, counting the bytes of each phase. It returns the port to dial.
func startReResolveSink(ctx context.Context, tb testing.TB) (int, *reResolveSink) {
	tb.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(tb, err, "listening for the re-resolve transfer")
	tb.Cleanup(func() { ln.Close() })

	sink := &reResolveSink{}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Once the policy is in place the sender's FIN is dropped with its data,
		// so Read never sees EOF. Close the conn at test end to unblock it.
		go func() {
			<-ctx.Done()
			conn.Close()
		}()

		buf := make([]byte, 65536)
		for {
			n, err := conn.Read(buf)
			for _, b := range buf[:n] {
				switch b {
				case 'A':
					sink.aBytes.Add(1)
				case 'B':
					sink.bBytes.Add(1)
				}
			}
			if err != nil {
				return
			}
		}
	}()

	return ln.Addr().(*net.TCPAddr).Port, sink
}

// checkPolicyReResolve proves a deny policy added mid-connection takes effect on
// an established socket. The sender streams phase 1 over an open connection, the
// deny lands, and phase 2 must not reach the sink.
//
// Without the re-resolve the socket keeps the allow verdict it cached at connect
// and phase 2 flows through, so this check fails when the fix is absent.
func checkPolicyReResolve(ctx context.Context, tb testing.TB, _ *testcase.TestCase, _ *modelserver.Server, _ *harness.Harness) {
	sender := modelutils.FixupBinaryPathname("python3")

	port, sink := startReResolveSink(ctx, tb)

	// Start the sender asynchronously so the policy can be added while it holds an
	// open connection. tc.RunSingleBinary's blocking run would not allow that.
	cmd := exec.CommandContext(ctx, "python3", "-c",
		fmt.Sprintf(reResolveSendScript, reResolvePhaseBytes, reResolvePhaseBytes),
		strconv.Itoa(port))
	stdin, err := cmd.StdinPipe()
	require.NoError(tb, err, "opening the sender's stdin")
	require.NoError(tb, cmd.Start(), "starting the sender")

	// Phase 1 flows before any policy exists, so delivering it confirms the
	// connection is live before the deny lands.
	require.Eventually(tb, func() bool {
		return sink.aBytes.Load() >= reResolvePhaseBytes
	}, 3*time.Second, 50*time.Millisecond, "phase-1 traffic never arrived; the allow path is broken")

	np, err := netpol.FromYAML(fmt.Sprintf(reResolveDenyLoopback, sender))
	require.NoError(tb, err, "failed to parse deny policy")
	require.NoError(tb, netpol.Add(np), "failed to add deny policy")
	// Registered first so it runs last, after the removal below.
	releaseLeakedBinaryUIDs(tb, np.Spec.ProcessSelector.Values...)
	tb.Cleanup(func() { netpol.Delete(np) })

	_, err = io.WriteString(stdin, "\n")
	require.NoError(tb, err, "releasing the sender's second phase")
	stdin.Close()

	require.NoError(tb, cmd.Wait(), "the sender exited with an error")

	// Give any phase-2 byte time to arrive before concluding none did.
	time.Sleep(reResolveDrainWindow)

	require.Positive(tb, sink.aBytes.Load(), "phase-1 traffic never arrived; the allow path is broken")
	require.Zero(tb, sink.bBytes.Load(),
		"phase-2 traffic arrived after the deny policy; the socket kept its cached allow verdict")
}
