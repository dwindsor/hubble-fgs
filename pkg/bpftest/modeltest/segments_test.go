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
	"runtime"
	"testing"
	"time"
	"unsafe"

	commonNetV1 "github.com/isovalent/ipa/common/net/v1alpha"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/harness"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/model"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/testcase"
	modelutils "github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/utils"
	modelserver "github.com/isovalent/hubble-fgs/pkg/model/server"
	"github.com/isovalent/hubble-fgs/pkg/netpol"
)

const (
	// The bulk transfer runs at this MTU. At loopback's 65536 default every skb is
	// a single segment, so a per-skb count would pass without proving anything.
	segmentsMTU = 1500
	// Enough bytes that segmentation dominates the handshake and the ACKs.
	segmentsTransferBytes = 1 << 20
	// Allowed gap between the counted packets and the peer socket's segment total.
	// The two track closely. A 1 MiB transfer saw 764 packets against 761 segments,
	// and this slack covers the handshake and any ACKs in flight, well under the
	// error a per-skb count would produce.
	segmentsSlack = 8
)

// The transfer resolves to this policy's default rule and lands on the
// default-allow counters, which share the increment path with the drops. Allow
// rather than deny, because a denied connection never completes its handshake
// and so never carries a segment worth counting. The rule below is unreachable.
const segmentsAllowPolicy = `
apiVersion: cilium.io/v1alpha1
kind: TetragonNetworkPolicy
metadata:
  name: "modeltest-segments-allow"
spec:
  processSelector:
    operator: "In"
    values:
      - %q
  defaultAction: "allow"
  rules:
  - description: "unrelatedRule"
    hook: "connect"
    action: "allow"
    destination:
    - ipBlock:
        cidr: "127.0.0.1/32"
      ports:
        protocol: "TCP"
        ports: [1]
`

// segmentsSendScript pushes segmentsTransferBytes at a loopback listener, then
// waits for the listener to close back so the transfer has drained by the time
// the process exits. Formatted with the listener's port and the byte count.
const segmentsSendScript = `import socket
s = socket.create_connection(("127.0.0.1", %d))
s.sendall(b"x" * %d)
s.shutdown(socket.SHUT_WR)
s.recv(1)`

// checkSegmentPacketCounters drives a bulk transfer through real segmentation
// and asserts the packet counters count wire packets, not skbs.
//
// The egress hook runs upstream of the GSO split, so at a low MTU it sees
// aggregated skbs that each stand for many packets, and a per-skb count reports
// a mean packet size far above the MTU. The case forces GSO on for lo (restored
// on cleanup) so this holds whatever the host's ethtool defaults are. With GSO
// off one skb is one packet and the check proves nothing.
func checkSegmentPacketCounters(ctx context.Context, tb testing.TB, tc *testcase.TestCase, _ *modelserver.Server, _ *harness.Harness) {
	lo, err := netlink.LinkByName("lo")
	require.NoError(tb, err, "looking up the loopback device")

	origMTU := lo.Attrs().MTU
	tb.Cleanup(func() {
		require.NoError(tb, netlink.LinkSetMTU(lo, origMTU), "restoring the loopback MTU")
	})
	require.NoError(tb, netlink.LinkSetMTU(lo, segmentsMTU), "lowering the loopback MTU")

	// Force GSO on so the egress hook sees aggregated skbs. Restored on cleanup.
	prevGSO := loopbackGSOEnabled(tb)
	tb.Cleanup(func() { setLoopbackGSO(tb, prevGSO) })
	setLoopbackGSO(tb, true)
	tb.Logf("lo is at mtu %d advertising gso_max_size %d", segmentsMTU, lo.Attrs().GSOMaxSize)

	// The policy has to be in place before any traffic flows, so the whole
	// scenario runs as a step rather than via tc.Host.
	sender := modelutils.FixupBinaryPathname("python3")
	np, err := netpol.FromYAML(fmt.Sprintf(segmentsAllowPolicy, sender))
	require.NoError(tb, err, "failed to parse allow policy")
	require.NoError(tb, netpol.Add(np), "failed to add allow policy")
	// Registered first so it runs last, after the removal below.
	releaseLeakedBinaryUIDs(tb, np.Spec.ProcessSelector.Values...)
	tb.Cleanup(func() { netpol.Delete(np) })

	port, sink := startSegmentSink(tb)

	require.NoError(tb, tc.RunSingleBinary(ctx, model.Binary{
		Cmd:     "python3",
		Args:    []string{"-c", fmt.Sprintf(segmentsSendScript, port, segmentsTransferBytes)},
		Timeout: 30 * time.Second,
	}), "bulk transfer failed")

	result := <-sink
	require.NoError(tb, result.err, "draining the bulk transfer")
	tb.Logf("the peer socket was charged %d receive and %d transmit segments for %d bytes", result.segsIn, result.segsOut, segmentsTransferBytes)

	// Workaround for the empty-arguments bug
	// (https://github.com/isovalent/hubble-fgs/issues/8915): a process matched by a
	// processSelector reports empty arguments, so this check declares no Args.
	// Appending after the run means the entry is only matched, not run.
	tc.Host = append(tc.Host, model.Binary{
		Cmd: "python3",
		ConnectionChecks: model.ConnectionChecks{
			// Workaround for the duplicate-connection bug
			// (https://github.com/isovalent/hubble-fgs/issues/8916): the
			// destination shows up twice, as "localhost." and as a plain
			// IP, and one copy comes back zeroed. Here the DNS copy holds
			// the counters; the model_test.go drop case sees the IP copy
			// hold them instead. Check which copy carries the stats
			// rather than assuming DNS or IP.
			&model.DNSConnectionCheck{
				Names:    []string{"localhost."},
				Port:     model.UInt64Exactly(uint64(port)),
				Protocol: commonNetV1.IPProtocol_IP_PROTOCOL_TCP,
				Stats: model.StatsCheck{
					DefaultAllowBytes: model.UInt64GreaterThan(segmentsTransferBytes),
					// send() charges the transmit direction (the data the sink
					// received) and recv() the receive direction (the ACKs the
					// sink sent back), each on its own counter now.
					DefaultAllowPackets:   segmentPacketChecker(result.segsIn),
					RxDefaultAllowPackets: segmentPacketChecker(result.segsOut),
					// Nothing is dropped on the default-allow path.
					TxDropBytes:   model.UInt64Exactly(0),
					TxDropPackets: model.UInt64Exactly(0),
					RxDropBytes:   model.UInt64Exactly(0),
					RxDropPackets: model.UInt64Exactly(0),
				},
			},
		},
	})
}

// segmentPacketChecker requires a packet count within segmentsSlack of the peer
// socket's own segment count for one direction. Both sides count the same
// per-skb quantity send() and recv() charge, so the totals are comparable.
func segmentPacketChecker(peerSegs uint64) model.UInt64Checker {
	return func(packets uint64) error {
		diff := int64(packets) - int64(peerSegs)
		if diff < 0 {
			diff = -diff
		}
		if diff > segmentsSlack {
			return fmt.Errorf("%d packets disagrees with the %d segments the kernel charged the peer socket",
				packets, peerSegs)
		}
		return nil
	}
}

type segmentSinkResult struct {
	segsIn  uint64
	segsOut uint64
	err     error
}

// startSegmentSink listens on loopback, drains the one connection it accepts,
// and reports the segments the kernel charged that socket in both directions.
// Draining rather than reading a fixed count keeps the sender off a full window.
// The counters are sampled before the socket closes. Reading after would race
// the sender's last ACK and fold in the closing handshake.
func startSegmentSink(tb testing.TB) (int, <-chan segmentSinkResult) {
	tb.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(tb, err, "listening for the bulk transfer")
	tb.Cleanup(func() { ln.Close() })

	result := make(chan segmentSinkResult, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			result <- segmentSinkResult{err: fmt.Errorf("accept: %w", err)}
			return
		}
		defer conn.Close()

		if _, err := io.Copy(io.Discard, conn); err != nil {
			result <- segmentSinkResult{err: fmt.Errorf("read: %w", err)}
			return
		}

		segsIn, segsOut, err := socketSegments(conn.(*net.TCPConn))
		result <- segmentSinkResult{segsIn: segsIn, segsOut: segsOut, err: err}
	}()

	return ln.Addr().(*net.TCPAddr).Port, result
}

// socketSegments returns the number of segments the kernel charged conn in the
// receive and transmit directions.
func socketSegments(conn *net.TCPConn) (uint64, uint64, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}

	var info *unix.TCPInfo
	var getErr error
	if err := raw.Control(func(fd uintptr) {
		info, getErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); err != nil {
		return 0, 0, err
	}
	if getErr != nil {
		return 0, 0, fmt.Errorf("TCP_INFO: %w", getErr)
	}

	return uint64(info.Segs_in), uint64(info.Segs_out), nil
}

// ethtoolValue mirrors struct ethtool_value: a command word and one word of
// data, the payload the boolean feature ioctls read and write.
type ethtoolValue struct{ cmd, data uint32 }

// loopbackEthtool issues one ethtool_value ioctl against lo and returns the data
// word. x/sys/unix leaves the ifreq-carrying-a-pointer plumbing unexported, so
// this lays out the ifreq by hand: the interface name, then a pointer to the
// value in the ifr_data union.
func loopbackEthtool(tb testing.TB, cmd, data uint32) uint32 {
	tb.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	require.NoError(tb, err, "socket for the ethtool ioctl")
	defer unix.Close(fd)

	value := ethtoolValue{cmd: cmd, data: data}
	var ifr [unix.IFNAMSIZ + 8]byte
	copy(ifr[:unix.IFNAMSIZ], "lo")
	*(*uintptr)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = uintptr(unsafe.Pointer(&value))
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.SIOCETHTOOL), uintptr(unsafe.Pointer(&ifr[0])))
	runtime.KeepAlive(&value)
	if errno != 0 {
		tb.Fatalf("ethtool ioctl 0x%x on lo: %v", cmd, errno)
	}
	return value.data
}

// loopbackGSOEnabled reports whether generic segmentation offload is on for lo.
func loopbackGSOEnabled(tb testing.TB) bool {
	return loopbackEthtool(tb, unix.ETHTOOL_GGSO, 0) != 0
}

// setLoopbackGSO turns generic segmentation offload on lo on or off.
func setLoopbackGSO(tb testing.TB, on bool) {
	var data uint32
	if on {
		data = 1
	}
	loopbackEthtool(tb, unix.ETHTOOL_SGSO, data)
}
