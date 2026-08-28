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
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/bpf"

	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/harness"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/model"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/testcase"
	modelutils "github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/utils"
	modelserver "github.com/isovalent/hubble-fgs/pkg/model/server"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/netpol"
)

// dropSubsetPort is the listener the datagram goes to. The rule is programmed
// against dropSubsetRulePort, so no row the traffic produces matches it and the
// traffic takes the default action instead.
const (
	dropSubsetPort     = 9992
	dropSubsetRulePort = 1
)

// dropSubsetDenyPolicy denies by default and carries a rule that matches
// nothing, so traffic reaches send() and recv() with TNP_POLICY_FALLTHRU set.
// Formatted with the sender's binary path.
const dropSubsetDenyPolicy = `
apiVersion: cilium.io/v1alpha1
kind: TetragonNetworkPolicy
metadata:
  name: "modeltest-dropsubset-deny"
spec:
  processSelector:
    operator: "In"
    values:
      - %q
  defaultAction: "deny"
  rules:
  - description: "unrelatedRule"
    hook: "connect"
    action: "allow"
    destination:
    - ipBlock:
        cidr: "127.0.0.1/32"
      ports:
        protocol: "TCP"
        ports: [%d]
`

// checkDropSubsetCounters asserts the drop-policy-subset CEL rules ipa declares
// on EdgeTypeNetworkTelemetry: no row may charge more default-action drops than
// drops, in either direction (deny_default_packets <= tx_drop_packets and
// rx_default_drop_packets <= rx_drop_packets).
//
// The regression this guards is recv() charging deny_default, a transmit-side
// field, on a receive drop. The sender and receiver are separate sockets, so the
// ingress path keys the receiver's row on the sender's source port and the two
// directions land on separate rows. A receive-only row that charges deny_default
// reports a transmit policy drop against a transmit total of zero, breaking the
// transmit subset.
func checkDropSubsetCounters(ctx context.Context, tb testing.TB, tc *testcase.TestCase, _ *modelserver.Server, _ *harness.Harness) {
	sink := startDatagramSink(tb)

	// The policy has to be in place before any traffic flows, so the whole
	// scenario runs as a step rather than via tc.Host.
	sender := modelutils.FixupBinaryPathname("nc")
	np, err := netpol.FromYAML(fmt.Sprintf(dropSubsetDenyPolicy, sender, dropSubsetRulePort))
	require.NoError(tb, err, "failed to parse deny policy")
	require.NoError(tb, netpol.Add(np), "failed to add deny policy")
	// Registered first so it runs last, after the removal below.
	releaseLeakedBinaryUIDs(tb, np.Spec.ProcessSelector.Values...)
	tb.Cleanup(func() { netpol.Delete(np) })

	// UDP enforcement is observability-only, so the datagram lands even though
	// the verdict is a drop. nc exits on its own -w timeout.
	require.NoError(tb, tc.RunSingleBinary(ctx, model.Binary{
		Cmd:             "nc",
		Args:            []string{"-4", "-u", "-w1", "127.0.0.1", fmt.Sprint(dropSubsetPort)},
		Stdin:           "drop-subset\n",
		Timeout:         10 * time.Second,
		TimeoutExpected: true,
	}))

	select {
	case <-sink:
	case <-time.After(5 * time.Second):
		tb.Fatal("the datagram never reached the listener")
	}
	time.Sleep(100 * time.Millisecond)

	destMap := filepath.Join(bpf.MapPrefixPath(), "destination_endpoint_map")
	m, err := ebpf.LoadPinnedMap(destMap, nil)
	require.NoError(tb, err, "opening destination_endpoint_map")
	defer m.Close()

	// The receiver's peer port is the sender's ephemeral source port, which this
	// case cannot predict, so no key names the receiver's row and we walk every
	// row instead. rx_bytes on the receiver's row proves recv() ran, so the
	// invariant below is not asserted against an empty map.
	var (
		k          types.DestinationEndpointKey
		v          types.DestinationEndpointValue
		received   bool
		violations []string
	)
	iter := m.Iterate()
	for iter.Next(&k, &v) {
		if v.RxBytes > 0 {
			received = true
		}
		if v.DenyDefaultPackets > v.TxDropPackets {
			violations = append(violations, fmt.Sprintf(
				"%v charges %d transmit default-action drops against %d transmit drops",
				k, v.DenyDefaultPackets, v.TxDropPackets))
		}
		if v.RxDefaultDropPackets > v.RxDropPackets {
			violations = append(violations, fmt.Sprintf(
				"%v charges %d receive default-action drops against %d receive drops",
				k, v.RxDefaultDropPackets, v.RxDropPackets))
		}
	}
	require.NoError(tb, iter.Err(), "iterating destination_endpoint_map")
	require.True(tb, received, "expected recv() to charge the received datagram")
	for _, violation := range violations {
		tb.Error(violation)
	}
}

// startDatagramSink binds the listener before the policy loads and closes the
// returned channel once a datagram arrives.
func startDatagramSink(tb testing.TB) <-chan struct{} {
	tb.Helper()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: dropSubsetPort,
	})
	require.NoError(tb, err, "binding the datagram sink")
	tb.Cleanup(func() { conn.Close() })

	got := make(chan struct{})
	go func() {
		defer close(got)
		buf := make([]byte, 64)
		if _, _, err := conn.ReadFrom(buf); err != nil {
			return
		}
	}()
	return got
}
