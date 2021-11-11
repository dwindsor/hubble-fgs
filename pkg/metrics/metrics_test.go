// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metrics

import (
	"strings"
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/api"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func Test_handleProcessedEvent(t *testing.T) {
	assert.NoError(t, testutil.CollectAndCompare(EventsProcessed, strings.NewReader("")))
	handleProcessedEvent(nil)
	// empty process
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessConnect{ProcessConnect: &fgs.ProcessConnect{}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExec{ProcessExec: &fgs.ProcessExec{}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessListen{ProcessListen: &fgs.ProcessListen{}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_Tls{Tls: &fgs.Tls{}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExit{ProcessExit: &fgs.ProcessExit{}}})

	// empty pod
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessConnect{ProcessConnect: &fgs.ProcessConnect{
		Process: &fgs.Process{Binary: "binary_a"},
	}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExec{ProcessExec: &fgs.ProcessExec{
		Process: &fgs.Process{Binary: "binary_b"},
	}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessListen{ProcessListen: &fgs.ProcessListen{
		Process: &fgs.Process{Binary: "binary_c"},
	}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_Tls{Tls: &fgs.Tls{
		Process: &fgs.Process{Binary: "binary_d"},
	}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExit{ProcessExit: &fgs.ProcessExit{
		Process: &fgs.Process{Binary: "binary_e"},
	}}})

	// with pod
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessConnect{ProcessConnect: &fgs.ProcessConnect{
		Process: &fgs.Process{
			Binary: "binary_a",
			Pod:    &fgs.Pod{Namespace: "namespace_a", Name: "pod_a"},
		},
	}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExec{ProcessExec: &fgs.ProcessExec{
		Process: &fgs.Process{
			Binary: "binary_b",
			Pod:    &fgs.Pod{Namespace: "namespace_b", Name: "pod_b"},
		},
	}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessListen{ProcessListen: &fgs.ProcessListen{
		Process: &fgs.Process{
			Binary: "binary_c",
			Pod:    &fgs.Pod{Namespace: "namespace_c", Name: "pod_c"},
		},
	}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_Tls{Tls: &fgs.Tls{
		Process: &fgs.Process{
			Binary: "binary_d",
			Pod:    &fgs.Pod{Namespace: "namespace_d", Name: "pod_d"},
		},
	}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExit{ProcessExit: &fgs.ProcessExit{
		Process: &fgs.Process{
			Binary: "binary_e",
			Pod:    &fgs.Pod{Namespace: "namespace_e", Name: "pod_e"},
		},
	}}})

	expected := strings.NewReader(`# HELP isovalent_events_total The total number of FGS events
# TYPE isovalent_events_total counter
isovalent_events_total{binary="",namespace="",pod="",type="PROCESS_CONNECT"} 1
isovalent_events_total{binary="",namespace="",pod="",type="PROCESS_EXEC"} 1
isovalent_events_total{binary="",namespace="",pod="",type="PROCESS_EXIT"} 1
isovalent_events_total{binary="",namespace="",pod="",type="PROCESS_LISTEN"} 1
isovalent_events_total{binary="",namespace="",pod="",type="PROCESS_TLS"} 1
isovalent_events_total{binary="",namespace="",pod="",type="unknown"} 1
isovalent_events_total{binary="binary_a",namespace="",pod="",type="PROCESS_CONNECT"} 1
isovalent_events_total{binary="binary_a",namespace="namespace_a",pod="pod_a",type="PROCESS_CONNECT"} 1
isovalent_events_total{binary="binary_b",namespace="",pod="",type="PROCESS_EXEC"} 1
isovalent_events_total{binary="binary_b",namespace="namespace_b",pod="pod_b",type="PROCESS_EXEC"} 1
isovalent_events_total{binary="binary_c",namespace="",pod="",type="PROCESS_LISTEN"} 1
isovalent_events_total{binary="binary_c",namespace="namespace_c",pod="pod_c",type="PROCESS_LISTEN"} 1
isovalent_events_total{binary="binary_d",namespace="",pod="",type="PROCESS_TLS"} 1
isovalent_events_total{binary="binary_d",namespace="namespace_d",pod="pod_d",type="PROCESS_TLS"} 1
isovalent_events_total{binary="binary_e",namespace="",pod="",type="PROCESS_EXIT"} 1
isovalent_events_total{binary="binary_e",namespace="namespace_e",pod="pod_e",type="PROCESS_EXIT"} 1
`)
	assert.NoError(t, testutil.CollectAndCompare(EventsProcessed, expected))
}

func Test_handleOriginalEvent(t *testing.T) {
	handleOriginalEvent(nil)
	handleOriginalEvent(&api.MsgExecveEventUnix{})
	assert.NoError(t, testutil.CollectAndCompare(FlagCount, strings.NewReader("")))
	handleOriginalEvent(&api.MsgExecveEventUnix{
		Process: api.MsgExecUnix{
			Flags: api.EventClone | api.EventExecve,
		},
	})
	expected := strings.NewReader(`# HELP isovalent_flags_total The total number of FGS flags. For internal use only.
# TYPE isovalent_flags_total counter
isovalent_flags_total{type="clone"} 1
isovalent_flags_total{type="execve"} 1
`)
	assert.NoError(t, testutil.CollectAndCompare(FlagCount, expected))
}

func Test_getNegotiatedVersion(t *testing.T) {
	version := getNegotiatedVersion(&fgs.Tls{NegotiatedVersion: "hello"})
	assert.Equal(t, "hello", version)
	version = getNegotiatedVersion(&fgs.Tls{ClientVersion: "TLS 1.2", ServerVersion: "TLS 1.1"})
	assert.Equal(t, "TLS 1.1", version)
	version = getNegotiatedVersion(&fgs.Tls{ClientVersion: "TLS 1.1", ServerVersion: "TLS 1.2"})
	assert.Equal(t, "TLS 1.1", version)
	version = getNegotiatedVersion(&fgs.Tls{ClientVersion: "TLS 1.0", ServerVersion: "TLS 1.0"})
	assert.Equal(t, "TLS 1.0", version)
}

func Test_handleInterfaceStatsEvent(t *testing.T) {
	handleInterfaceStatsEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_InterfaceStats{InterfaceStats: &fgs.InterfaceStats{
		InterfaceName:   "eth0",
		BytesSent:       1,
		BytesReceived:   2,
		PacketsSent:     3,
		PacketsReceived: 4,
		TxErrors:        5,
		RxErrors:        6,
		TxDrops:         7,
		RxDrops:         8,
	}}})

	expected := strings.NewReader(`# HELP isovalent_interface_txbytes Bytes sent per network interface
# TYPE isovalent_interface_txbytes gauge
isovalent_interface_txbytes{name="eth0"} 1
`)
	assert.NoError(t, testutil.CollectAndCompare(InterfaceBytesSent, expected))

	expected = strings.NewReader(`# HELP isovalent_interface_rxbytes Bytes received per network interface
# TYPE isovalent_interface_rxbytes gauge
isovalent_interface_rxbytes{name="eth0"} 2
`)
	assert.NoError(t, testutil.CollectAndCompare(InterfaceBytesReceived, expected))

	expected = strings.NewReader(`# HELP isovalent_interface_txsegs Segments sent per network interface
# TYPE isovalent_interface_txsegs gauge
isovalent_interface_txsegs{name="eth0"} 3
`)
	assert.NoError(t, testutil.CollectAndCompare(InterfaceSegmentsSent, expected))

	expected = strings.NewReader(`# HELP isovalent_interface_rxsegs Segments received per network interface
# TYPE isovalent_interface_rxsegs gauge
isovalent_interface_rxsegs{name="eth0"} 4
`)
	assert.NoError(t, testutil.CollectAndCompare(InterfaceSegmentsReceived, expected))

	expected = strings.NewReader(`# HELP isovalent_interface_txerrors TX errors per network interface
# TYPE isovalent_interface_txerrors gauge
isovalent_interface_txerrors{name="eth0"} 5
`)
	assert.NoError(t, testutil.CollectAndCompare(InterfaceTxErrors, expected))

	expected = strings.NewReader(`# HELP isovalent_interface_rxerrors RX errors per network interface
# TYPE isovalent_interface_rxerrors gauge
isovalent_interface_rxerrors{name="eth0"} 6
`)
	assert.NoError(t, testutil.CollectAndCompare(InterfaceRxErrors, expected))

	expected = strings.NewReader(`# HELP isovalent_interface_txdrops TX drops per network interface
# TYPE isovalent_interface_txdrops gauge
isovalent_interface_txdrops{name="eth0"} 7
`)
	assert.NoError(t, testutil.CollectAndCompare(InterfaceTxDrops, expected))

	expected = strings.NewReader(`# HELP isovalent_interface_rxdrops RX drops per network interface
# TYPE isovalent_interface_rxdrops gauge
isovalent_interface_rxdrops{name="eth0"} 8
`)
	assert.NoError(t, testutil.CollectAndCompare(InterfaceRxDrops, expected))
}
