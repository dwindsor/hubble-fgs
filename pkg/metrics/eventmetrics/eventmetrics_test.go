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

package eventmetrics_test

import (
	"strings"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/api/processapi"
	ossEventMetrics "github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/interfacemetrics"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func Test_eventHandleProcessedEvent(t *testing.T) {
	assert.NoError(t, testutil.CollectAndCompare(ossEventMetrics.EventsProcessed, strings.NewReader("")))
	eventmetrics.HandleProcessedEvent(nil)
	// empty process
	eventmetrics.HandleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessConnect{ProcessConnect: &tetragon.ProcessConnect{}}})
	eventmetrics.HandleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExec{ProcessExec: &tetragon.ProcessExec{}}})
	eventmetrics.HandleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessListen{ProcessListen: &tetragon.ProcessListen{}}})
	eventmetrics.HandleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_Tls{Tls: &tetragon.Tls{}}})
	eventmetrics.HandleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExit{ProcessExit: &tetragon.ProcessExit{}}})

	// empty pod
	eventmetrics.HandleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessConnect{ProcessConnect: &tetragon.ProcessConnect{
		Process: &tetragon.Process{Binary: "binary_a"},
	}}})
	eventmetrics.HandleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExec{ProcessExec: &tetragon.ProcessExec{
		Process: &tetragon.Process{Binary: "binary_b"},
	}}})
	eventmetrics.HandleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessListen{ProcessListen: &tetragon.ProcessListen{
		Process: &tetragon.Process{Binary: "binary_c"},
	}}})
	eventmetrics.HandleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_Tls{Tls: &tetragon.Tls{
		Process: &tetragon.Process{Binary: "binary_d"},
	}}})
	eventmetrics.HandleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExit{ProcessExit: &tetragon.ProcessExit{
		Process: &tetragon.Process{Binary: "binary_e"},
	}}})

	// with pod
	eventmetrics.HandleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessConnect{ProcessConnect: &tetragon.ProcessConnect{
		Process: &tetragon.Process{
			Binary: "binary_a",
			Pod:    &tetragon.Pod{Namespace: "namespace_a", Name: "pod_a"},
		},
	}}})
	eventmetrics.HandleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExec{ProcessExec: &tetragon.ProcessExec{
		Process: &tetragon.Process{
			Binary: "binary_b",
			Pod:    &tetragon.Pod{Namespace: "namespace_b", Name: "pod_b"},
		},
	}}})
	eventmetrics.HandleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessListen{ProcessListen: &tetragon.ProcessListen{
		Process: &tetragon.Process{
			Binary: "binary_c",
			Pod:    &tetragon.Pod{Namespace: "namespace_c", Name: "pod_c"},
		},
	}}})
	eventmetrics.HandleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_Tls{Tls: &tetragon.Tls{
		Process: &tetragon.Process{
			Binary: "binary_d",
			Pod:    &tetragon.Pod{Namespace: "namespace_d", Name: "pod_d"},
		},
	}}})
	eventmetrics.HandleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExit{ProcessExit: &tetragon.ProcessExit{
		Process: &tetragon.Process{
			Binary: "binary_e",
			Pod:    &tetragon.Pod{Namespace: "namespace_e", Name: "pod_e"},
		},
	}}})

	expected := strings.NewReader(`# HELP tetragon_events_total The total number of Tetragon events
# TYPE tetragon_events_total counter
tetragon_events_total{binary="",namespace="",pod="",type="PROCESS_CONNECT"} 1
tetragon_events_total{binary="",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="",namespace="",pod="",type="PROCESS_EXIT"} 1
tetragon_events_total{binary="",namespace="",pod="",type="PROCESS_LISTEN"} 1
tetragon_events_total{binary="",namespace="",pod="",type="PROCESS_TLS"} 1
tetragon_events_total{binary="",namespace="",pod="",type="unknown"} 1
tetragon_events_total{binary="binary_a",namespace="",pod="",type="PROCESS_CONNECT"} 1
tetragon_events_total{binary="binary_a",namespace="namespace_a",pod="pod_a",type="PROCESS_CONNECT"} 1
tetragon_events_total{binary="binary_b",namespace="",pod="",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="binary_b",namespace="namespace_b",pod="pod_b",type="PROCESS_EXEC"} 1
tetragon_events_total{binary="binary_c",namespace="",pod="",type="PROCESS_LISTEN"} 1
tetragon_events_total{binary="binary_c",namespace="namespace_c",pod="pod_c",type="PROCESS_LISTEN"} 1
tetragon_events_total{binary="binary_d",namespace="",pod="",type="PROCESS_TLS"} 1
tetragon_events_total{binary="binary_d",namespace="namespace_d",pod="pod_d",type="PROCESS_TLS"} 1
tetragon_events_total{binary="binary_e",namespace="",pod="",type="PROCESS_EXIT"} 1
tetragon_events_total{binary="binary_e",namespace="namespace_e",pod="pod_e",type="PROCESS_EXIT"} 1
`)
	assert.NoError(t, testutil.CollectAndCompare(ossEventMetrics.EventsProcessed, expected))
}

func Test_handleOriginalEvent(t *testing.T) {
	eventmetrics.HandleOriginalEvent(nil)
	eventmetrics.HandleOriginalEvent(&processapi.MsgExecveEventUnix{})
	assert.NoError(t, testutil.CollectAndCompare(ossEventMetrics.FlagCount, strings.NewReader("")))
	eventmetrics.HandleOriginalEvent(&processapi.MsgExecveEventUnix{
		Process: processapi.MsgProcess{
			Flags: api.EventClone | api.EventExecve,
		},
	})
	expected := strings.NewReader(`# HELP tetragon_flags_total The total number of Tetragon flags. For internal use only.
# TYPE tetragon_flags_total counter
tetragon_flags_total{type="clone"} 1
tetragon_flags_total{type="execve"} 1
`)
	assert.NoError(t, testutil.CollectAndCompare(ossEventMetrics.FlagCount, expected))
}

func Test_handleInterfaceStatsEvent(t *testing.T) {
	eventmetrics.HandleInterfaceStatsEvent(&tetragon.InterfaceStats{
		InterfaceName:   "eth0",
		Netns:           "foobar",
		BytesSent:       1,
		BytesReceived:   2,
		PacketsSent:     3,
		PacketsReceived: 4,
		TxErrors:        5,
		RxErrors:        6,
		TxDrops:         7,
		RxDrops:         8,
	})

	expected := strings.NewReader(`# HELP tetragon_interface_txbytes Bytes sent per network interface
# TYPE tetragon_interface_txbytes gauge
tetragon_interface_txbytes{name="eth0", namespace="", pod=""} 1
`)
	assert.NoError(t, testutil.CollectAndCompare(interfacemetrics.InterfaceBytesSent, expected))

	expected = strings.NewReader(`# HELP tetragon_interface_rxbytes Bytes received per network interface
# TYPE tetragon_interface_rxbytes gauge
tetragon_interface_rxbytes{name="eth0",  namespace="", pod=""} 2
`)
	assert.NoError(t, testutil.CollectAndCompare(interfacemetrics.InterfaceBytesReceived, expected))

	expected = strings.NewReader(`# HELP tetragon_interface_txsegs Segments sent per network interface
# TYPE tetragon_interface_txsegs gauge
tetragon_interface_txsegs{name="eth0", namespace="", pod=""} 3
`)
	assert.NoError(t, testutil.CollectAndCompare(interfacemetrics.InterfaceSegmentsSent, expected))

	expected = strings.NewReader(`# HELP tetragon_interface_rxsegs Segments received per network interface
# TYPE tetragon_interface_rxsegs gauge
tetragon_interface_rxsegs{name="eth0", namespace="", pod=""} 4
`)
	assert.NoError(t, testutil.CollectAndCompare(interfacemetrics.InterfaceSegmentsReceived, expected))

	expected = strings.NewReader(`# HELP tetragon_interface_txerrors TX errors per network interface
# TYPE tetragon_interface_txerrors gauge
tetragon_interface_txerrors{name="eth0", namespace="", pod=""} 5
`)
	assert.NoError(t, testutil.CollectAndCompare(interfacemetrics.InterfaceTxErrors, expected))

	expected = strings.NewReader(`# HELP tetragon_interface_rxerrors RX errors per network interface
# TYPE tetragon_interface_rxerrors gauge
tetragon_interface_rxerrors{name="eth0", namespace="", pod=""} 6
`)
	assert.NoError(t, testutil.CollectAndCompare(interfacemetrics.InterfaceRxErrors, expected))

	expected = strings.NewReader(`# HELP tetragon_interface_txdrops TX drops per network interface
# TYPE tetragon_interface_txdrops gauge
tetragon_interface_txdrops{name="eth0", namespace="", pod=""} 7
`)
	assert.NoError(t, testutil.CollectAndCompare(interfacemetrics.InterfaceTxDrops, expected))

	expected = strings.NewReader(`# HELP tetragon_interface_rxdrops RX drops per network interface
# TYPE tetragon_interface_rxdrops gauge
tetragon_interface_rxdrops{name="eth0", namespace="", pod=""} 8
`)
	assert.NoError(t, testutil.CollectAndCompare(interfacemetrics.InterfaceRxDrops, expected))
}
