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
	"fmt"
	"net/http"
	"strings"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/api/v1/fgs/codegen/helpers"
	"github.com/isovalent/hubble-fgs/pkg/api/processapi"
	"github.com/isovalent/hubble-fgs/pkg/filters"
	readerdns "github.com/isovalent/hubble-fgs/pkg/reader/dns"
	"github.com/isovalent/hubble-fgs/pkg/reader/exec"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type ErrorType string

const (
	// Parent process was not found in the pid map for a process without the clone flag.
	NoParentNoClone ErrorType = "no_parent_no_clone"
	// Process not found on get() call.
	ProcessCacheMissOnGet ErrorType = "process_cache_miss_on_get"
	// Process evicted from the cache.
	ProcessCacheEvicted ErrorType = "process_cache_evicted"
	// Process not found on remove() call.
	ProcessCacheMissOnRemove ErrorType = "process_cache_miss_on_remove"
	// Missing event handler.
	UnhandledEvent ErrorType = "unhandled_event"
	// Event cache add network entry to cache.
	EventCacheNetworkCount ErrorType = "event_cache_network_count"
	// Event cache add process entry to cache.
	EventCacheProcessCount ErrorType = "event_cache_process_count"
	// Event cache podInfo retries failed.
	EventCachePodInfoRetryFailed ErrorType = "event_cache_podinfo_retry_failed"
	// Event cache endpoint retries failed.
	EventCacheEndpointRetryFailed ErrorType = "event_cache_endpoint_retry_failed"
	// Event cache failed to set process information for an event.
	EventCacheProcessInfoFailed ErrorType = "event_cache_process_info_failed"
	// There was an invalid entry in the pid map.
	PidMapInvalidEntry ErrorType = "pid_map_invalid_entry"
	// An entry was evicted from the pid map because the map was full.
	PidMapEvicted ErrorType = "pid_map_evicted"
	// PID not found in the pid map on remove() call.
	PidMapMissOnRemove ErrorType = "pid_map_miss_on_remove"
	// MetricNamePrefix defines the prefix for Prometheus metrics.
	MetricNamePrefix string = "isovalent_"

	tlsVersion1_0 = "TLS1.0"
	tlsVersion1_1 = "TLS1.1"
	tlsVersion1_2 = "TLS1.2"
)

// TCP socket metrics
var (
	SocketStatsTxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_txbytes",
		Help: "TCP socket TX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsTxSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_txsegs",
		Help: "TCP socket TX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsTxBursts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_txbursts",
		Help: "TCP socket TX bursts statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsRxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_rxbytes",
		Help: "TCP socket RX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsRxSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_rxsegs",
		Help: "TCP socket RX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsRxBursts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_rxbursts",
		Help: "TCP socket RX bursts statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsRetranBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_retransmitbytes",
		Help: "TCP socket retransmit bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsRetranSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_retransmitsegs",
		Help: "TCP socket retransmit seg statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsZeroWindow = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_zerowindow",
		Help: "TCP socket zero window events",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsSrtt = promauto.NewSummaryVec(prometheus.SummaryOpts{
		Name:       MetricNamePrefix + "socket_stats_srtt",
		Help:       "TCP socket smoothed RTT latency distribution.",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsDrops = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_drops",
		Help: "TCP socket socket drops statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
)

// UDP socket metrics
var (
	SocketStatsUDPTxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_udp_txbytes",
		Help: "UDP socket TX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPTxSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_udp_txsegs",
		Help: "UDP socket TX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPTxBursts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_udp_txbursts",
		Help: "UDP socket TX bursts statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsUDPRxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_udp_rxbytes",
		Help: "UDP socket RX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPRxSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_udp_rxsegs",
		Help: "UDP socket RX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPRxBursts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_udp_rxbursts",
		Help: "UDP socket RX bursts statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsUDPDrops = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_udp_drops",
		Help: "UDP socket drops statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPConsumeMisses = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_udp_consume_misses",
		Help: "UDP socket consume packet misses",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPStackTxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_udp_stack_txbytes",
		Help: "UDP stack TX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPStackTxSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_udp_stack_txsegs",
		Help: "UDP stack TX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPStackRxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_udp_stack_rxbytes",
		Help: "UDP stack RX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPStackRxSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_udp_stack_rxsegs",
		Help: "UDP stack RX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
)

// HTTP metrics
var (
	HttpResponseTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "http_response_total",
		Help: "HTTP return code statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns", "host", "code"})
	HttpRequestDurationSeconds = promauto.NewSummaryVec(prometheus.SummaryOpts{
		Name:       MetricNamePrefix + "http_stats_latency",
		Help:       "HTTP latency statistics",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns", "host"})
)

// DNS metrics
var (
	DnsRequestTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "dns_total",
		Help: "Dns request/response statistics",
	}, []string{"namespace", "pod", "binary", "names", "rcodes", "response"})
)

// FGS debugging and core info metrics
var (
	MsgOpsCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        MetricNamePrefix + "msg_op_total",
		Help:        "The total number of times we encounter a given message opcode. For internal use only.",
		ConstLabels: nil,
	}, []string{"msg_op"})
	EventsProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        MetricNamePrefix + "events_total",
		Help:        "The total number of FGS events",
		ConstLabels: nil,
	}, []string{"type", "namespace", "pod", "binary"})
	FlagCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        MetricNamePrefix + "flags_total",
		Help:        "The total number of FGS flags. For internal use only.",
		ConstLabels: nil,
	}, []string{"type"})
	ErrorCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        MetricNamePrefix + "errors_total",
		Help:        "The total number of FGS errors. For internal use only.",
		ConstLabels: nil,
	}, []string{"type"})
	ExecveMapSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        MetricNamePrefix + "map_in_use_gauge",
		Help:        "The total number of in-use entries per map.",
		ConstLabels: nil,
	}, []string{"map", "total"})
	LruMapSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        MetricNamePrefix + "lru_in_use_gauge",
		Help:        "The total number of LRU in-use entries.",
		ConstLabels: nil,
	}, []string{"map", "total"})
	EventCacheCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        MetricNamePrefix + "event_cache",
		Help:        "The total number of FGS event cache access/errors. For internal use only.",
		ConstLabels: nil,
	}, []string{"type"})
	RingBufPerfEventReceived = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        MetricNamePrefix + "ringbuf_perf_event_received",
		Help:        "The total number of FGS ringbuf perf events received.",
		ConstLabels: nil,
	}, nil)
	RingBufPerfEventLost = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        MetricNamePrefix + "ringbuf_perf_event_lost",
		Help:        "The total number of FGS ringbuf perf events lost.",
		ConstLabels: nil,
	}, nil)
	RingBufPerfEventErrors = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        MetricNamePrefix + "ringbuf_perf_event_errors",
		Help:        "The total number of FGS ringbuf perf event error count.",
		ConstLabels: nil,
	}, nil)
	ProcessInfoErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        MetricNamePrefix + "process_info_errors",
		Help:        "The total of times we failed to fetch cached process info for a given event type.",
		ConstLabels: nil,
	}, []string{"event_type"})
)

// TLS metrics

var (
	TlsHandshakeTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "tls_handshakes_total",
		Help: "TLS handshake statistics",
	}, []string{"namespace", "pod", "binaray", "version", "cipher", "sni_name"})
)

// Interface metrics

var (
	InterfaceBytesSent = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: MetricNamePrefix + "interface_txbytes",
		Help: "Bytes sent per network interface",
	}, []string{"name", "netns"})
	InterfaceBytesReceived = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: MetricNamePrefix + "interface_rxbytes",
		Help: "Bytes received per network interface",
	}, []string{"name", "netns"})
	InterfaceSegmentsSent = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: MetricNamePrefix + "interface_txsegs",
		Help: "Segments sent per network interface",
	}, []string{"name", "netns"})
	InterfaceSegmentsReceived = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: MetricNamePrefix + "interface_rxsegs",
		Help: "Segments received per network interface",
	}, []string{"name", "netns"})
	InterfaceTxErrors = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: MetricNamePrefix + "interface_txerrors",
		Help: "TX errors per network interface",
	}, []string{"name", "netns"})
	InterfaceRxErrors = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: MetricNamePrefix + "interface_rxerrors",
		Help: "RX errors per network interface",
	}, []string{"name", "netns"})
	InterfaceTxDrops = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: MetricNamePrefix + "interface_txdrops",
		Help: "TX drops per network interface",
	}, []string{"name", "netns"})
	InterfaceRxDrops = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: MetricNamePrefix + "interface_rxdrops",
		Help: "RX drops per network interface",
	}, []string{"name", "netns"})
)

func getDstPodInfo(dstPod *fgs.Pod) (pod, ns string) {
	if dstPod != nil {
		ns = dstPod.Namespace
		pod = dstPod.Name
	}
	return pod, ns
}

func getProcessInfo(process *fgs.Process) (binary, pod, namespace string) {
	if process != nil {
		binary = process.Binary
		if process.Pod != nil {
			namespace = process.Pod.Namespace
			pod = process.Pod.Name
		}
	}
	return binary, pod, namespace
}

func handleOriginalEvent(originalEvent interface{}) {
	var flags uint32
	switch msg := originalEvent.(type) {
	case *processapi.MsgExecveEventUnix:
		flags = msg.Process.Flags
	}
	for _, flag := range exec.DecodeCommonFlags(flags) {
		FlagCount.WithLabelValues(flag).Inc()
	}
}

func postHttpStats(ev *fgs.GetEventsResponse, res *fgs.ProcessHttp) {
	binary, pod, ns := getProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))
	dstPod := res.GetDestinationPod()
	dstpod, dstns := getDstPodInfo(dstPod)
	dstLabels := strings.Join(res.Socket.DestinationNames, ",")

	http := res.Http
	code := fmt.Sprintf("%d", http.Response.Code)
	host := http.Request.Host

	// We may consider adding URI here as well, but without a configuration mechanism
	// to enable/disable it this could have poor scaling properties. Imagine a user
	// scanning for URIs behind a host.
	HttpResponseTotal.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels, host, code).Inc()

	c := float64(http.Latency.AsDuration().Seconds())
	HttpRequestDurationSeconds.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels, host).Observe(c)
}

func handleHttpEvent(processedEvent interface{}) {
	switch ev := processedEvent.(type) {
	case *fgs.GetEventsResponse:
		switch res := ev.Event.(type) {
		case *fgs.GetEventsResponse_ProcessHttp:
			postHttpStats(ev, res.ProcessHttp)
		}
	}
}

func postDnsMetric(ev *fgs.GetEventsResponse, res *fgs.ProcessDns) {
	var rr string

	binary, pod, ns := getProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))

	dns := res.Dns
	names := strings.Join(dns.GetNames(), ",")
	codes := readerdns.GetRCodeString(uint16(dns.GetRcode()))

	if dns.Response {
		rr = "Response"
	} else {
		rr = "Request"
	}

	DnsRequestTotal.WithLabelValues(ns, pod, binary, names, codes, rr).Inc()
}

func handleDnsEvent(processedEvent interface{}) {
	switch ev := processedEvent.(type) {
	case *fgs.GetEventsResponse:
		switch res := ev.Event.(type) {
		case *fgs.GetEventsResponse_ProcessDns:
			postDnsMetric(ev, res.ProcessDns)
		}
	}
}

func postUDPSocketStats(ns, pod, binary, dstns, dstpod, dstLabels string, s *fgs.SocketStats) {
	c := float64(s.BytesSubmitted)
	SocketStatsUDPTxBytes.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
	c = float64(s.SegsSubmitted)
	SocketStatsUDPTxSegs.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)

	c = float64(s.BytesConsumed)
	SocketStatsUDPRxBytes.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
	c = float64(s.SegsConsumed)
	SocketStatsUDPRxSegs.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)

	c = float64(s.BytesSent)
	SocketStatsUDPStackTxBytes.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
	c = float64(s.SegsOut)
	SocketStatsUDPStackTxSegs.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)

	c = float64(s.BytesReceived)
	SocketStatsUDPStackRxBytes.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
	c = float64(s.SegsIn)
	SocketStatsUDPStackRxSegs.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)

	c = float64(s.SkDrop)
	SocketStatsUDPDrops.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)

	c = float64(s.SkbConsumeMisses)
	SocketStatsUDPConsumeMisses.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
}

func postTCPSocketStats(ns, pod, binary, dstns, dstpod, dstLabels string, s *fgs.SocketStats) {
	c := float64(s.BytesSent)
	SocketStatsTxBytes.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
	c = float64(s.SegsOut)
	SocketStatsTxSegs.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)

	c = float64(s.BytesReceived)
	SocketStatsRxBytes.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
	c = float64(s.SegsIn)
	SocketStatsRxSegs.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)

	c = float64(s.RetransmitsBytes)
	SocketStatsRetranBytes.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
	c = float64(s.RetransmitsSegs)
	SocketStatsRetranSegs.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)

	c = float64(s.ToZeroWindow)
	SocketStatsZeroWindow.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)

	c = float64(s.Srtt)
	SocketStatsSrtt.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Observe(c)

	c = float64(s.SkDrop)
	SocketStatsDrops.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
}

func postStatsEventSocketStats(ev *fgs.GetEventsResponse, res *fgs.ProcessSockStats) {
	binary, pod, ns := getProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))
	dstPod := res.Socket.GetDestinationPod()
	dstpod, dstns := getDstPodInfo(dstPod)
	dstLabels := strings.Join(res.Socket.DestinationNames, ",")

	if res.Socket.Protocol == fgs.SocketProtocol_TCP {
		postTCPSocketStats(ns, pod, binary, dstns, dstpod, dstLabels, res.Stats)
	} else if res.Socket.Protocol == fgs.SocketProtocol_UDP {
		postUDPSocketStats(ns, pod, binary, dstns, dstpod, dstLabels, res.Stats)
	}
}

func postUDPBurstStats(ns, pod, binary string, s *fgs.ProcessNetworkBurst) {
	if s.Direction == "egress" {
		SocketStatsUDPTxBursts.WithLabelValues(ns, pod, binary).Inc()
	} else {
		SocketStatsUDPRxBursts.WithLabelValues(ns, pod, binary).Inc()
	}
}

func postTCPBurstStats(ns, pod, binary string, s *fgs.ProcessNetworkBurst) {
	if s.Direction == "egress" {
		SocketStatsTxBursts.WithLabelValues(ns, pod, binary).Inc()
	} else {
		SocketStatsRxBursts.WithLabelValues(ns, pod, binary).Inc()
	}
}

func postProcessNetworkBurstEventStats(ev *fgs.GetEventsResponse, res *fgs.ProcessNetworkBurst) {
	binary, pod, ns := getProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))
	if res.BurstState == "start" {
		switch res.Protocol {
		case fgs.SocketProtocol_UDP.String():
			postUDPBurstStats(ns, pod, binary, res)
		case fgs.SocketProtocol_TCP.String():
			postTCPBurstStats(ns, pod, binary, res)
		}
	}
}

func handleSocketEvent(processedEvent interface{}) {
	switch ev := processedEvent.(type) {
	case *fgs.GetEventsResponse:
		switch res := ev.Event.(type) {
		case *fgs.GetEventsResponse_ProcessSockStats:
			postStatsEventSocketStats(ev, res.ProcessSockStats)
		}
	}
}

func handleProcessBurstEvent(processedEvent interface{}) {
	switch ev := processedEvent.(type) {
	case *fgs.GetEventsResponse:
		switch res := ev.Event.(type) {
		case *fgs.GetEventsResponse_ProcessNetworkBurst:
			postProcessNetworkBurstEventStats(ev, res.ProcessNetworkBurst)
		}
	}
}

func handleProcessedEvent(processedEvent interface{}) {
	var eventType, namespace, pod, binary string
	switch ev := processedEvent.(type) {
	case *fgs.GetEventsResponse:
		binary, pod, namespace = getProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))
		var err error
		eventType, err = helpers.EventTypeString(ev.Event)
		if err != nil {
			logger.GetLogger().WithField("event", processedEvent).WithError(err).Warn("metrics: handleProcessedEvent: unhandled event")
			eventType = "unhandled"
		}
	default:
		eventType = "unknown"
	}
	EventsProcessed.WithLabelValues(eventType, namespace, pod, binary).Inc()
}

func getNegotiatedVersion12(tls *fgs.Tls) string {
	c := tls.ClientVersion
	s := tls.ServerVersion

	// TLS version degrade to lowest common protocol support, so
	// walk through TLS versions starting at lowest and working
	// up checking if either client or server indicate the version.
	// If c or s have an unknown protocol we report that to ensure
	// we don't make an incorrect assumption.
	if strings.Contains(c, "unknown") {
		return c
	} else if strings.Contains(s, "unknown") {
		return s
	} else if c == tlsVersion1_0 || s == tlsVersion1_0 {
		return tlsVersion1_0
	} else if c == tlsVersion1_1 || s == tlsVersion1_1 {
		return tlsVersion1_1
	} else if c == tlsVersion1_2 || s == tlsVersion1_2 {
		return tlsVersion1_2
	} else {
		// We should never get here if we do lets use the
		// code below and we can count it in metrics because
		// it is unique from grpc layers unknown(#) syntax.
		return "unknown(c|s)"
	}
}

func getNegotiatedVersion(tls *fgs.Tls) string {
	if tls.NegotiatedVersion != "" {
		// For TLS 1.3 the negotiated version field is set. Use it.
		return tls.NegotiatedVersion
	}
	// For <TLS 1.3 do version discovery
	return getNegotiatedVersion12(tls)
}

func handleTlsEvent(processedEvent interface{}) {
	switch ev := processedEvent.(type) {
	case *fgs.GetEventsResponse:
		switch res := ev.Event.(type) {
		case *fgs.GetEventsResponse_Tls:
			binary, pod, ns := getProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))
			version := getNegotiatedVersion(res.Tls)
			TlsHandshakeTotal.WithLabelValues(ns, pod, binary, version, res.Tls.Cipher, res.Tls.SniName).Inc()
		}
	}
}

func handleInterfaceStatsEvent(processedEvent interface{}) {
	switch ev := processedEvent.(type) {
	case *fgs.GetEventsResponse:
		switch res := ev.Event.(type) {
		case *fgs.GetEventsResponse_InterfaceStats:
			name := res.InterfaceStats.InterfaceName
			ns := res.InterfaceStats.Netns
			InterfaceBytesSent.WithLabelValues(name, ns).Set(float64(res.InterfaceStats.BytesSent))
			InterfaceBytesReceived.WithLabelValues(name, ns).Set(float64(res.InterfaceStats.BytesReceived))
			InterfaceSegmentsSent.WithLabelValues(name, ns).Set(float64(res.InterfaceStats.PacketsSent))
			InterfaceSegmentsReceived.WithLabelValues(name, ns).Set(float64(res.InterfaceStats.PacketsReceived))
			InterfaceTxErrors.WithLabelValues(name, ns).Set(float64(res.InterfaceStats.TxErrors))
			InterfaceRxErrors.WithLabelValues(name, ns).Set(float64(res.InterfaceStats.RxErrors))
			InterfaceTxDrops.WithLabelValues(name, ns).Set(float64(res.InterfaceStats.TxDrops))
			InterfaceRxDrops.WithLabelValues(name, ns).Set(float64(res.InterfaceStats.RxDrops))
		}
	}
}

func ProcessEvent(originalEvent interface{}, processedEvent interface{}) {
	handleOriginalEvent(originalEvent)
	handleProcessedEvent(processedEvent)
	handleSocketEvent(processedEvent)
	handleProcessBurstEvent(processedEvent)
	handleHttpEvent(processedEvent)
	handleDnsEvent(processedEvent)
	handleTlsEvent(processedEvent)
	handleInterfaceStatsEvent(processedEvent)
}

func EnableMetrics(address string) {
	logger.GetLogger().WithField("addr", address).Info("Starting metrics server")
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(address, nil)
}
