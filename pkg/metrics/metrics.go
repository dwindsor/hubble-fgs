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
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/filters"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/reader"
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
	// There was an invalid entry in the pid map.
	PidMapInvalidEntry ErrorType = "pid_map_invalid_entry"
	// An entry was evicted from the pid map because the map was full.
	PidMapEvicted ErrorType = "pid_map_evicted"
	// PID not found in the pid map on remove() call.
	PidMapMissOnRemove ErrorType = "pid_map_miss_on_remove"
	// MetricNamePrefix defines the prefix for Prometheus metrics.
	MetricNamePrefix string = "isovalent_"
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
	SocketStatsRxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_rxbytes",
		Help: "TCP socket RX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsRxSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_rxsegs",
		Help: "TCP socket RX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
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
	SocketStatsUDPRxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_udp_rxbytes",
		Help: "UDP socket RX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPRxSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricNamePrefix + "socket_stats_udp_rxsegs",
		Help: "UDP socket RX segment statistics",
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

// FGS debugging and core info metrics
var (
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
	case *api.MsgExecveEventUnix:
		flags = msg.Process.Flags
	}
	for _, flag := range reader.DecodeCommonFlags(flags) {
		FlagCount.WithLabelValues(flag).Inc()
	}
}

func postHttpStats(ev *fgs.GetEventsResponse, res *fgs.ProcessHttp) {
	binary, pod, ns := getProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))
	dstPod := res.GetDestinationPod()
	dstpod, dstns := getDstPodInfo(dstPod)
	dstLabels := strings.Join(res.DestinationNames, ",")

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

func postUDPSocketStats(ns, pod, binary, dstns, dstpod, dstLabels string, s *fgs.SocketStats) {
	c := float64(s.BytesSent)
	SocketStatsUDPTxBytes.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
	c = float64(s.SegsOut)
	SocketStatsUDPTxSegs.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)

	c = float64(s.BytesReceived)
	SocketStatsUDPRxBytes.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
	c = float64(s.SegsIn)
	SocketStatsUDPRxSegs.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
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
}

func postCloseEventSocketStats(ev *fgs.GetEventsResponse, res *fgs.ProcessClose, s *fgs.SocketStats) {
	binary, pod, ns := getProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))
	dstPod := res.GetDestinationPod()
	dstpod, dstns := getDstPodInfo(dstPod)
	dstLabels := strings.Join(res.DestinationNames, ",")

	if res.Protocol == fgs.SocketProtocol_TCP {
		postTCPSocketStats(ns, pod, binary, dstns, dstpod, dstLabels, s)
	} else if res.Protocol == fgs.SocketProtocol_UDP {
		postUDPSocketStats(ns, pod, binary, dstns, dstpod, dstLabels, s)
	}
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

func handleSocketEvent(processedEvent interface{}) {
	switch ev := processedEvent.(type) {
	case *fgs.GetEventsResponse:
		switch res := ev.Event.(type) {
		case *fgs.GetEventsResponse_ProcessClose:
			postCloseEventSocketStats(ev, res.ProcessClose, res.ProcessClose.Stats)
		case *fgs.GetEventsResponse_ProcessSockstats:
			postStatsEventSocketStats(ev, res.ProcessSockstats)
		}
	}
}

func handleProcessedEvent(processedEvent interface{}) {
	var eventType, namespace, pod, binary string
	switch ev := processedEvent.(type) {
	case *fgs.GetEventsResponse:
		binary, pod, namespace = getProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))
		switch ev.Event.(type) {
		case *fgs.GetEventsResponse_ProcessConnect:
			eventType = fgs.EventType_PROCESS_CONNECT.String()
		case *fgs.GetEventsResponse_ProcessClose:
			eventType = fgs.EventType_PROCESS_CLOSE.String()
		case *fgs.GetEventsResponse_ProcessExec:
			eventType = fgs.EventType_PROCESS_EXEC.String()
		case *fgs.GetEventsResponse_ProcessListen:
			eventType = fgs.EventType_PROCESS_LISTEN.String()
		case *fgs.GetEventsResponse_ProcessHttp:
			eventType = fgs.EventType_PROCESS_HTTP.String()
		case *fgs.GetEventsResponse_Tls:
			eventType = fgs.EventType_PROCESS_TLS.String()
		case *fgs.GetEventsResponse_ProcessExit:
			eventType = fgs.EventType_PROCESS_EXIT.String()
		case *fgs.GetEventsResponse_ProcessCred:
			eventType = fgs.EventType_PROCESS_CRED.String()
		case *fgs.GetEventsResponse_ProcessAccept:
			eventType = fgs.EventType_PROCESS_ACCEPT.String()
		case *fgs.GetEventsResponse_ProcessKprobe:
			eventType = fgs.EventType_PROCESS_KPROBE.String()
		case *fgs.GetEventsResponse_ProcessTracepoint:
			eventType = fgs.EventType_PROCESS_TRACEPOINT.String()
		case *fgs.GetEventsResponse_ProcessSockstats:
			eventType = fgs.EventType_PROCESS_SOCKSTATS.String()
		default:
			logger.GetLogger().WithField("event", processedEvent).Warn("metrics: handleProcessedEvent: unhandled event")
			eventType = "unhandled"
		}
	default:
		eventType = "unknown"
	}
	EventsProcessed.WithLabelValues(eventType, namespace, pod, binary).Inc()
}

func ProcessEvent(originalEvent interface{}, processedEvent interface{}) {
	handleOriginalEvent(originalEvent)
	handleProcessedEvent(processedEvent)
	handleSocketEvent(processedEvent)
	handleHttpEvent(processedEvent)
}

func EnableMetrics(address string) {
	logger.GetLogger().WithField("addr", address).Info("Starting metrics server")
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(address, nil)
}
