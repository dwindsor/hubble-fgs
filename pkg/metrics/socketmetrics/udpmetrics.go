//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package socketmetrics

import (
	"sync"

	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

// UDP socket metrics
var (
	SocketStatsUDPTxBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_txbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPTxSegs = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_txsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPTxBursts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_txbursts_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX bursts statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsUDPTxDips = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_txdips_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX dips statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsUDPRxBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_rxbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPRxSegs = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_rxsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPRxBursts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_rxbursts_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX bursts statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsUDPRxDips = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_rxdips_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX dips statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsUDPDrops = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_drops_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket drops statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPConsumeMisses = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_consume_misses_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket consume packet misses",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPStackTxBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_stack_txbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP stack TX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPStackTxSegs = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_stack_txsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP stack TX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPStackRxBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_stack_rxbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP stack RX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPStackRxSegs = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_stack_rxsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP stack RX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPTxWatermarksState = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "socket_stats_udp_tx_watermarks_state",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX watermarks state",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsUDPRxWatermarksState = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "socket_stats_udp_rx_watermarks_state",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX watermarks state",
	}, []string{"namespace", "pod", "binary"})
)

// UDP multicast socket metrics
var (
	SocketStatsUDPMulticastTxBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_txbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX bytes statistics",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	SocketStatsUDPMulticastTxSegs = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_txsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX segment statistics",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	SocketStatsUDPMulticastRxBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_rxbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX bytes statistics",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	SocketStatsUDPMulticastRxSegs = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_rxsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX segment statistics",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	SocketStatsUDPMulticastDrops = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_drops_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket drops statistics",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	SocketStatsUDPMulticastConsumeMisses = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_consume_misses_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket consume packet misses",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
)

// UDP metrics collection errors
var (
	SocketStatsUDPGC = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "socket_stats_udp_retrieve_total",
		Namespace:   consts.MetricsNamespace,
		Help:        "UDP socket retrieval stats. For internal use only.",
		ConstLabels: nil,
	}, []string{"count"})
)

// UDP Latency Histogram
// It emulates an OpenMetrics histogram:
//   - a set of "_bucket"-suffixed counters with a "le" label (less or equal), which is the upper
//     limit of the bucket
//   - a "_count" metric, identical to the highest ("+Inf") bucket metric
//   - a "_sum" metric, reporting the sum of all observed values
var (
	UdpLatencyBucket = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "udp_latency_microseconds_bucket",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram bucket for UDP socket latency in microseconds",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns", "le"})
	UdpLatencyCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "udp_latency_microseconds_count",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram count for UDP socket latency",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	UdpLatencySum = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "udp_latency_microseconds_sum",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram sum for UDP socket latency in microseconds",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
)

// UDP Multicast Latency Histogram
// It emulates an OpenMetrics histogram:
//   - a set of "_bucket"-suffixed counters with a "le" label (less or equal), which is the upper
//     limit of the bucket
//   - a "_count" metric, identical to the highest ("+Inf") bucket metric
//   - a "_sum" metric, reporting the sum of all observed values
var (
	UdpMulticastLatencyBucket = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "udp_mcast_latency_microseconds_bucket",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram bucket for UDP socket multicast latency in microseconds",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast", "le"})
	UdpMulticastLatencyCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "udp_mcast_latency_microseconds_count",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram count for UDP socket multicast latency",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	UdpMulticastLatencySum = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "udp_mcast_latency_microseconds_sum",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram sum for UDP socket multicast latency in microseconds",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
)

// UDP Sequence Check errors
var (
	SocketStatsUDPSeqCheckErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_sequence_check_errors_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket sequence check errors statistics",
	}, []string{"namespace", "pod", "binary"})
)

type UDPGCType int

const (
	UDPGCTypeTicker UDPGCType = iota
	UDPGCTypeFailedToOpenMap
	UDPGCTypeTotalRetrieve
	UDPGCTypePidIsZero
	UDPGCTypeNanoTimeSinceFailure
	UDPGCTypeDiffValuesFailure
	UDPGCTypeDiffValuesFailureGC
)

var UDPGCTypeStrings = map[UDPGCType]string{
	UDPGCTypeTicker:               "Ticker",
	UDPGCTypeFailedToOpenMap:      "Failed To Open Map",
	UDPGCTypeTotalRetrieve:        "Total Retrieved",
	UDPGCTypePidIsZero:            "Pid Is Zero",
	UDPGCTypeNanoTimeSinceFailure: "NanoTimeSince Failure",
	UDPGCTypeDiffValuesFailure:    "DiffValues Failure",
	UDPGCTypeDiffValuesFailureGC:  "DiffValues GC Failure",
}

var (
	statsUpdate sync.Mutex
)

// Increment a UDP GC metric for a retrieval type
func UDPGCMetricInc(ty UDPGCType) {
	statsUpdate.Lock()
	SocketStatsUDPGC.WithLabelValues(UDPGCTypeStrings[ty]).Inc()
	statsUpdate.Unlock()
}

func UDPGCMetricIncNoLock(ty UDPGCType) {
	SocketStatsUDPGC.WithLabelValues(UDPGCTypeStrings[ty]).Inc()
}
