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
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// UDP socket metrics
var (
	SocketStatsUDPTxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_txbytes",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPTxSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_txsegs",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPTxBursts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_txbursts",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX bursts statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsUDPTxDips = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_txdips",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX dips statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsUDPRxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_rxbytes",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPRxSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_rxsegs",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPRxBursts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_rxbursts",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX bursts statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsUDPRxDips = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_rxdips",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX dips statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsUDPDrops = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_drops",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket drops statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPConsumeMisses = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_consume_misses",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket consume packet misses",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPStackTxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_stack_txbytes",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP stack TX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPStackTxSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_stack_txsegs",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP stack TX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPStackRxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_stack_rxbytes",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP stack RX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPStackRxSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_stack_rxsegs",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP stack RX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPTxWatermarksState = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "socket_stats_udp_tx_watermarks_state",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX watermarks state",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsUDPRxWatermarksState = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "socket_stats_udp_rx_watermarks_state",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX watermarks state",
	}, []string{"namespace", "pod", "binary"})
)

// UDP multicast socket metrics
var (
	SocketStatsUDPMulticastTxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_txbytes",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX bytes statistics",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	SocketStatsUDPMulticastTxSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_txsegs",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX segment statistics",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	SocketStatsUDPMulticastRxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_rxbytes",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX bytes statistics",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	SocketStatsUDPMulticastRxSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_rxsegs",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX segment statistics",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	SocketStatsUDPMulticastDrops = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_drops",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket drops statistics",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	SocketStatsUDPMulticastConsumeMisses = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_consume_misses",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket consume packet misses",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
)

// UDP metrics collection errors
var (
	SocketStatsUDPGC = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        "socket_stats_udp_retrieve",
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
	UdpLatencyBucket = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "udp_latency_microseconds_bucket",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram bucket for UDP socket latency in microseconds",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns", "le"})
	UdpLatencyCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "udp_latency_microseconds_count",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram count for UDP socket latency",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	UdpLatencySum = promauto.NewCounterVec(prometheus.CounterOpts{
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
	UdpMulticastLatencyBucket = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "udp_mcast_latency_microseconds_bucket",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram bucket for UDP socket multicast latency in microseconds",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast", "le"})
	UdpMulticastLatencyCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "udp_mcast_latency_microseconds_count",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram count for UDP socket multicast latency",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	UdpMulticastLatencySum = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "udp_mcast_latency_microseconds_sum",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram sum for UDP socket multicast latency in microseconds",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
)

// UDP Sequence Check errors
var (
	SocketStatsUDPSeqCheckErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_udp_sequence_check_errors",
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
