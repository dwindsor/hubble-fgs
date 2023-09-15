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

	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

// UDP socket metrics
var (
	SocketStatsUDPTxBytes = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_txbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX bytes statistics",
	}, []string{"namespace", "workload", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPTxSegs = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_txsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX segment statistics",
	}, []string{"namespace", "workload", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPTxBursts = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_txbursts_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX bursts statistics",
	}, []string{"namespace", "workload", "pod", "binary"})
	SocketStatsUDPTxDips = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_txdips_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX dips statistics",
	}, []string{"namespace", "workload", "pod", "binary"})
	SocketStatsUDPRxBytes = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_rxbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX bytes statistics",
	}, []string{"namespace", "workload", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPRxSegs = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_rxsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX segment statistics",
	}, []string{"namespace", "workload", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPRxBursts = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_rxbursts_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX bursts statistics",
	}, []string{"namespace", "workload", "pod", "binary"})
	SocketStatsUDPRxDips = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_rxdips_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX dips statistics",
	}, []string{"namespace", "workload", "pod", "binary"})
	SocketStatsUDPDrops = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_drops_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket drops statistics",
	}, []string{"namespace", "workload", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPConsumeMisses = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_consume_misses_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket consume packet misses",
	}, []string{"namespace", "workload", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPStackTxBytes = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_stack_txbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP stack TX bytes statistics",
	}, []string{"namespace", "workload", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPStackTxSegs = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_stack_txsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP stack TX segment statistics",
	}, []string{"namespace", "workload", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPStackRxBytes = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_stack_rxbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP stack RX bytes statistics",
	}, []string{"namespace", "workload", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPStackRxSegs = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_stack_rxsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP stack RX segment statistics",
	}, []string{"namespace", "workload", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPTxWatermarksState = metrics.NewGaugeVecWithPod(prometheus.GaugeOpts{
		Name:      "socket_stats_udp_tx_watermarks_state",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX watermarks state",
	}, []string{"namespace", "workload", "pod", "binary"})
	SocketStatsUDPRxWatermarksState = metrics.NewGaugeVecWithPod(prometheus.GaugeOpts{
		Name:      "socket_stats_udp_rx_watermarks_state",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX watermarks state",
	}, []string{"namespace", "workload", "pod", "binary"})
)

// UDP multicast socket metrics
var (
	SocketStatsUDPMulticastTxBytes = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_txbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX bytes statistics",
	}, []string{"namespace", "workload", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	SocketStatsUDPMulticastTxSegs = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_txsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX segment statistics",
	}, []string{"namespace", "workload", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	SocketStatsUDPMulticastRxBytes = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_rxbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX bytes statistics",
	}, []string{"namespace", "workload", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	SocketStatsUDPMulticastRxSegs = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_rxsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX segment statistics",
	}, []string{"namespace", "workload", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	SocketStatsUDPMulticastDrops = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_drops_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket drops statistics",
	}, []string{"namespace", "workload", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	SocketStatsUDPMulticastConsumeMisses = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_consume_misses_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket consume packet misses",
	}, []string{"namespace", "workload", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
)

// UDP metrics collection errors
var (
	SocketStatsUDPGC = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
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
	UdpLatencyBucket = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "udp_latency_microseconds_bucket",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram bucket for UDP socket latency in microseconds",
	}, []string{"namespace", "workload", "pod", "binary", "dstnamespace", "dstpod", "dstdns", "le"})
	UdpLatencyCount = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "udp_latency_microseconds_count",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram count for UDP socket latency",
	}, []string{"namespace", "workload", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	UdpLatencySum = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "udp_latency_microseconds_sum",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram sum for UDP socket latency in microseconds",
	}, []string{"namespace", "workload", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
)

// UDP Multicast Latency Histogram
// It emulates an OpenMetrics histogram:
//   - a set of "_bucket"-suffixed counters with a "le" label (less or equal), which is the upper
//     limit of the bucket
//   - a "_count" metric, identical to the highest ("+Inf") bucket metric
//   - a "_sum" metric, reporting the sum of all observed values
var (
	UdpMulticastLatencyBucket = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "udp_mcast_latency_microseconds_bucket",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram bucket for UDP socket multicast latency in microseconds",
	}, []string{"namespace", "workload", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast", "le"})
	UdpMulticastLatencyCount = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "udp_mcast_latency_microseconds_count",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram count for UDP socket multicast latency",
	}, []string{"namespace", "workload", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	UdpMulticastLatencySum = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "udp_mcast_latency_microseconds_sum",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram sum for UDP socket multicast latency in microseconds",
	}, []string{"namespace", "workload", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
)

// UDP Sequence Check errors
var (
	SocketStatsUDPSeqCheckErrors = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_sequence_check_errors_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket sequence check errors statistics",
	}, []string{"namespace", "workload", "pod", "binary"})
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
	UDPGCTypeDeleteKeyFailed
)

var UDPGCTypeStrings = map[UDPGCType]string{
	UDPGCTypeTicker:               "Ticker",
	UDPGCTypeFailedToOpenMap:      "Failed To Open Map",
	UDPGCTypeTotalRetrieve:        "Total Retrieved",
	UDPGCTypePidIsZero:            "Pid Is Zero",
	UDPGCTypeNanoTimeSinceFailure: "NanoTimeSince Failure",
	UDPGCTypeDiffValuesFailure:    "DiffValues Failure",
	UDPGCTypeDiffValuesFailureGC:  "DiffValues GC Failure",
	UDPGCTypeDeleteKeyFailed:      "Delete Key Failed",
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
