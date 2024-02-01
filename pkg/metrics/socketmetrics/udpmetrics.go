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

var (
	LabelStringUDPSrc      = []string{"namespace", "workload", "pod", "binary"}
	LabelStringUDPDst      = []string{"dstnamespace", "dstworkload", "dstpod", "dstdns", "dstip"}
	LabelStringUDP         = append(LabelStringUDPSrc, LabelStringUDPDst[:]...)
	LabelStringUDPLe       = append(LabelStringUDP, "le")
	LabelStringMulticast   = append(LabelStringUDPSrc, "srcmcast", "dstnamespace", "dstworkload", "dstpod", "dstmcast")
	LabelStringMulticastLe = append(LabelStringMulticast, "le")
)

// UDP socket metrics
var (
	SocketStatsUDPTxBytes = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_txbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX bytes statistics",
	}, LabelStringUDP)
	SocketStatsUDPTxSegs = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_txsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX segment statistics",
	}, LabelStringUDP)
	SocketStatsUDPTxBursts = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_txbursts_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX bursts statistics",
	}, LabelStringUDPSrc)
	SocketStatsUDPTxDips = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_txdips_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX dips statistics",
	}, LabelStringUDPSrc)
	SocketStatsUDPRxBytes = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_rxbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX bytes statistics",
	}, LabelStringUDP)
	SocketStatsUDPRxSegs = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_rxsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX segment statistics",
	}, LabelStringUDP)
	SocketStatsUDPRxBursts = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_rxbursts_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX bursts statistics",
	}, LabelStringUDPSrc)
	SocketStatsUDPRxDips = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_rxdips_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX dips statistics",
	}, LabelStringUDPSrc)
	SocketStatsUDPDrops = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_drops_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket drops statistics",
	}, LabelStringUDP)
	SocketStatsUDPConsumeMisses = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_consume_misses_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket consume packet misses",
	}, LabelStringUDP)
	SocketStatsUDPStackTxBytes = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_stack_txbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP stack TX bytes statistics",
	}, LabelStringUDP)
	SocketStatsUDPStackTxSegs = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_stack_txsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP stack TX segment statistics",
	}, LabelStringUDP)
	SocketStatsUDPStackRxBytes = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_stack_rxbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP stack RX bytes statistics",
	}, LabelStringUDP)
	SocketStatsUDPStackRxSegs = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_stack_rxsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP stack RX segment statistics",
	}, LabelStringUDP)
	SocketStatsUDPTxWatermarksState = metrics.NewGaugeVecWithPod(prometheus.GaugeOpts{
		Name:      "socket_stats_udp_tx_watermarks_state",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX watermarks state",
	}, LabelStringUDPSrc)
	SocketStatsUDPRxWatermarksState = metrics.NewGaugeVecWithPod(prometheus.GaugeOpts{
		Name:      "socket_stats_udp_rx_watermarks_state",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX watermarks state",
	}, LabelStringUDPSrc)
)

// UDP multicast socket metrics
var (
	SocketStatsUDPMulticastTxBytes = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_txbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX bytes statistics",
	}, LabelStringMulticast)
	SocketStatsUDPMulticastTxSegs = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_txsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX segment statistics",
	}, LabelStringMulticast)
	SocketStatsUDPMulticastRxBytes = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_rxbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX bytes statistics",
	}, LabelStringMulticast)
	SocketStatsUDPMulticastRxSegs = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_rxsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX segment statistics",
	}, LabelStringMulticast)
	SocketStatsUDPMulticastDrops = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_drops_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket drops statistics",
	}, LabelStringMulticast)
	SocketStatsUDPMulticastConsumeMisses = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_consume_misses_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket consume packet misses",
	}, LabelStringMulticast)
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
	}, LabelStringUDPLe)
	UdpLatencyCount = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "udp_latency_microseconds_count",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram count for UDP socket latency",
	}, LabelStringUDP)
	UdpLatencySum = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "udp_latency_microseconds_sum",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram sum for UDP socket latency in microseconds",
	}, LabelStringUDP)
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
	}, LabelStringMulticastLe)
	UdpMulticastLatencyCount = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "udp_mcast_latency_microseconds_count",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram count for UDP socket multicast latency",
	}, LabelStringMulticast)
	UdpMulticastLatencySum = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "udp_mcast_latency_microseconds_sum",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram sum for UDP socket multicast latency in microseconds",
	}, LabelStringMulticast)
)

// UDP Sequence Check errors
// NB: This metric is specific to a proprietary protocol transmitting sequence
// numbers on top of UDP. It shouldn't be registered by default.
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
