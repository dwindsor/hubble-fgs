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
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

// TCP socket metrics
var (
	SocketStatsTxBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_txbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket TX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsTxSegs = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_txsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket TX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsTxBursts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_txbursts_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket TX bursts statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsTxDips = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_txdips_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket TX dips statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsRxBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_rxbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket RX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsRxSegs = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_rxsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket RX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsRxBursts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_rxbursts_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket RX bursts statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsRxDips = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_rxdips_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket RX dips statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsRetranBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_retransmitbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket retransmit bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsRetranSegs = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_retransmitsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket retransmit seg statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsZeroWindow = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_zerowindow_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket zero window events",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsSrtt = prometheus.NewSummaryVec(prometheus.SummaryOpts{
		Name:       "socket_stats_srtt",
		Namespace:  consts.MetricsNamespace,
		Help:       "TCP socket smoothed RTT latency distribution.",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsDrops = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "socket_stats_drops_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket socket drops statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsTxWatermarksState = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "socket_stats_tx_watermarks_state",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket TX watermarks state",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsRxWatermarksState = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "socket_stats_rx_watermarks_state",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket RX watermarks state",
	}, []string{"namespace", "pod", "binary"})
)

// TCP Latency Histograms
// They emulate OpenMetrics histograms:
//   - a set of "_bucket"-suffixed counters with a "le" label (less or equal), which is the upper
//     limit of the bucket
//   - a "_count" metric, identical to the highest ("+Inf") bucket metric
//   - a "_sum" metric, reporting the sum of all observed values
var (
	TcpRttBucket = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "tcp_rtt_microseconds_bucket",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram bucket for TCP socket rtt in microseconds",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns", "le"})
	TcpRttCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "tcp_rtt_microseconds_count",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram count for TCP socket rtt",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	TcpRttSum = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "tcp_rtt_microseconds_sum",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram sum for TCP socket rtt in microseconds",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
)
var (
	TcpLatencyBucket = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "tcp_latency_microseconds_bucket",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram bucket for TCP socket latency in microseconds",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns", "le"})
	TcpLatencyCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "tcp_latency_microseconds_count",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram count for TCP socket latency",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	TcpLatencySum = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "tcp_latency_microseconds_sum",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram sum for TCP socket latency in microseconds",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
)
