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
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

// TCP socket metrics
var (
	SocketStatsTxBytes = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_txbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket TX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsTxSegs = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_txsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket TX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsTxBursts = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_txbursts_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket TX bursts statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsTxDips = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_txdips_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket TX dips statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsRxBytes = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_rxbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket RX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsRxSegs = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_rxsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket RX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsRxBursts = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_rxbursts_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket RX bursts statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsRxDips = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_rxdips_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket RX dips statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsRetranBytes = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_retransmitbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket retransmit bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsRetranSegs = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_retransmitsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket retransmit seg statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsZeroWindow = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_zerowindow_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket zero window events",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsSrtt = metrics.NewHistogramVecWithPod(prometheus.HistogramOpts{
		Name:      "socket_stats_srtt",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket smoothed RTT latency distribution in microseconds.",
		Buckets:   []float64{50, 100, 250, 500, 750, 1_000, 2_500, 5_000, 7_500, 10_000, 25_000, 50_000, 75_000, 100_000},
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsDrops = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_drops_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket socket drops statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsTxWatermarksState = metrics.NewGaugeVecWithPod(prometheus.GaugeOpts{
		Name:      "socket_stats_tx_watermarks_state",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket TX watermarks state",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsRxWatermarksState = metrics.NewGaugeVecWithPod(prometheus.GaugeOpts{
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
	TcpRttBucket = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "tcp_rtt_microseconds_bucket",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram bucket for TCP socket rtt in microseconds",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns", "le"})
	TcpRttCount = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "tcp_rtt_microseconds_count",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram count for TCP socket rtt",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	TcpRttSum = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "tcp_rtt_microseconds_sum",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram sum for TCP socket rtt in microseconds",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
)
var (
	TcpLatencyBucket = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "tcp_latency_microseconds_bucket",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram bucket for TCP socket latency in microseconds",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns", "le"})
	TcpLatencyCount = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "tcp_latency_microseconds_count",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram count for TCP socket latency",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	TcpLatencySum = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "tcp_latency_microseconds_sum",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram sum for TCP socket latency in microseconds",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
)
