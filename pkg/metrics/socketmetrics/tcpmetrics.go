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

var (
	LabelStringTCPSrc = []string{"namespace", "workload", "pod", "binary"}
	LabelStringTCPDst = []string{"dstnamespace", "dstworkload", "dstpod", "dstdns", "dstip"}
	LabelStringTCP    = append(LabelStringTCPSrc, LabelStringTCPDst[:]...)
	LabelStringTCPLe  = append(LabelStringTCP, "le")
)

// TCP socket metrics
var (
	SocketStatsTxBytes = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_txbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket TX bytes statistics",
	}, LabelStringTCP)
	SocketStatsTxSegs = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_txsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket TX segment statistics",
	}, LabelStringTCP)
	SocketStatsTxBursts = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_txbursts_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket TX bursts statistics",
	}, LabelStringTCPSrc)
	SocketStatsTxDips = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_txdips_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket TX dips statistics",
	}, LabelStringTCPSrc)
	SocketStatsRxBytes = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_rxbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket RX bytes statistics",
	}, LabelStringTCP)
	SocketStatsRxSegs = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_rxsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket RX segment statistics",
	}, LabelStringTCP)
	SocketStatsRxBursts = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_rxbursts_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket RX bursts statistics",
	}, LabelStringTCPSrc)
	SocketStatsRxDips = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_rxdips_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket RX dips statistics",
	}, LabelStringTCPSrc)
	SocketStatsRetranBytes = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_retransmitbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket retransmit bytes statistics",
	}, LabelStringTCP)
	SocketStatsRetranSegs = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_retransmitsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket retransmit seg statistics",
	}, LabelStringTCP)
	SocketStatsZeroWindow = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_zerowindow_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket zero window events",
	}, LabelStringTCP)
	SocketStatsSrtt = metrics.NewHistogramVecWithPod(prometheus.HistogramOpts{
		Name:      "socket_stats_srtt",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket smoothed RTT latency distribution in microseconds.",
		Buckets:   []float64{50, 100, 250, 500, 750, 1_000, 2_500, 5_000, 7_500, 10_000, 25_000, 50_000, 75_000, 100_000},
	}, LabelStringTCP)
	SocketStatsDrops = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "socket_stats_drops_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket socket drops statistics",
	}, LabelStringTCP)
	SocketStatsTxWatermarksState = metrics.NewGaugeVecWithPod(prometheus.GaugeOpts{
		Name:      "socket_stats_tx_watermarks_state",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket TX watermarks state",
	}, LabelStringTCPSrc)
	SocketStatsRxWatermarksState = metrics.NewGaugeVecWithPod(prometheus.GaugeOpts{
		Name:      "socket_stats_rx_watermarks_state",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket RX watermarks state",
	}, LabelStringTCPSrc)
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
	}, LabelStringTCPLe)
	TcpRttCount = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "tcp_rtt_microseconds_count",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram count for TCP socket rtt",
	}, LabelStringTCP)
	TcpRttSum = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "tcp_rtt_microseconds_sum",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram sum for TCP socket rtt in microseconds",
	}, LabelStringTCP)
)
var (
	TcpLatencyBucket = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "tcp_latency_microseconds_bucket",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram bucket for TCP socket latency in microseconds",
	}, LabelStringTCPLe)
	TcpLatencyCount = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "tcp_latency_microseconds_count",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram count for TCP socket latency",
	}, LabelStringTCP)
	TcpLatencySum = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "tcp_latency_microseconds_sum",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram sum for TCP socket latency in microseconds",
	}, LabelStringTCP)
)
