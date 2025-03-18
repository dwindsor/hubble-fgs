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
	SocketStatsTxBytes = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_txbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket TX bytes statistics",
	}, nil)
	SocketStatsTxSegs = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_txsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket TX segment statistics",
	}, nil)
	SocketStatsTxBursts = metrics.MustNewGranularCounter[metrics.ProcessLabels](prometheus.CounterOpts{
		Name:      "socket_stats_txbursts_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket TX bursts statistics",
	}, nil)
	SocketStatsTxDips = metrics.MustNewGranularCounter[metrics.ProcessLabels](prometheus.CounterOpts{
		Name:      "socket_stats_txdips_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket TX dips statistics",
	}, nil)
	SocketStatsRxBytes = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_rxbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket RX bytes statistics",
	}, nil)
	SocketStatsRxSegs = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_rxsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket RX segment statistics",
	}, nil)
	SocketStatsRxBursts = metrics.MustNewGranularCounter[metrics.ProcessLabels](prometheus.CounterOpts{
		Name:      "socket_stats_rxbursts_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket RX bursts statistics",
	}, nil)
	SocketStatsRxDips = metrics.MustNewGranularCounter[metrics.ProcessLabels](prometheus.CounterOpts{
		Name:      "socket_stats_rxdips_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket RX dips statistics",
	}, nil)
	SocketStatsRetranBytes = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_retransmitbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket retransmit bytes statistics",
	}, nil)
	SocketStatsRetranSegs = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_retransmitsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket retransmit seg statistics",
	}, nil)
	SocketStatsZeroWindow = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_zerowindow_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket zero window events",
	}, nil)
	SocketStatsSrtt = metrics.MustNewGranularHistogram[SocketLabels](prometheus.HistogramOpts{
		Name:      "socket_stats_srtt",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket smoothed RTT latency distribution in microseconds.",
		Buckets:   []float64{50, 100, 250, 500, 750, 1_000, 2_500, 5_000, 7_500, 10_000, 25_000, 50_000, 75_000, 100_000},
	}, nil)
	SocketStatsDrops = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_drops_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket socket drops statistics",
	}, nil)
	SocketStatsTxWatermarksState = metrics.MustNewGranularGauge[metrics.ProcessLabels](prometheus.GaugeOpts{
		Name:      "socket_stats_tx_watermarks_state",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket TX watermarks state",
	}, nil)
	SocketStatsRxWatermarksState = metrics.MustNewGranularGauge[metrics.ProcessLabels](prometheus.GaugeOpts{
		Name:      "socket_stats_rx_watermarks_state",
		Namespace: consts.MetricsNamespace,
		Help:      "TCP socket RX watermarks state",
	}, nil)
)

// TCP Latency Histograms
// They emulate OpenMetrics histograms:
//   - a set of "_bucket"-suffixed counters with a "le" label (less or equal), which is the upper
//     limit of the bucket
//   - a "_count" metric, identical to the highest ("+Inf") bucket metric
//   - a "_sum" metric, reporting the sum of all observed values
var (
	TcpRttBucket = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "tcp_rtt_microseconds_bucket",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram bucket for TCP socket rtt in microseconds",
	}, []string{"le"})
	TcpRttCount = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "tcp_rtt_microseconds_count",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram count for TCP socket rtt",
	}, nil)
	TcpRttSum = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "tcp_rtt_microseconds_sum",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram sum for TCP socket rtt in microseconds",
	}, nil)
)
var (
	TcpLatencyBucket = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "tcp_latency_microseconds_bucket",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram bucket for TCP socket latency in microseconds",
	}, []string{"le"})
	TcpLatencyCount = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "tcp_latency_microseconds_count",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram count for TCP socket latency",
	}, nil)
	TcpLatencySum = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "tcp_latency_microseconds_sum",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram sum for TCP socket latency in microseconds",
	}, nil)
)

// TCP LRU Cache size
var (
	TcpCacheEntries = prometheus.NewGauge(prometheus.GaugeOpts{
		Name:      "tcp_cache_entries",
		Namespace: consts.MetricsNamespace,
		Help:      "The total number of in-use entries in the TCP socket cache",
	})
)
