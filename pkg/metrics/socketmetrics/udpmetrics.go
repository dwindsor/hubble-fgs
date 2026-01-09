// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package socketmetrics

import (
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/udpconfig"
)

// UDP socket metrics
var (
	SocketStatsUDPTxBytes = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_udp_txbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX bytes statistics",
	}, nil)
	SocketStatsUDPTxSegs = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_udp_txsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX segment statistics",
	}, nil)
	SocketStatsUDPTxBursts = metrics.MustNewGranularCounter[metrics.ProcessLabels](prometheus.CounterOpts{
		Name:      "socket_stats_udp_txbursts_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX bursts statistics",
	}, nil)
	SocketStatsUDPTxDips = metrics.MustNewGranularCounter[metrics.ProcessLabels](prometheus.CounterOpts{
		Name:      "socket_stats_udp_txdips_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX dips statistics",
	}, nil)
	SocketStatsUDPRxBytes = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_udp_rxbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX bytes statistics",
	}, nil)
	SocketStatsUDPRxSegs = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_udp_rxsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX segment statistics",
	}, nil)
	SocketStatsUDPRxBursts = metrics.MustNewGranularCounter[metrics.ProcessLabels](prometheus.CounterOpts{
		Name:      "socket_stats_udp_rxbursts_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX bursts statistics",
	}, nil)
	SocketStatsUDPRxDips = metrics.MustNewGranularCounter[metrics.ProcessLabels](prometheus.CounterOpts{
		Name:      "socket_stats_udp_rxdips_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX dips statistics",
	}, nil)
	SocketStatsUDPDrops = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_udp_drops_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket drops statistics",
	}, nil)
	SocketStatsUDPConsumeMisses = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_udp_consume_misses_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket consume packet misses",
	}, nil)
	SocketStatsUDPStackTxBytes = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_udp_stack_txbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP stack TX bytes statistics",
	}, nil)
	SocketStatsUDPStackTxSegs = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_udp_stack_txsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP stack TX segment statistics",
	}, nil)
	SocketStatsUDPStackRxBytes = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_udp_stack_rxbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP stack RX bytes statistics",
	}, nil)
	SocketStatsUDPStackRxSegs = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_udp_stack_rxsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP stack RX segment statistics",
	}, nil)
	SocketStatsUDPTxWatermarksState = metrics.MustNewGranularGauge[metrics.ProcessLabels](prometheus.GaugeOpts{
		Name:      "socket_stats_udp_tx_watermarks_state",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX watermarks state",
	}, nil)
	SocketStatsUDPRxWatermarksState = metrics.MustNewGranularGauge[metrics.ProcessLabels](prometheus.GaugeOpts{
		Name:      "socket_stats_udp_rx_watermarks_state",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX watermarks state",
	}, nil)
)

// UDP multicast socket metrics
var (
	SocketStatsUDPMulticastTxBytes = metrics.MustNewGranularCounter[MulticastSocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_txbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX bytes statistics",
	}, nil)
	SocketStatsUDPMulticastTxSegs = metrics.MustNewGranularCounter[MulticastSocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_txsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket TX segment statistics",
	}, nil)
	SocketStatsUDPMulticastRxBytes = metrics.MustNewGranularCounter[MulticastSocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_rxbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX bytes statistics",
	}, nil)
	SocketStatsUDPMulticastRxSegs = metrics.MustNewGranularCounter[MulticastSocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_rxsegs_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket RX segment statistics",
	}, nil)
	SocketStatsUDPMulticastDrops = metrics.MustNewGranularCounter[MulticastSocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_drops_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket drops statistics",
	}, nil)
	SocketStatsUDPMulticastConsumeMisses = metrics.MustNewGranularCounter[MulticastSocketLabels](prometheus.CounterOpts{
		Name:      "socket_stats_udp_mcast_consume_misses_total",
		Namespace: consts.MetricsNamespace,
		Help:      "UDP socket consume packet misses",
	}, nil)
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

// UDP metrics BPF map size
var (
	UDPMapEntries = metrics.MustNewCustomGauge(metrics.NewOpts(
		consts.MetricsNamespace, "", "udp_map_entries",
		"The total number of in-use entries in the UDP socket map.",
		nil, nil, nil,
	))
)

// UDP Latency Histogram
// It emulates an OpenMetrics histogram:
//   - a set of "_bucket"-suffixed counters with a "le" label (less or equal), which is the upper
//     limit of the bucket
//   - a "_count" metric, identical to the highest ("+Inf") bucket metric
//   - a "_sum" metric, reporting the sum of all observed values
var (
	UdpLatencyBucket = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "udp_latency_microseconds_bucket",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram bucket for UDP socket latency in microseconds",
	}, []string{"le"})
	UdpLatencyCount = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "udp_latency_microseconds_count",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram count for UDP socket latency",
	}, nil)
	UdpLatencySum = metrics.MustNewGranularCounter[SocketLabels](prometheus.CounterOpts{
		Name:      "udp_latency_microseconds_sum",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram sum for UDP socket latency in microseconds",
	}, nil)
)

// UDP Multicast Latency Histogram
// It emulates an OpenMetrics histogram:
//   - a set of "_bucket"-suffixed counters with a "le" label (less or equal), which is the upper
//     limit of the bucket
//   - a "_count" metric, identical to the highest ("+Inf") bucket metric
//   - a "_sum" metric, reporting the sum of all observed values
var (
	UdpMulticastLatencyBucket = metrics.MustNewGranularCounter[MulticastSocketLabels](prometheus.CounterOpts{
		Name:      "udp_mcast_latency_microseconds_bucket",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram bucket for UDP socket multicast latency in microseconds",
	}, []string{"le"})
	UdpMulticastLatencyCount = metrics.MustNewGranularCounter[MulticastSocketLabels](prometheus.CounterOpts{
		Name:      "udp_mcast_latency_microseconds_count",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram count for UDP socket multicast latency",
	}, nil)
	UdpMulticastLatencySum = metrics.MustNewGranularCounter[MulticastSocketLabels](prometheus.CounterOpts{
		Name:      "udp_mcast_latency_microseconds_sum",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram sum for UDP socket multicast latency in microseconds",
	}, nil)
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
	UDPGCTypeCloseEventMissingSocket
)

var UDPGCTypeStrings = map[UDPGCType]string{
	UDPGCTypeTicker:                  "Ticker",
	UDPGCTypeFailedToOpenMap:         "Failed To Open Map",
	UDPGCTypeTotalRetrieve:           "Total Retrieved",
	UDPGCTypePidIsZero:               "Pid Is Zero",
	UDPGCTypeNanoTimeSinceFailure:    "NanoTimeSince Failure",
	UDPGCTypeDiffValuesFailure:       "DiffValues Failure",
	UDPGCTypeDiffValuesFailureGC:     "DiffValues GC Failure",
	UDPGCTypeDeleteKeyFailed:         "Delete Key Failed",
	UDPGCTypeCloseEventMissingSocket: "Close event missing socket",
}

// Increment a UDP GC metric for a retrieval type
func UDPGCMetricInc(ty UDPGCType) {
	SocketStatsUDPGC.WithLabelValues(UDPGCTypeStrings[ty]).Inc()
}

func NewUdpBPFCollector() metrics.CollectorWithInit {
	return metrics.NewCustomCollector(
		metrics.CustomMetrics{
			UDPMapEntries,
		},
		collect,
		collectForDocs,
	)
}

func collect(ch chan<- prometheus.Metric) {
	if !udpconfig.MetricsEnabled {
		return
	}
	statsFile := filepath.Join(bpf.MapPrefixPath(), udpconfig.UdpMapStatsName)
	mStats, err := ebpf.LoadPinnedMap(statsFile, nil)
	if err != nil {
		logger.GetLogger().Warn("UDP map stats update failed to open file.", logfields.Error, err, "file", statsFile)
		return
	}
	defer mStats.Close()

	key := int32(0)
	var value []int64
	err = mStats.Lookup(key, &value)
	if err != nil {
		logger.GetLogger().Warn("UDP read map stats failed.", logfields.Error, err)
		return
	}
	udpconfig.UdpMapRemovesUpdate.Lock()
	count := -udpconfig.UdpMapRemoves
	udpconfig.UdpMapRemovesUpdate.Unlock()
	for _, v := range value {
		count += v
	}
	ch <- UDPMapEntries.MustMetric(float64(count))
}

func collectForDocs(ch chan<- prometheus.Metric) {
	ch <- UDPMapEntries.MustMetric(0)
}
