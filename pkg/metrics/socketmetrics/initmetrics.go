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
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"

	enterpriseMetrics "github.com/isovalent/hubble-fgs/pkg/metrics"
)

func InitTCPEventsMetrics(registry *prometheus.Registry) {
	// TCP socket metrics
	registry.MustRegister(SocketStatsTxBytes)
	registry.MustRegister(SocketStatsTxSegs)
	registry.MustRegister(SocketStatsTxBursts)
	registry.MustRegister(SocketStatsTxDips)
	registry.MustRegister(SocketStatsRxBytes)
	registry.MustRegister(SocketStatsRxSegs)
	registry.MustRegister(SocketStatsRxBursts)
	registry.MustRegister(SocketStatsRxDips)
	registry.MustRegister(SocketStatsRetranBytes)
	registry.MustRegister(SocketStatsRetranSegs)
	registry.MustRegister(SocketStatsZeroWindow)
	registry.MustRegister(SocketStatsSrtt)
	registry.MustRegister(SocketStatsDrops)
	registry.MustRegister(SocketStatsTxWatermarksState)
	registry.MustRegister(SocketStatsRxWatermarksState)

	// TCP RTT Histograms
	registry.MustRegister(TcpRttBucket)
	registry.MustRegister(TcpRttCount)
	registry.MustRegister(TcpRttSum)
}

func InitTCPEventsMetricsForDocs(registry *prometheus.Registry) {
	InitTCPEventsMetrics(registry)

	socketLabels := NewSocketLabels(
		consts.ExampleNamespace, consts.ExampleWorkload, consts.ExamplePod, consts.ExampleBinary,
		consts.ExampleNamespace, consts.ExampleWorkload, consts.ExamplePod,
		enterpriseMetrics.ExampleDNSNamesLabel, enterpriseMetrics.ExampleIPLabel,
	)

	SocketStatsTxBytes.WithLabelValues(socketLabels).Add(0)
	SocketStatsTxSegs.WithLabelValues(socketLabels).Add(0)
	SocketStatsRxBytes.WithLabelValues(socketLabels).Add(0)
	SocketStatsRxSegs.WithLabelValues(socketLabels).Add(0)
	SocketStatsRetranBytes.WithLabelValues(socketLabels).Add(0)
	SocketStatsRetranSegs.WithLabelValues(socketLabels).Add(0)
	SocketStatsZeroWindow.WithLabelValues(socketLabels).Add(0)
	SocketStatsDrops.WithLabelValues(socketLabels).Add(0)
	SocketStatsSrtt.WithLabelValues(socketLabels)

	// Watermarks
	srcSocketLabels := metrics.NewProcessLabels(
		consts.ExampleNamespace, consts.ExampleWorkload, consts.ExamplePod, consts.ExampleBinary, consts.ExampleNodeName,
	)
	SocketStatsTxBursts.WithLabelValues(srcSocketLabels).Add(0)
	SocketStatsTxDips.WithLabelValues(srcSocketLabels).Add(0)
	SocketStatsRxBursts.WithLabelValues(srcSocketLabels).Add(0)
	SocketStatsRxDips.WithLabelValues(srcSocketLabels).Add(0)
	SocketStatsTxWatermarksState.WithLabelValues(srcSocketLabels).Add(0)
	SocketStatsRxWatermarksState.WithLabelValues(srcSocketLabels).Add(0)

	// Histograms. They are defined not with Prometheus histogram struct, but as sets of counters.
	// This means they are rendered differently than "regular" histograms in the metrics docs.
	// We might consider improving docs for histograms, both Prometheus and Tetragon.
	for _, b := range enterpriseMetrics.ExampleLatencyBuckets {
		TcpRttBucket.WithLabelValues(socketLabels, b).Add(0)
	}
	TcpRttCount.WithLabelValues(socketLabels).Add(0)
	TcpRttSum.WithLabelValues(socketLabels).Add(0)
}

func InitHealthMetrics(registry *prometheus.Registry) {
	// UDP metrics collection errors
	registry.MustRegister(SocketStatsUDPGC)

	for _, er := range UDPGCTypeStrings {
		SocketStatsUDPGC.WithLabelValues(er).Add(0)
	}

	// NOTES:
	// * Rename count label (to e.g. error)?

	// Register tg_udp_map entries metric
	registry.MustRegister(NewUdpBPFCollector())

	// TCP Cache LRU
	registry.MustRegister(TcpCacheEntries)
}

func InitUDPEventsMetrics(registry *prometheus.Registry) {
	// UDP socket metrics
	registry.MustRegister(SocketStatsUDPTxBytes)
	registry.MustRegister(SocketStatsUDPTxSegs)
	registry.MustRegister(SocketStatsUDPTxBursts)
	registry.MustRegister(SocketStatsUDPTxDips)
	registry.MustRegister(SocketStatsUDPRxBytes)
	registry.MustRegister(SocketStatsUDPRxSegs)
	registry.MustRegister(SocketStatsUDPRxBursts)
	registry.MustRegister(SocketStatsUDPRxDips)
	registry.MustRegister(SocketStatsUDPDrops)
	registry.MustRegister(SocketStatsUDPConsumeMisses)
	registry.MustRegister(SocketStatsUDPStackTxBytes)
	registry.MustRegister(SocketStatsUDPStackTxSegs)
	registry.MustRegister(SocketStatsUDPStackRxBytes)
	registry.MustRegister(SocketStatsUDPStackRxSegs)
	registry.MustRegister(SocketStatsUDPTxWatermarksState)
	registry.MustRegister(SocketStatsUDPRxWatermarksState)

	// UDP multicast socket metrics
	registry.MustRegister(SocketStatsUDPMulticastTxBytes)
	registry.MustRegister(SocketStatsUDPMulticastTxSegs)
	registry.MustRegister(SocketStatsUDPMulticastRxBytes)
	registry.MustRegister(SocketStatsUDPMulticastRxSegs)
	registry.MustRegister(SocketStatsUDPMulticastDrops)
	registry.MustRegister(SocketStatsUDPMulticastConsumeMisses)
	registry.MustRegister(SocketStatsUDPSeqCheckErrors)
}

func InitUDPEventsMetricsForDocs(registry *prometheus.Registry) {
	InitUDPEventsMetrics(registry)

	socketLabels := NewSocketLabels(
		consts.ExampleNamespace, consts.ExampleWorkload, consts.ExamplePod, consts.ExampleBinary,
		consts.ExampleNamespace, consts.ExampleWorkload, consts.ExamplePod,
		enterpriseMetrics.ExampleDNSNamesLabel, enterpriseMetrics.ExampleIPLabel,
	)

	SocketStatsUDPTxBytes.WithLabelValues(socketLabels).Add(0)
	SocketStatsUDPTxSegs.WithLabelValues(socketLabels).Add(0)
	SocketStatsUDPRxBytes.WithLabelValues(socketLabels).Add(0)
	SocketStatsUDPRxSegs.WithLabelValues(socketLabels).Add(0)
	SocketStatsUDPDrops.WithLabelValues(socketLabels).Add(0)
	SocketStatsUDPConsumeMisses.WithLabelValues(socketLabels).Add(0)
	SocketStatsUDPStackTxBytes.WithLabelValues(socketLabels).Add(0)
	SocketStatsUDPStackTxSegs.WithLabelValues(socketLabels).Add(0)
	SocketStatsUDPStackRxBytes.WithLabelValues(socketLabels).Add(0)
	SocketStatsUDPStackRxSegs.WithLabelValues(socketLabels).Add(0)

	// Watermarks
	srcSocketLabels := metrics.NewProcessLabels(
		consts.ExampleNamespace, consts.ExampleWorkload, consts.ExamplePod, consts.ExampleBinary, consts.ExampleNodeName,
	)
	SocketStatsUDPTxBursts.WithLabelValues(srcSocketLabels).Add(0)
	SocketStatsUDPTxDips.WithLabelValues(srcSocketLabels).Add(0)
	SocketStatsUDPRxBursts.WithLabelValues(srcSocketLabels).Add(0)
	SocketStatsUDPRxDips.WithLabelValues(srcSocketLabels).Add(0)
	SocketStatsUDPTxWatermarksState.WithLabelValues(srcSocketLabels).Add(0)
	SocketStatsUDPRxWatermarksState.WithLabelValues(srcSocketLabels).Add(0)

	// Multicast
	multicastLabels := NewMulticastSocketLabels(
		consts.ExampleNamespace, consts.ExampleWorkload, consts.ExamplePod, consts.ExampleBinary,
		enterpriseMetrics.ExampleIPLabel,
		consts.ExampleNamespace, consts.ExampleWorkload, consts.ExamplePod,
		enterpriseMetrics.ExampleIPLabel,
	)
	udpSeqCheckLabels := metrics.NewProcessLabels(
		consts.ExampleNamespace, consts.ExampleWorkload, consts.ExamplePod, consts.ExampleBinary, consts.ExampleNodeName,
	)
	SocketStatsUDPMulticastTxBytes.WithLabelValues(multicastLabels).Add(0)
	SocketStatsUDPMulticastTxSegs.WithLabelValues(multicastLabels).Add(0)
	SocketStatsUDPMulticastRxBytes.WithLabelValues(multicastLabels).Add(0)
	SocketStatsUDPMulticastRxSegs.WithLabelValues(multicastLabels).Add(0)
	SocketStatsUDPMulticastDrops.WithLabelValues(multicastLabels).Add(0)
	SocketStatsUDPMulticastConsumeMisses.WithLabelValues(multicastLabels).Add(0)
	SocketStatsUDPSeqCheckErrors.WithLabelValues(udpSeqCheckLabels).Add(0)
}

func InitRawSocketEventsMetrics(registry *prometheus.Registry) {
	// Raw socket metrics
	registry.MustRegister(RawsockCreateVol)
	registry.MustRegister(RawsockCloseVol)
}

func InitRawSocketEventsMetricsForDocs(registry *prometheus.Registry) {
	InitRawSocketEventsMetrics(registry)

	srcSocketLabels := metrics.NewProcessLabels(
		consts.ExampleNamespace, consts.ExampleWorkload, consts.ExamplePod, consts.ExampleBinary, consts.ExampleNodeName,
	)

	RawsockCreateVol.WithLabelValues(srcSocketLabels).Add(0)
	RawsockCloseVol.WithLabelValues(srcSocketLabels).Add(0)
}
