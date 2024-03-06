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
	"slices"

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

	// TCP Latency Histograms
	registry.MustRegister(TcpLatencyBucket)
	registry.MustRegister(TcpLatencyCount)
	registry.MustRegister(TcpLatencySum)
}

func InitTCPEventsMetricsForDocs(registry *prometheus.Registry) {
	InitTCPEventsMetrics(registry)

	labels := slices.Concat(consts.ExampleProcessLabels, enterpriseMetrics.ExampleDstLabels)

	SocketStatsTxBytes.WithLabelValues(labels...).Add(0)
	SocketStatsTxSegs.WithLabelValues(labels...).Add(0)
	SocketStatsRxBytes.WithLabelValues(labels...).Add(0)
	SocketStatsRxSegs.WithLabelValues(labels...).Add(0)
	SocketStatsRetranBytes.WithLabelValues(labels...).Add(0)
	SocketStatsRetranSegs.WithLabelValues(labels...).Add(0)
	SocketStatsZeroWindow.WithLabelValues(labels...).Add(0)
	SocketStatsDrops.WithLabelValues(labels...).Add(0)
	SocketStatsSrtt.WithLabelValues(labels...)

	// Watermarks
	SocketStatsTxBursts.WithLabelValues(consts.ExampleProcessLabels...).Add(0)
	SocketStatsTxDips.WithLabelValues(consts.ExampleProcessLabels...).Add(0)
	SocketStatsRxBursts.WithLabelValues(consts.ExampleProcessLabels...).Add(0)
	SocketStatsRxDips.WithLabelValues(consts.ExampleProcessLabels...).Add(0)
	SocketStatsTxWatermarksState.WithLabelValues(consts.ExampleProcessLabels...).Add(0)
	SocketStatsRxWatermarksState.WithLabelValues(consts.ExampleProcessLabels...).Add(0)

	// Histograms. They are defined not with Prometheus histogram struct, but as sets of counters.
	// This means they are rendered differently than "regular" histograms in the metrics docs.
	// We might consider improving docs for histograms, both Prometheus and Tetragon.
	for _, b := range enterpriseMetrics.ExampleLatencyBuckets {
		bucketLabels := append(labels, b)
		TcpRttBucket.WithLabelValues(bucketLabels...).Add(0)
		TcpLatencyBucket.WithLabelValues(bucketLabels...).Add(0)
	}
	TcpRttCount.WithLabelValues(labels...).Add(0)
	TcpRttSum.WithLabelValues(labels...).Add(0)
	TcpLatencyCount.WithLabelValues(labels...).Add(0)
	TcpLatencySum.WithLabelValues(labels...).Add(0)
}

func InitUDPHealthMetrics(registry *prometheus.Registry) {
	// UDP metrics collection errors
	registry.MustRegister(SocketStatsUDPGC)

	for _, er := range UDPGCTypeStrings {
		SocketStatsUDPGC.WithLabelValues(er).Add(0)
	}

	// NOTES:
	// * Rename count label (to e.g. error)?
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

	// UDP Latency Histogram
	registry.MustRegister(UdpLatencyBucket)
	registry.MustRegister(UdpLatencyCount)
	registry.MustRegister(UdpLatencySum)

	// UDP Multicast Latency Histogram
	registry.MustRegister(UdpMulticastLatencyBucket)
	registry.MustRegister(UdpMulticastLatencyCount)
	registry.MustRegister(UdpMulticastLatencySum)
}

func InitRawSocketEventsMetrics(registry *prometheus.Registry) {
	// Raw socket metrics
	registry.MustRegister(RawsockCreateVol)
	registry.MustRegister(RawsockCloseVol)
}
