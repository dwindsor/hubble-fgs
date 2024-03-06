//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package interfacemetrics

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

// Interface metrics
var (
	InterfaceBytesSent = metrics.NewGaugeVecWithPod(prometheus.GaugeOpts{
		Name:      "interface_txbytes",
		Namespace: consts.MetricsNamespace,
		Help:      "Bytes sent per network interface",
	}, []string{"name", "namespace", "workload", "pod"})
	InterfaceBytesReceived = metrics.NewGaugeVecWithPod(prometheus.GaugeOpts{
		Name:      "interface_rxbytes",
		Namespace: consts.MetricsNamespace,
		Help:      "Bytes received per network interface",
	}, []string{"name", "namespace", "workload", "pod"})
	InterfaceSegmentsSent = metrics.NewGaugeVecWithPod(prometheus.GaugeOpts{
		Name:      "interface_txsegs",
		Namespace: consts.MetricsNamespace,
		Help:      "Segments sent per network interface",
	}, []string{"name", "namespace", "workload", "pod"})
	InterfaceSegmentsReceived = metrics.NewGaugeVecWithPod(prometheus.GaugeOpts{
		Name:      "interface_rxsegs",
		Namespace: consts.MetricsNamespace,
		Help:      "Segments received per network interface",
	}, []string{"name", "namespace", "workload", "pod"})
	InterfaceTxErrors = metrics.NewGaugeVecWithPod(prometheus.GaugeOpts{
		Name:      "interface_txerrors",
		Namespace: consts.MetricsNamespace,
		Help:      "TX errors per network interface",
	}, []string{"name", "namespace", "workload", "pod"})
	InterfaceRxErrors = metrics.NewGaugeVecWithPod(prometheus.GaugeOpts{
		Name:      "interface_rxerrors",
		Namespace: consts.MetricsNamespace,
		Help:      "RX errors per network interface",
	}, []string{"name", "namespace", "workload", "pod"})
	InterfaceTxDrops = metrics.NewGaugeVecWithPod(prometheus.GaugeOpts{
		Name:      "interface_txdrops",
		Namespace: consts.MetricsNamespace,
		Help:      "TX drops per network interface",
	}, []string{"name", "namespace", "workload", "pod"})
	InterfaceRxDrops = metrics.NewGaugeVecWithPod(prometheus.GaugeOpts{
		Name:      "interface_rxdrops",
		Namespace: consts.MetricsNamespace,
		Help:      "RX drops per network interface",
	}, []string{"name", "namespace", "workload", "pod"})
)

// Interface QLen Histogram
// It emulates an OpenMetrics gauge histogram:
//   - a set of "_bucket"-suffixed gauges with a "le" label (less or equal), which is the upper
//     limit of the bucket
//   - a "_gcount" metric, identical to the highest ("+Inf") bucket metric
//   - a "_gsum" metric, reporting the sum of all observed values
var (
	InterfaceQlenBucket = metrics.NewGaugeVecWithPod(prometheus.GaugeOpts{
		Name:      "interface_qlen_bucket",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram bucket for the number of enqued packets",
	}, []string{"name", "namespace", "workload", "pod", "le"})
	InterfaceQlenCount = metrics.NewGaugeVecWithPod(prometheus.GaugeOpts{
		Name:      "interface_qlen_gcount",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram count for the number of enqued packets",
	}, []string{"name", "namespace", "workload", "pod"})
	InterfaceQlenSum = metrics.NewGaugeVecWithPod(prometheus.GaugeOpts{
		Name:      "interface_qlen_gsum",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram sum for the number of enqued packets",
	}, []string{"name", "namespace", "workload", "pod"})
)

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(InterfaceBytesSent)
	registry.MustRegister(InterfaceBytesReceived)
	registry.MustRegister(InterfaceSegmentsSent)
	registry.MustRegister(InterfaceSegmentsReceived)
	registry.MustRegister(InterfaceTxErrors)
	registry.MustRegister(InterfaceRxErrors)
	registry.MustRegister(InterfaceTxDrops)
	registry.MustRegister(InterfaceRxDrops)
	registry.MustRegister(InterfaceQlenBucket)
	registry.MustRegister(InterfaceQlenCount)
	registry.MustRegister(InterfaceQlenSum)
}

func InitMetricsForDocs(registry *prometheus.Registry) {
	InitMetrics(registry)

	InterfaceBytesSent.WithLabelValues(consts.ExampleProcessLabels...).Add(0)
	InterfaceBytesReceived.WithLabelValues(consts.ExampleProcessLabels...).Add(0)
	InterfaceSegmentsSent.WithLabelValues(consts.ExampleProcessLabels...).Add(0)
	InterfaceSegmentsReceived.WithLabelValues(consts.ExampleProcessLabels...).Add(0)
	InterfaceTxErrors.WithLabelValues(consts.ExampleProcessLabels...).Add(0)
	InterfaceRxErrors.WithLabelValues(consts.ExampleProcessLabels...).Add(0)
	InterfaceTxDrops.WithLabelValues(consts.ExampleProcessLabels...).Add(0)
	InterfaceRxDrops.WithLabelValues(consts.ExampleProcessLabels...).Add(0)

	qlenBuckets := []string{"10", "100", "250", "500", "750", "900", "990", "+Inf"}
	for _, b := range qlenBuckets {
		InterfaceQlenBucket.WithLabelValues(append(consts.ExampleProcessLabels, b)...).Add(0)
	}
	InterfaceQlenCount.WithLabelValues(consts.ExampleProcessLabels...).Add(0)
	InterfaceQlenSum.WithLabelValues(consts.ExampleProcessLabels...).Add(0)
}
