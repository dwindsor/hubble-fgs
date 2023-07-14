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
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Interface metrics
var (
	InterfaceBytesSent = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "interface_txbytes",
		Namespace: consts.MetricsNamespace,
		Help:      "Bytes sent per network interface",
	}, []string{"name", "namespace", "pod"})
	InterfaceBytesReceived = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "interface_rxbytes",
		Namespace: consts.MetricsNamespace,
		Help:      "Bytes received per network interface",
	}, []string{"name", "namespace", "pod"})
	InterfaceSegmentsSent = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "interface_txsegs",
		Namespace: consts.MetricsNamespace,
		Help:      "Segments sent per network interface",
	}, []string{"name", "namespace", "pod"})
	InterfaceSegmentsReceived = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "interface_rxsegs",
		Namespace: consts.MetricsNamespace,
		Help:      "Segments received per network interface",
	}, []string{"name", "namespace", "pod"})
	InterfaceTxErrors = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "interface_txerrors",
		Namespace: consts.MetricsNamespace,
		Help:      "TX errors per network interface",
	}, []string{"name", "namespace", "pod"})
	InterfaceRxErrors = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "interface_rxerrors",
		Namespace: consts.MetricsNamespace,
		Help:      "RX errors per network interface",
	}, []string{"name", "namespace", "pod"})
	InterfaceTxDrops = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "interface_txdrops",
		Namespace: consts.MetricsNamespace,
		Help:      "TX drops per network interface",
	}, []string{"name", "namespace", "pod"})
	InterfaceRxDrops = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "interface_rxdrops",
		Namespace: consts.MetricsNamespace,
		Help:      "RX drops per network interface",
	}, []string{"name", "namespace", "pod"})
)

// Interface QLen Histogram
// It emulates an OpenMetrics gauge histogram:
//   - a set of "_bucket"-suffixed gauges with a "le" label (less or equal), which is the upper
//     limit of the bucket
//   - a "_gcount" metric, identical to the highest ("+Inf") bucket metric
//   - a "_gsum" metric, reporting the sum of all observed values
var (
	InterfaceQlenBucket = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "interface_qlen_bucket",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram bucket for the number of enqued packets",
	}, []string{"name", "namespace", "pod", "le"})
	InterfaceQlenCount = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "interface_qlen_gcount",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram count for the number of enqued packets",
	}, []string{"name", "namespace", "pod"})
	InterfaceQlenSum = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "interface_qlen_gsum",
		Namespace: consts.MetricsNamespace,
		Help:      "Histogram sum for the number of enqued packets",
	}, []string{"name", "namespace", "pod"})
)
