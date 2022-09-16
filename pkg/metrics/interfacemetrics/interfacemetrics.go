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
		Name: consts.MetricNamePrefix + "interface_txbytes",
		Help: "Bytes sent per network interface",
	}, []string{"name", "namespace", "pod"})
	InterfaceBytesReceived = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_rxbytes",
		Help: "Bytes received per network interface",
	}, []string{"name", "namespace", "pod"})
	InterfaceSegmentsSent = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_txsegs",
		Help: "Segments sent per network interface",
	}, []string{"name", "namespace", "pod"})
	InterfaceSegmentsReceived = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_rxsegs",
		Help: "Segments received per network interface",
	}, []string{"name", "namespace", "pod"})
	InterfaceTxErrors = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_txerrors",
		Help: "TX errors per network interface",
	}, []string{"name", "namespace", "pod"})
	InterfaceRxErrors = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_rxerrors",
		Help: "RX errors per network interface",
	}, []string{"name", "namespace", "pod"})
	InterfaceTxDrops = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_txdrops",
		Help: "TX drops per network interface",
	}, []string{"name", "namespace", "pod"})
	InterfaceRxDrops = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_rxdrops",
		Help: "RX drops per network interface",
	}, []string{"name", "namespace", "pod"})
)

var (
	InterfaceQlen99 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_qlen99",
		Help: "The number of packets enqueued at 99th percentile queue length",
	}, []string{"name", "namespace", "pod"})
	InterfaceQlen90 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_qlen90",
		Help: "The number of packets enqueued at 90th percentile queue length",
	}, []string{"name", "namespace", "pod"})
	InterfaceQlen75 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_qlen75",
		Help: "The number of packets enqueued at 75th percentile queue length",
	}, []string{"name", "namespace", "pod"})
	InterfaceQlen50 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_qlen50",
		Help: "The number of packets enqueued at 50th percentile queue length",
	}, []string{"name", "namespace", "pod"})
	InterfaceQlen25 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_qlen25",
		Help: "The number of packets enqueued at 25th percentile queue length",
	}, []string{"name", "namespace", "pod"})
	InterfaceQlen10 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_qlen10",
		Help: "The number of packets enqueued at 10th percentile queue length",
	}, []string{"name", "namespace", "pod"})
	InterfaceQlen01 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_qlen01",
		Help: "The number of packets enqueued at 1st percentile queue length",
	}, []string{"name", "namespace", "pod"})
	InterfaceQlen00 = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_qlen00",
		Help: "The number of packets enqueued at 1st percentile queue length",
	}, []string{"name", "namespace", "pod"})
)
