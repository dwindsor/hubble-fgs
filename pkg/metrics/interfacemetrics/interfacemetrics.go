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

// TCP socket metrics
var (
	InterfaceBytesSent = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_txbytes",
		Help: "Bytes sent per network interface",
	}, []string{"name", "netns"})
	InterfaceBytesReceived = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_rxbytes",
		Help: "Bytes received per network interface",
	}, []string{"name", "netns"})
	InterfaceSegmentsSent = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_txsegs",
		Help: "Segments sent per network interface",
	}, []string{"name", "netns"})
	InterfaceSegmentsReceived = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_rxsegs",
		Help: "Segments received per network interface",
	}, []string{"name", "netns"})
	InterfaceTxErrors = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_txerrors",
		Help: "TX errors per network interface",
	}, []string{"name", "netns"})
	InterfaceRxErrors = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_rxerrors",
		Help: "RX errors per network interface",
	}, []string{"name", "netns"})
	InterfaceTxDrops = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_txdrops",
		Help: "TX drops per network interface",
	}, []string{"name", "netns"})
	InterfaceRxDrops = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: consts.MetricNamePrefix + "interface_rxdrops",
		Help: "RX drops per network interface",
	}, []string{"name", "netns"})
)
