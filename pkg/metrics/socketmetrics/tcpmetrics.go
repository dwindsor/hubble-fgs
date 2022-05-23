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
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// TCP socket metrics
var (
	SocketStatsTxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_txbytes",
		Help: "TCP socket TX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsTxSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_txsegs",
		Help: "TCP socket TX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsTxBursts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_txbursts",
		Help: "TCP socket TX bursts statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsRxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_rxbytes",
		Help: "TCP socket RX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsRxSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_rxsegs",
		Help: "TCP socket RX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsRxBursts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_rxbursts",
		Help: "TCP socket RX bursts statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsRetranBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_retransmitbytes",
		Help: "TCP socket retransmit bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsRetranSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_retransmitsegs",
		Help: "TCP socket retransmit seg statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsZeroWindow = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_zerowindow",
		Help: "TCP socket zero window events",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsSrtt = promauto.NewSummaryVec(prometheus.SummaryOpts{
		Name:       consts.MetricNamePrefix + "socket_stats_srtt",
		Help:       "TCP socket smoothed RTT latency distribution.",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsDrops = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_drops",
		Help: "TCP socket socket drops statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
)
