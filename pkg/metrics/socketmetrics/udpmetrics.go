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

// UDP socket metrics
var (
	SocketStatsUDPTxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_udp_txbytes",
		Help: "UDP socket TX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPTxSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_udp_txsegs",
		Help: "UDP socket TX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPTxBursts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_udp_txbursts",
		Help: "UDP socket TX bursts statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsUDPRxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_udp_rxbytes",
		Help: "UDP socket RX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPRxSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_udp_rxsegs",
		Help: "UDP socket RX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPRxBursts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_udp_rxbursts",
		Help: "UDP socket RX bursts statistics",
	}, []string{"namespace", "pod", "binary"})
	SocketStatsUDPDrops = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_udp_drops",
		Help: "UDP socket drops statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPConsumeMisses = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_udp_consume_misses",
		Help: "UDP socket consume packet misses",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPStackTxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_udp_stack_txbytes",
		Help: "UDP stack TX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPStackTxSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_udp_stack_txsegs",
		Help: "UDP stack TX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPStackRxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_udp_stack_rxbytes",
		Help: "UDP stack RX bytes statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
	SocketStatsUDPStackRxSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_udp_stack_rxsegs",
		Help: "UDP stack RX segment statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns"})
)

// UDP multicast socket metrics
var (
	SocketStatsUDPMulticastTxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_udp_mcast_txbytes",
		Help: "UDP socket TX bytes statistics",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	SocketStatsUDPMulticastTxSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_udp_mcast_txsegs",
		Help: "UDP socket TX segment statistics",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	SocketStatsUDPMulticastRxBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_udp_mcast_rxbytes",
		Help: "UDP socket RX bytes statistics",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	SocketStatsUDPMulticastRxSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_udp_mcast_rxsegs",
		Help: "UDP socket RX segment statistics",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	SocketStatsUDPMulticastDrops = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_udp_mcast_drops",
		Help: "UDP socket drops statistics",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
	SocketStatsUDPMulticastConsumeMisses = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_udp_mcast_consume_misses",
		Help: "UDP socket consume packet misses",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast"})
)

// UDP metrics collection errors
var (
	SocketStatsUDPGC = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "socket_stats_udp_retrieve",
		Help:        "UDP socket retrieval stats. For internal use only.",
		ConstLabels: nil,
	}, []string{"count"})
)

// UDP Latency Histogram
var (
	SocketStatsUdpLatency = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_udp_latency",
		Help: "UDP socket latency bucket counter",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns", "bucket"})
)

// UDP Multicast Latency Histogram
var (
	SocketStatsUdpMulticastLatency = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "socket_stats_udp_mcast_latency",
		Help: "UDP socket latency bucket counter",
	}, []string{"namespace", "pod", "binary", "srcmcast", "dstnamespace", "dstpod", "dstmcast", "bucket"})
)

type UDPGCType int

const (
	UDPGCTypeTicker UDPGCType = iota
	UDPGCTypeFailedToOpenMap
	UDPGCTypeTotalRetrieve
	UDPGCTypePidIsZero
	UDPGCTypeNanoTimeSinceFailure
	UDPGCTypeDiffValuesFailure
)

var UDPGCTypeStrings = map[UDPGCType]string{
	UDPGCTypeTicker:               "Ticker",
	UDPGCTypeFailedToOpenMap:      "Failed To Open Map",
	UDPGCTypeTotalRetrieve:        "Total Retrieved",
	UDPGCTypePidIsZero:            "Pid Is Zero",
	UDPGCTypeNanoTimeSinceFailure: "NanoTimeSince Failure",
	UDPGCTypeDiffValuesFailure:    "DiffValues Failure",
}

// Increment a UDP GC metric for a retrieval type
func UDPGCMetricInc(ty UDPGCType) {
	SocketStatsUDPGC.WithLabelValues(UDPGCTypeStrings[ty]).Inc()
}
