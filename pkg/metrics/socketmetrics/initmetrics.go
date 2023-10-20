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

import "github.com/prometheus/client_golang/prometheus"

func InitMetrics(registry *prometheus.Registry) {
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

	// UDP metrics collection errors
	registry.MustRegister(SocketStatsUDPGC)

	// UDP Latency Histogram
	registry.MustRegister(UdpLatencyBucket)
	registry.MustRegister(UdpLatencyCount)
	registry.MustRegister(UdpLatencySum)

	// UDP Multicast Latency Histogram
	registry.MustRegister(UdpMulticastLatencyBucket)
	registry.MustRegister(UdpMulticastLatencyCount)
	registry.MustRegister(UdpMulticastLatencySum)

	// Raw socket metrics
	registry.MustRegister(RawsockCreateVol)
	registry.MustRegister(RawsockCloseVol)
}
