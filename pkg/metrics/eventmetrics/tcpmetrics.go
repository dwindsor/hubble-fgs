//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package eventmetrics

import (
	"strconv"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/tcpconfig"
)

func postTCPSocketStats(socketLabels *socketmetrics.SocketLabels, s *tetragon.SocketStats) {
	c := float64(s.BytesSent)
	socketmetrics.SocketStatsTxBytes.WithLabelValues(socketLabels).Add(c)
	c = float64(s.SegsOut)
	socketmetrics.SocketStatsTxSegs.WithLabelValues(socketLabels).Add(c)

	c = float64(s.BytesReceived)
	socketmetrics.SocketStatsRxBytes.WithLabelValues(socketLabels).Add(c)
	c = float64(s.SegsIn)
	socketmetrics.SocketStatsRxSegs.WithLabelValues(socketLabels).Add(c)

	c = float64(s.RetransmitsBytes)
	socketmetrics.SocketStatsRetranBytes.WithLabelValues(socketLabels).Add(c)
	c = float64(s.RetransmitsSegs)
	socketmetrics.SocketStatsRetranSegs.WithLabelValues(socketLabels).Add(c)

	c = float64(s.ToZeroWindow)
	socketmetrics.SocketStatsZeroWindow.WithLabelValues(socketLabels).Add(c)

	c = float64(s.Srtt)
	socketmetrics.SocketStatsSrtt.WithLabelValues(socketLabels).Observe(c)

	c = float64(s.SkDrop)
	socketmetrics.SocketStatsDrops.WithLabelValues(socketLabels).Add(c)

	// Post TCP Latency numbers
	// Prometheus buckets are cumulative, so we keep adding the values for higher buckets.
	// Bucket values in ProtocolConfig are lower limits, while metrics need upper limits as
	// "le" label value, so we always use (N+1)th bucket for that.
	if s.Rtt != nil && s.Rtt.Buckets != nil {
		c = float64(s.Rtt.Buckets[0].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(socketLabels, getTcpRttPromBucket(1)).Add(c)

		c += float64(s.Rtt.Buckets[1].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(socketLabels, getTcpRttPromBucket(10)).Add(c)

		c += float64(s.Rtt.Buckets[2].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(socketLabels, getTcpRttPromBucket(25)).Add(c)

		c += float64(s.Rtt.Buckets[3].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(socketLabels, getTcpRttPromBucket(50)).Add(c)

		c += float64(s.Rtt.Buckets[4].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(socketLabels, getTcpRttPromBucket(75)).Add(c)

		c += float64(s.Rtt.Buckets[5].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(socketLabels, getTcpRttPromBucket(90)).Add(c)

		c += float64(s.Rtt.Buckets[6].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(socketLabels, getTcpRttPromBucket(99)).Add(c)

		c += float64(s.Rtt.Buckets[7].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(socketLabels, getTcpRttPromBucket(100)).Add(c)

		socketmetrics.TcpRttCount.WithLabelValues(socketLabels).Add(c)
		socketmetrics.TcpRttSum.WithLabelValues(socketLabels).Add(float64(s.Rtt.Sum))
	}

	if s.Latency != nil && s.Latency.Buckets != nil {
		c = float64(s.Latency.Buckets[0].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(socketLabels, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket01))).Add(c)

		c += float64(s.Latency.Buckets[1].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(socketLabels, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket10))).Add(c)

		c += float64(s.Latency.Buckets[2].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(socketLabels, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket25))).Add(c)

		c += float64(s.Latency.Buckets[3].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(socketLabels, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket50))).Add(c)

		c += float64(s.Latency.Buckets[4].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(socketLabels, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket75))).Add(c)

		c += float64(s.Latency.Buckets[5].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(socketLabels, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket90))).Add(c)

		c += float64(s.Latency.Buckets[6].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(socketLabels, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket99))).Add(c)

		c += float64(s.Latency.Buckets[7].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(socketLabels, "+Inf").Add(c)
		socketmetrics.TcpLatencyCount.WithLabelValues(socketLabels).Add(c)
		socketmetrics.TcpLatencySum.WithLabelValues(socketLabels).Add(float64(s.Latency.Sum))
	}
}
