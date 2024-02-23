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
	"github.com/isovalent/hubble-fgs/pkg/sensors/tcp/tcpconfig"
)

func postTCPSocketStats(l *socketLabels, s *tetragon.SocketStats) {
	labelStrings := l.labelString()

	c := float64(s.BytesSent)
	socketmetrics.SocketStatsTxBytes.WithLabelValues(labelStrings...).Add(c)
	c = float64(s.SegsOut)
	socketmetrics.SocketStatsTxSegs.WithLabelValues(labelStrings...).Add(c)

	c = float64(s.BytesReceived)
	socketmetrics.SocketStatsRxBytes.WithLabelValues(labelStrings...).Add(c)
	c = float64(s.SegsIn)
	socketmetrics.SocketStatsRxSegs.WithLabelValues(labelStrings...).Add(c)

	c = float64(s.RetransmitsBytes)
	socketmetrics.SocketStatsRetranBytes.WithLabelValues(labelStrings...).Add(c)
	c = float64(s.RetransmitsSegs)
	socketmetrics.SocketStatsRetranSegs.WithLabelValues(labelStrings...).Add(c)

	c = float64(s.ToZeroWindow)
	socketmetrics.SocketStatsZeroWindow.WithLabelValues(labelStrings...).Add(c)

	c = float64(s.Srtt)
	socketmetrics.SocketStatsSrtt.WithLabelValues(labelStrings...).Observe(c)

	c = float64(s.SkDrop)
	socketmetrics.SocketStatsDrops.WithLabelValues(labelStrings...).Add(c)

	// Post TCP Latency numbers
	// Prometheus buckets are cumulative, so we keep adding the values for higher buckets.
	// Bucket values in ProtocolConfig are lower limits, while metrics need upper limits as
	// "le" label value, so we always use (N+1)th bucket for that.
	if s.Rtt != nil && s.Rtt.Buckets != nil {
		b := append(labelStrings, getTcpRttPromBucket(1))
		c = float64(s.Rtt.Buckets[0].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(b...).Add(c)

		b = append(labelStrings, getTcpRttPromBucket(10))
		c += float64(s.Rtt.Buckets[1].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(b...).Add(c)

		b = append(labelStrings, getTcpRttPromBucket(25))
		c += float64(s.Rtt.Buckets[2].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(b...).Add(c)

		b = append(labelStrings, getTcpRttPromBucket(50))
		c += float64(s.Rtt.Buckets[3].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(b...).Add(c)

		b = append(labelStrings, getTcpRttPromBucket(75))
		c += float64(s.Rtt.Buckets[4].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(b...).Add(c)

		b = append(labelStrings, getTcpRttPromBucket(90))
		c += float64(s.Rtt.Buckets[5].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(b...).Add(c)

		b = append(labelStrings, getTcpRttPromBucket(99))
		c += float64(s.Rtt.Buckets[6].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(b...).Add(c)

		b = append(labelStrings, getTcpRttPromBucket(100))
		c += float64(s.Rtt.Buckets[7].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(b...).Add(c)

		socketmetrics.TcpRttCount.WithLabelValues(labelStrings...).Add(c)
		socketmetrics.TcpRttSum.WithLabelValues(labelStrings...).Add(float64(s.Rtt.Sum))
	}

	if s.Latency != nil && s.Latency.Buckets != nil {
		b := append(labelStrings, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket01)))
		c = float64(s.Latency.Buckets[0].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(b...).Add(c)

		b = append(labelStrings, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket01)))
		c += float64(s.Latency.Buckets[1].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(b...).Add(c)

		b = append(labelStrings, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket01)))
		c += float64(s.Latency.Buckets[2].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(b...).Add(c)

		b = append(labelStrings, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket01)))
		c += float64(s.Latency.Buckets[3].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(b...).Add(c)

		b = append(labelStrings, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket01)))
		c += float64(s.Latency.Buckets[4].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(b...).Add(c)

		b = append(labelStrings, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket01)))
		c += float64(s.Latency.Buckets[5].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(b...).Add(c)

		b = append(labelStrings, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket01)))
		c += float64(s.Latency.Buckets[6].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(b...).Add(c)

		b = append(labelStrings, "+Inf")
		c += float64(s.Latency.Buckets[7].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(b...).Add(c)
		socketmetrics.TcpLatencyCount.WithLabelValues(labelStrings...).Add(c)
		socketmetrics.TcpLatencySum.WithLabelValues(labelStrings...).Add(float64(s.Latency.Sum))
	}
}
