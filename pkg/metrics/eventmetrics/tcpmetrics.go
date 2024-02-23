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

func postTCPSocketStats(l *SocketLabels, s *tetragon.SocketStats) {
	labels := l.LabelString()

	c := float64(s.BytesSent)
	socketmetrics.SocketStatsTxBytes.WithLabelValues(labels...).Add(c)
	c = float64(s.SegsOut)
	socketmetrics.SocketStatsTxSegs.WithLabelValues(labels...).Add(c)

	c = float64(s.BytesReceived)
	socketmetrics.SocketStatsRxBytes.WithLabelValues(labels...).Add(c)
	c = float64(s.SegsIn)
	socketmetrics.SocketStatsRxSegs.WithLabelValues(labels...).Add(c)

	c = float64(s.RetransmitsBytes)
	socketmetrics.SocketStatsRetranBytes.WithLabelValues(labels...).Add(c)
	c = float64(s.RetransmitsSegs)
	socketmetrics.SocketStatsRetranSegs.WithLabelValues(labels...).Add(c)

	c = float64(s.ToZeroWindow)
	socketmetrics.SocketStatsZeroWindow.WithLabelValues(labels...).Add(c)

	c = float64(s.Srtt)
	socketmetrics.SocketStatsSrtt.WithLabelValues(labels...).Observe(c)

	c = float64(s.SkDrop)
	socketmetrics.SocketStatsDrops.WithLabelValues(labels...).Add(c)

	// Post TCP Latency numbers
	// Prometheus buckets are cumulative, so we keep adding the values for higher buckets.
	// Bucket values in ProtocolConfig are lower limits, while metrics need upper limits as
	// "le" label value, so we always use (N+1)th bucket for that.
	if s.Rtt != nil && s.Rtt.Buckets != nil {
		bucketLabels := append(labels, getTcpRttPromBucket(1))
		c = float64(s.Rtt.Buckets[0].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(bucketLabels...).Add(c)

		bucketLabels = append(labels, getTcpRttPromBucket(10))
		c += float64(s.Rtt.Buckets[1].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(bucketLabels...).Add(c)

		bucketLabels = append(labels, getTcpRttPromBucket(25))
		c += float64(s.Rtt.Buckets[2].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(bucketLabels...).Add(c)

		bucketLabels = append(labels, getTcpRttPromBucket(50))
		c += float64(s.Rtt.Buckets[3].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(bucketLabels...).Add(c)

		bucketLabels = append(labels, getTcpRttPromBucket(75))
		c += float64(s.Rtt.Buckets[4].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(bucketLabels...).Add(c)

		bucketLabels = append(labels, getTcpRttPromBucket(90))
		c += float64(s.Rtt.Buckets[5].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(bucketLabels...).Add(c)

		bucketLabels = append(labels, getTcpRttPromBucket(99))
		c += float64(s.Rtt.Buckets[6].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(bucketLabels...).Add(c)

		bucketLabels = append(labels, getTcpRttPromBucket(100))
		c += float64(s.Rtt.Buckets[7].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(bucketLabels...).Add(c)

		socketmetrics.TcpRttCount.WithLabelValues(labels...).Add(c)
		socketmetrics.TcpRttSum.WithLabelValues(labels...).Add(float64(s.Rtt.Sum))
	}

	if s.Latency != nil && s.Latency.Buckets != nil {
		bucketLabels := append(labels, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket01)))
		c = float64(s.Latency.Buckets[0].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(bucketLabels...).Add(c)

		bucketLabels = append(labels, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket10)))
		c += float64(s.Latency.Buckets[1].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(bucketLabels...).Add(c)

		bucketLabels = append(labels, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket25)))
		c += float64(s.Latency.Buckets[2].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(bucketLabels...).Add(c)

		bucketLabels = append(labels, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket50)))
		c += float64(s.Latency.Buckets[3].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(bucketLabels...).Add(c)

		bucketLabels = append(labels, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket75)))
		c += float64(s.Latency.Buckets[4].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(bucketLabels...).Add(c)

		bucketLabels = append(labels, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket90)))
		c += float64(s.Latency.Buckets[5].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(bucketLabels...).Add(c)

		bucketLabels = append(labels, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket99)))
		c += float64(s.Latency.Buckets[6].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(bucketLabels...).Add(c)

		bucketLabels = append(labels, "+Inf")
		c += float64(s.Latency.Buckets[7].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(bucketLabels...).Add(c)
		socketmetrics.TcpLatencyCount.WithLabelValues(labels...).Add(c)
		socketmetrics.TcpLatencySum.WithLabelValues(labels...).Add(float64(s.Latency.Sum))
	}
}
