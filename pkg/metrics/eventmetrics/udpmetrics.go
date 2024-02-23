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
	"net"
	"strconv"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
	"github.com/isovalent/hubble-fgs/pkg/sensors/udp/udpconfig"
)

func postUDPSocketStats(l *SocketLabels, s *tetragon.SocketStats) {
	labels := l.LabelString()

	c := float64(s.BytesSubmitted)
	socketmetrics.SocketStatsUDPTxBytes.WithLabelValues(labels...).Add(c)
	c = float64(s.SegsSubmitted)
	socketmetrics.SocketStatsUDPTxSegs.WithLabelValues(labels...).Add(c)

	c = float64(s.BytesConsumed)
	socketmetrics.SocketStatsUDPRxBytes.WithLabelValues(labels...).Add(c)
	c = float64(s.SegsConsumed)
	socketmetrics.SocketStatsUDPRxSegs.WithLabelValues(labels...).Add(c)

	c = float64(s.BytesSent)
	socketmetrics.SocketStatsUDPStackTxBytes.WithLabelValues(labels...).Add(c)
	c = float64(s.SegsOut)
	socketmetrics.SocketStatsUDPStackTxSegs.WithLabelValues(labels...).Add(c)

	c = float64(s.BytesReceived)
	socketmetrics.SocketStatsUDPStackRxBytes.WithLabelValues(labels...).Add(c)
	c = float64(s.SegsIn)
	socketmetrics.SocketStatsUDPStackRxSegs.WithLabelValues(labels...).Add(c)

	c = float64(s.SkDrop)
	socketmetrics.SocketStatsUDPDrops.WithLabelValues(labels...).Add(c)

	c = float64(s.SkbConsumeMisses)
	socketmetrics.SocketStatsUDPConsumeMisses.WithLabelValues(labels...).Add(c)

	// Post UDP Latency numbers
	// Prometheus buckets are cumulative, so we keep adding the values for higher buckets.
	// Bucket values in ProtocolConfig are lower limits, while metrics need upper limits as
	// "le" label value, so we always use (N+1)th bucket for that.
	if s.Latency != nil && s.Latency.Buckets != nil {
		bucketLabels := append(labels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket01)))
		c = float64(s.Latency.Buckets[0].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(bucketLabels...).Add(c)

		bucketLabels = append(labels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket10)))
		c += float64(s.Latency.Buckets[1].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(bucketLabels...).Add(c)

		bucketLabels = append(labels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket25)))
		c += float64(s.Latency.Buckets[2].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(bucketLabels...).Add(c)

		bucketLabels = append(labels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket50)))
		c += float64(s.Latency.Buckets[3].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(bucketLabels...).Add(c)

		bucketLabels = append(labels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket75)))
		c += float64(s.Latency.Buckets[4].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(bucketLabels...).Add(c)

		bucketLabels = append(labels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket90)))
		c += float64(s.Latency.Buckets[5].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(bucketLabels...).Add(c)

		bucketLabels = append(labels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket99)))
		c += float64(s.Latency.Buckets[6].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(bucketLabels...).Add(c)

		bucketLabels = append(labels, "+Inf")
		c += float64(s.Latency.Buckets[7].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(bucketLabels...).Add(c)
		socketmetrics.UdpLatencyCount.WithLabelValues(labels...).Add(c)
		socketmetrics.UdpLatencySum.WithLabelValues(labels...).Add(float64(s.Latency.Sum))
	}
}

func postUDPMulticastSocketStats(res *tetragon.ProcessSockStats) {
	sip := net.ParseIP(res.Socket.SourceIp)
	dip := net.ParseIP(res.Socket.DestinationIp)

	if !sip.IsMulticast() && !dip.IsMulticast() {
		return
	}

	s := res.Stats
	multicastLabels := createMulticastSocketLabels(res)
	m := multicastLabels.labelString()

	c := float64(s.BytesSubmitted)
	socketmetrics.SocketStatsUDPMulticastTxBytes.WithLabelValues(m...).Add(c)

	c = float64(s.SegsSubmitted)
	socketmetrics.SocketStatsUDPMulticastTxSegs.WithLabelValues(m...).Add(c)

	c = float64(s.BytesConsumed)
	socketmetrics.SocketStatsUDPMulticastRxBytes.WithLabelValues(m...).Add(c)

	c = float64(s.SegsConsumed)
	socketmetrics.SocketStatsUDPMulticastRxSegs.WithLabelValues(m...).Add(c)

	c = float64(s.SkDrop)
	socketmetrics.SocketStatsUDPMulticastDrops.WithLabelValues(m...).Add(c)

	c = float64(s.SkbConsumeMisses)
	socketmetrics.SocketStatsUDPMulticastConsumeMisses.WithLabelValues(m...).Add(c)

	// Post UDP Multicast Latency numbers
	// Prometheus buckets are cumulative, so we keep adding the values for higher buckets.
	// Bucket values in ProtocolConfig are lower limits, while metrics need upper limits as
	// "le" label value, so we always use (N+1)th bucket for that.
	if s.Latency != nil && s.Latency.Buckets != nil {
		mBucket := append(m, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket01)))
		c = float64(s.Latency.Buckets[0].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(mBucket...).Add(c)

		mBucket = append(m, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket10)))
		c += float64(s.Latency.Buckets[1].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(mBucket...).Add(c)

		mBucket = append(m, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket25)))
		c += float64(s.Latency.Buckets[2].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(mBucket...).Add(c)

		mBucket = append(m, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket50)))
		c += float64(s.Latency.Buckets[3].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(mBucket...).Add(c)

		mBucket = append(m, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket75)))
		c += float64(s.Latency.Buckets[4].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(mBucket...).Add(c)

		mBucket = append(m, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket90)))
		c += float64(s.Latency.Buckets[5].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(mBucket...).Add(c)

		mBucket = append(m, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket99)))
		c += float64(s.Latency.Buckets[6].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(mBucket...).Add(c)

		mBucket = append(m, "+Inf")
		c += float64(s.Latency.Buckets[7].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(mBucket...).Add(c)
		socketmetrics.UdpMulticastLatencyCount.WithLabelValues(m...).Add(c)
		socketmetrics.UdpMulticastLatencySum.WithLabelValues(m...).Add(float64(s.Latency.Sum))
	}
}
