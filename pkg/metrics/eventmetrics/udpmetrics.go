// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package eventmetrics

import (
	"net"
	"strconv"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/udpconfig"
)

func postUDPSocketStats(socketLabels *socketmetrics.SocketLabels, s *tetragon.SocketStats) {
	c := float64(s.BytesSubmitted)
	socketmetrics.SocketStatsUDPTxBytes.WithLabelValues(socketLabels).Add(c)
	c = float64(s.SegsSubmitted)
	socketmetrics.SocketStatsUDPTxSegs.WithLabelValues(socketLabels).Add(c)

	c = float64(s.BytesConsumed)
	socketmetrics.SocketStatsUDPRxBytes.WithLabelValues(socketLabels).Add(c)
	c = float64(s.SegsConsumed)
	socketmetrics.SocketStatsUDPRxSegs.WithLabelValues(socketLabels).Add(c)

	c = float64(s.BytesSent)
	socketmetrics.SocketStatsUDPStackTxBytes.WithLabelValues(socketLabels).Add(c)
	c = float64(s.SegsOut)
	socketmetrics.SocketStatsUDPStackTxSegs.WithLabelValues(socketLabels).Add(c)

	c = float64(s.BytesReceived)
	socketmetrics.SocketStatsUDPStackRxBytes.WithLabelValues(socketLabels).Add(c)
	c = float64(s.SegsIn)
	socketmetrics.SocketStatsUDPStackRxSegs.WithLabelValues(socketLabels).Add(c)

	c = float64(s.SkDrop)
	socketmetrics.SocketStatsUDPDrops.WithLabelValues(socketLabels).Add(c)

	// Post UDP Latency numbers
	// Prometheus buckets are cumulative, so we keep adding the values for higher buckets.
	// Bucket values in ProtocolConfig are lower limits, while metrics need upper limits as
	// "le" label value, so we always use (N+1)th bucket for that.
	if s.Latency != nil && s.Latency.Buckets != nil {
		c = float64(s.Latency.Buckets[0].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(socketLabels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket01))).Add(c)

		c += float64(s.Latency.Buckets[1].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(socketLabels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket10))).Add(c)

		c += float64(s.Latency.Buckets[2].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(socketLabels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket25))).Add(c)

		c += float64(s.Latency.Buckets[3].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(socketLabels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket50))).Add(c)

		c += float64(s.Latency.Buckets[4].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(socketLabels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket75))).Add(c)

		c += float64(s.Latency.Buckets[5].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(socketLabels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket90))).Add(c)

		c += float64(s.Latency.Buckets[6].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(socketLabels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket99))).Add(c)

		c += float64(s.Latency.Buckets[7].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(socketLabels, "+Inf").Add(c)
		socketmetrics.UdpLatencyCount.WithLabelValues(socketLabels).Add(c)
		socketmetrics.UdpLatencySum.WithLabelValues(socketLabels).Add(float64(s.Latency.Sum))
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

	c := float64(s.BytesSubmitted)
	socketmetrics.SocketStatsUDPMulticastTxBytes.WithLabelValues(multicastLabels).Add(c)

	c = float64(s.SegsSubmitted)
	socketmetrics.SocketStatsUDPMulticastTxSegs.WithLabelValues(multicastLabels).Add(c)

	c = float64(s.BytesConsumed)
	socketmetrics.SocketStatsUDPMulticastRxBytes.WithLabelValues(multicastLabels).Add(c)

	c = float64(s.SegsConsumed)
	socketmetrics.SocketStatsUDPMulticastRxSegs.WithLabelValues(multicastLabels).Add(c)

	c = float64(s.SkDrop)
	socketmetrics.SocketStatsUDPMulticastDrops.WithLabelValues(multicastLabels).Add(c)

	// Post UDP Multicast Latency numbers
	// Prometheus buckets are cumulative, so we keep adding the values for higher buckets.
	// Bucket values in ProtocolConfig are lower limits, while metrics need upper limits as
	// "le" label value, so we always use (N+1)th bucket for that.
	if s.Latency != nil && s.Latency.Buckets != nil {
		c = float64(s.Latency.Buckets[0].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(multicastLabels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket01))).Add(c)

		c += float64(s.Latency.Buckets[1].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(multicastLabels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket10))).Add(c)

		c += float64(s.Latency.Buckets[2].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(multicastLabels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket25))).Add(c)

		c += float64(s.Latency.Buckets[3].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(multicastLabels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket50))).Add(c)

		c += float64(s.Latency.Buckets[4].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(multicastLabels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket75))).Add(c)

		c += float64(s.Latency.Buckets[5].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(multicastLabels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket90))).Add(c)

		c += float64(s.Latency.Buckets[6].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(multicastLabels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket99))).Add(c)

		c += float64(s.Latency.Buckets[7].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(multicastLabels, "+Inf").Add(c)
		socketmetrics.UdpMulticastLatencyCount.WithLabelValues(multicastLabels).Add(c)
		socketmetrics.UdpMulticastLatencySum.WithLabelValues(multicastLabels).Add(float64(s.Latency.Sum))
	}
}
