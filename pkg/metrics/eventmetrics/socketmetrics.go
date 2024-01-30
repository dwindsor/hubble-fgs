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
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	oss "github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
	"github.com/isovalent/hubble-fgs/pkg/sensors/tcp/tcpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/udp/udpconfig"
)

func postUDPSocketStats(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels string, s *tetragon.SocketStats) {
	c := float64(s.BytesSubmitted)
	socketmetrics.SocketStatsUDPTxBytes.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(c)
	c = float64(s.SegsSubmitted)
	socketmetrics.SocketStatsUDPTxSegs.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(c)

	c = float64(s.BytesConsumed)
	socketmetrics.SocketStatsUDPRxBytes.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(c)
	c = float64(s.SegsConsumed)
	socketmetrics.SocketStatsUDPRxSegs.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(c)

	c = float64(s.BytesSent)
	socketmetrics.SocketStatsUDPStackTxBytes.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(c)
	c = float64(s.SegsOut)
	socketmetrics.SocketStatsUDPStackTxSegs.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(c)

	c = float64(s.BytesReceived)
	socketmetrics.SocketStatsUDPStackRxBytes.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(c)
	c = float64(s.SegsIn)
	socketmetrics.SocketStatsUDPStackRxSegs.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(c)

	c = float64(s.SkDrop)
	socketmetrics.SocketStatsUDPDrops.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(c)

	c = float64(s.SkbConsumeMisses)
	socketmetrics.SocketStatsUDPConsumeMisses.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(c)

	// Post UDP Latency numbers
	// Prometheus buckets are cumulative, so we keep adding the values for higher buckets.
	// Bucket values in ProtocolConfig are lower limits, while metrics need upper limits as
	// "le" label value, so we always use (N+1)th bucket for that.
	if s.Latency != nil && s.Latency.Buckets != nil {
		c = float64(s.Latency.Buckets[0].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket01))).Add(c)
		c += float64(s.Latency.Buckets[1].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket10))).Add(c)
		c += float64(s.Latency.Buckets[2].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket25))).Add(c)
		c += float64(s.Latency.Buckets[3].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket50))).Add(c)
		c += float64(s.Latency.Buckets[4].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket75))).Add(c)
		c += float64(s.Latency.Buckets[5].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket90))).Add(c)
		c += float64(s.Latency.Buckets[6].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket99))).Add(c)
		c += float64(s.Latency.Buckets[7].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, "+Inf").Add(c)
		socketmetrics.UdpLatencyCount.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(c)
		socketmetrics.UdpLatencySum.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(float64(s.Latency.Sum))
	}
}

func postUDPMulticastSocketStats(ns, workload, pod, binary, dstns, dstworkload, dstpod, _ string, res *tetragon.ProcessSockStats) {
	source := res.Socket.SourceIp
	sip := net.ParseIP(source)
	dest := res.Socket.DestinationIp
	dip := net.ParseIP(dest)

	s := res.Stats

	if !sip.IsMulticast() && !dip.IsMulticast() {
		return
	}

	c := float64(s.BytesSubmitted)
	socketmetrics.SocketStatsUDPMulticastTxBytes.WithLabelValues(ns, workload, pod, binary, source, dstns, dstworkload, dstpod, dest).Add(c)

	c = float64(s.SegsSubmitted)
	socketmetrics.SocketStatsUDPMulticastTxSegs.WithLabelValues(ns, workload, pod, binary, source, dstns, dstworkload, dstpod, dest).Add(c)

	c = float64(s.BytesConsumed)
	socketmetrics.SocketStatsUDPMulticastRxBytes.WithLabelValues(ns, workload, pod, binary, source, dstns, dstworkload, dstpod, dest).Add(c)

	c = float64(s.SegsConsumed)
	socketmetrics.SocketStatsUDPMulticastRxSegs.WithLabelValues(ns, workload, pod, binary, source, dstns, dstworkload, dstpod, dest).Add(c)

	c = float64(s.SkDrop)
	socketmetrics.SocketStatsUDPMulticastDrops.WithLabelValues(ns, workload, pod, binary, source, dstns, dstworkload, dstpod, dest).Add(c)

	c = float64(s.SkbConsumeMisses)
	socketmetrics.SocketStatsUDPMulticastConsumeMisses.WithLabelValues(ns, workload, pod, binary, source, dstns, dstworkload, dstpod, dest).Add(c)

	// Post UDP Multicast Latency numbers
	// Prometheus buckets are cumulative, so we keep adding the values for higher buckets.
	// Bucket values in ProtocolConfig are lower limits, while metrics need upper limits as
	// "le" label value, so we always use (N+1)th bucket for that.
	if s.Latency != nil && s.Latency.Buckets != nil {
		c = float64(s.Latency.Buckets[0].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(ns, workload, pod, binary, source, dstns, dstworkload, dstpod, dest, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket01))).Add(c)
		c += float64(s.Latency.Buckets[1].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(ns, workload, pod, binary, source, dstns, dstworkload, dstpod, dest, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket10))).Add(c)
		c += float64(s.Latency.Buckets[2].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(ns, workload, pod, binary, source, dstns, dstworkload, dstpod, dest, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket25))).Add(c)
		c += float64(s.Latency.Buckets[3].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(ns, workload, pod, binary, source, dstns, dstworkload, dstpod, dest, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket50))).Add(c)
		c += float64(s.Latency.Buckets[4].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(ns, workload, pod, binary, source, dstns, dstworkload, dstpod, dest, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket75))).Add(c)
		c += float64(s.Latency.Buckets[5].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(ns, workload, pod, binary, source, dstns, dstworkload, dstpod, dest, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket90))).Add(c)
		c += float64(s.Latency.Buckets[6].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(ns, workload, pod, binary, source, dstns, dstworkload, dstpod, dest, strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket99))).Add(c)
		c += float64(s.Latency.Buckets[7].Count)
		socketmetrics.UdpMulticastLatencyBucket.WithLabelValues(ns, workload, pod, binary, source, dstns, dstworkload, dstpod, dest, "+Inf").Add(c)
		socketmetrics.UdpMulticastLatencyCount.WithLabelValues(ns, workload, pod, binary, source, dstns, dstworkload, dstpod, dest).Add(c)
		socketmetrics.UdpMulticastLatencySum.WithLabelValues(ns, workload, pod, binary, source, dstns, dstworkload, dstpod, dest).Add(float64(s.Latency.Sum))
	}
}

func postTCPSocketStats(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels string, s *tetragon.SocketStats) {
	c := float64(s.BytesSent)
	socketmetrics.SocketStatsTxBytes.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(c)
	c = float64(s.SegsOut)
	socketmetrics.SocketStatsTxSegs.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(c)

	c = float64(s.BytesReceived)
	socketmetrics.SocketStatsRxBytes.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(c)
	c = float64(s.SegsIn)
	socketmetrics.SocketStatsRxSegs.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(c)

	c = float64(s.RetransmitsBytes)
	socketmetrics.SocketStatsRetranBytes.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(c)
	c = float64(s.RetransmitsSegs)
	socketmetrics.SocketStatsRetranSegs.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(c)

	c = float64(s.ToZeroWindow)
	socketmetrics.SocketStatsZeroWindow.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(c)

	c = float64(s.Srtt)
	socketmetrics.SocketStatsSrtt.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Observe(c)

	c = float64(s.SkDrop)
	socketmetrics.SocketStatsDrops.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(c)

	// Post TCP Latency numbers
	// Prometheus buckets are cumulative, so we keep adding the values for higher buckets.
	// Bucket values in ProtocolConfig are lower limits, while metrics need upper limits as
	// "le" label value, so we always use (N+1)th bucket for that.
	if s.Rtt != nil && s.Rtt.Buckets != nil {
		c = float64(s.Rtt.Buckets[0].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, getTcpRttPromBucket(1)).Add(c)
		c += float64(s.Rtt.Buckets[1].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, getTcpRttPromBucket(10)).Add(c)
		c += float64(s.Rtt.Buckets[2].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, getTcpRttPromBucket(25)).Add(c)
		c += float64(s.Rtt.Buckets[3].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, getTcpRttPromBucket(50)).Add(c)
		c += float64(s.Rtt.Buckets[4].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, getTcpRttPromBucket(75)).Add(c)
		c += float64(s.Rtt.Buckets[5].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, getTcpRttPromBucket(90)).Add(c)
		c += float64(s.Rtt.Buckets[6].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, getTcpRttPromBucket(99)).Add(c)
		c += float64(s.Rtt.Buckets[7].Count)
		socketmetrics.TcpRttBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, getTcpRttPromBucket(100)).Add(c)
		socketmetrics.TcpRttCount.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(c)
		socketmetrics.TcpRttSum.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(float64(s.Rtt.Sum))
	}
	if s.Latency != nil && s.Latency.Buckets != nil {
		c = float64(s.Latency.Buckets[0].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket01))).Add(c)
		c += float64(s.Latency.Buckets[1].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket10))).Add(c)
		c += float64(s.Latency.Buckets[2].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket25))).Add(c)
		c += float64(s.Latency.Buckets[3].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket50))).Add(c)
		c += float64(s.Latency.Buckets[4].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket75))).Add(c)
		c += float64(s.Latency.Buckets[5].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket90))).Add(c)
		c += float64(s.Latency.Buckets[6].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, strconv.Itoa(int(tcpconfig.LatencyConfig.LatBucket99))).Add(c)
		c += float64(s.Latency.Buckets[7].Count)
		socketmetrics.TcpLatencyBucket.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, "+Inf").Add(c)
		socketmetrics.TcpLatencyCount.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(c)
		socketmetrics.TcpLatencySum.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Add(float64(s.Latency.Sum))
	}
}

func GetPromBucket(min, max, upperLimitPercent uint32) string {
	if upperLimitPercent == 100 {
		return "+Inf"
	}
	return strconv.Itoa(int(min + (max-min)*upperLimitPercent/100))
}

func getTcpRttPromBucket(upperLimitPercent uint32) string {
	return GetPromBucket(tcpconfig.RttHistogramMin, tcpconfig.RttHistogramMax, upperLimitPercent)
}

func GetDstPodInfo(dstPod *tetragon.Pod) (pod, workload, ns string) {
	if dstPod != nil {
		ns = dstPod.Namespace
		workload = dstPod.Workload
		pod = dstPod.Name
	}
	return pod, workload, ns
}

func postStatsEventSocketStats(res *tetragon.ProcessSockStats) {
	binary, pod, workload, ns := oss.GetProcessInfo(res.Process)
	dstPod := res.Socket.GetDestinationPod()
	dstpod, dstworkload, dstns := GetDstPodInfo(dstPod)
	dstLabels := strings.Join(res.Socket.DestinationNames, ",")

	if res.Socket.Protocol == tetragon.SocketProtocol_TCP {
		if tcpconfig.MetricsEnabled {
			postTCPSocketStats(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, res.Stats)
		}
	} else if res.Socket.Protocol == tetragon.SocketProtocol_UDP {
		if udpconfig.MetricsEnabled {
			postUDPSocketStats(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, res.Stats)
			postUDPMulticastSocketStats(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, res)
		}
	}
}

func HandleSocketEvent(res *tetragon.ProcessSockStats) {
	postStatsEventSocketStats(res)
}
