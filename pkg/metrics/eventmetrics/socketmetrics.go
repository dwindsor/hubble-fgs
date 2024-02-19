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
	"github.com/isovalent/hubble-fgs/pkg/sensors/rawsock/rawsockconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/tcp/tcpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/udp/udpconfig"
)

type socketLabels struct {
	ns          string
	workload    string
	pod         string
	binary      string
	dstns       string
	dstWorkload string
	dstPod      string
	dstLabels   string
}

func (s socketLabels) labelString() []string {
	return []string{s.ns, s.workload, s.pod, s.binary, s.dstns, s.dstWorkload, s.dstPod, s.dstLabels}
}

func createTCPSocketLabels(res *tetragon.ProcessSockStats) *socketLabels {
	b, p, w, ns := oss.GetProcessInfo(res.Process)
	dstPod := res.Socket.GetDestinationPod()
	dstPodString, dstWorkload, dstns := GetDstPodInfo(dstPod)
	labels := strings.Join(res.Socket.DestinationNames, ",")

	if !tcpconfig.CurrentLabels["ns"] {
		ns = ""
	}
	if !tcpconfig.CurrentLabels["workload"] {
		w = ""
	}
	if !tcpconfig.CurrentLabels["pod"] {
		p = ""
	}
	if !tcpconfig.CurrentLabels["binary"] {
		b = ""
	}
	if !tcpconfig.CurrentLabels["dstns"] {
		dstns = ""
	}
	if !tcpconfig.CurrentLabels["dstworkload"] {
		dstWorkload = ""
	}
	if !tcpconfig.CurrentLabels["dstpod"] {
		dstPodString = ""
	}
	if !tcpconfig.CurrentLabels["dstlabels"] {
		labels = ""
	}

	return &socketLabels{
		ns:          ns,
		workload:    w,
		pod:         p,
		binary:      b,
		dstns:       dstns,
		dstWorkload: dstWorkload,
		dstPod:      dstPodString,
		dstLabels:   labels,
	}
}

func createUDPSocketLabels(res *tetragon.ProcessSockStats) *socketLabels {
	b, p, w, ns := oss.GetProcessInfo(res.Process)
	dstPod := res.Socket.GetDestinationPod()
	dstPodString, dstWorkload, dstns := GetDstPodInfo(dstPod)
	labels := strings.Join(res.Socket.DestinationNames, ",")

	if !udpconfig.CurrentLabels["ns"] {
		ns = ""
	}
	if !udpconfig.CurrentLabels["workload"] {
		w = ""
	}
	if !udpconfig.CurrentLabels["pod"] {
		p = ""
	}
	if !udpconfig.CurrentLabels["binary"] {
		b = ""
	}
	if !udpconfig.CurrentLabels["dstns"] {
		dstns = ""
	}
	if !udpconfig.CurrentLabels["dstworkload"] {
		dstWorkload = ""
	}
	if !udpconfig.CurrentLabels["dstpod"] {
		dstPodString = ""
	}
	if !udpconfig.CurrentLabels["dstlabels"] {
		labels = ""
	}

	return &socketLabels{
		ns:          ns,
		workload:    w,
		pod:         p,
		binary:      b,
		dstns:       dstns,
		dstWorkload: dstWorkload,
		dstPod:      dstPodString,
		dstLabels:   labels,
	}
}

type multicastSocketLabels struct {
	ns          string
	workload    string
	pod         string
	binary      string
	source      string
	dstns       string
	dstWorkload string
	dstPod      string
	dest        string
}

func createMulticastSocketLabels(res *tetragon.ProcessSockStats) *multicastSocketLabels {
	b, p, w, ns := oss.GetProcessInfo(res.Process)
	dstPod := res.Socket.GetDestinationPod()
	dstPodString, dstWorkload, dstns := GetDstPodInfo(dstPod)
	sourceIP := res.Socket.SourceIp
	dstIP := res.Socket.DestinationIp

	if !udpconfig.CurrentLabels["ns"] {
		ns = ""
	}
	if !udpconfig.CurrentLabels["workload"] {
		w = ""
	}
	if !udpconfig.CurrentLabels["pod"] {
		p = ""
	}
	if !udpconfig.CurrentLabels["binary"] {
		b = ""
	}
	if !udpconfig.CurrentLabels["dstns"] {
		dstns = ""
	}
	if !udpconfig.CurrentLabels["dstworkload"] {
		dstWorkload = ""
	}
	if !udpconfig.CurrentLabels["dstpod"] {
		dstPodString = ""
	}

	return &multicastSocketLabels{
		ns:          ns,
		workload:    w,
		pod:         p,
		binary:      b,
		source:      sourceIP,
		dstns:       dstns,
		dstWorkload: dstWorkload,
		dstPod:      dstPodString,
		dest:        dstIP,
	}
}

func (s multicastSocketLabels) labelString() []string {
	return []string{s.ns, s.workload, s.pod, s.binary, s.source, s.dstns, s.dstWorkload, s.dstPod, s.dest}
}

func postUDPSocketStats(l *socketLabels, s *tetragon.SocketStats) {
	c := float64(s.BytesSubmitted)
	socketmetrics.SocketStatsUDPTxBytes.WithLabelValues(l.labelString()...).Add(c)
	c = float64(s.SegsSubmitted)
	socketmetrics.SocketStatsUDPTxSegs.WithLabelValues(l.labelString()...).Add(c)

	c = float64(s.BytesConsumed)
	socketmetrics.SocketStatsUDPRxBytes.WithLabelValues(l.labelString()...).Add(c)
	c = float64(s.SegsConsumed)
	socketmetrics.SocketStatsUDPRxSegs.WithLabelValues(l.labelString()...).Add(c)

	c = float64(s.BytesSent)
	socketmetrics.SocketStatsUDPStackTxBytes.WithLabelValues(l.labelString()...).Add(c)
	c = float64(s.SegsOut)
	socketmetrics.SocketStatsUDPStackTxSegs.WithLabelValues(l.labelString()...).Add(c)

	c = float64(s.BytesReceived)
	socketmetrics.SocketStatsUDPStackRxBytes.WithLabelValues(l.labelString()...).Add(c)
	c = float64(s.SegsIn)
	socketmetrics.SocketStatsUDPStackRxSegs.WithLabelValues(l.labelString()...).Add(c)

	c = float64(s.SkDrop)
	socketmetrics.SocketStatsUDPDrops.WithLabelValues(l.labelString()...).Add(c)

	c = float64(s.SkbConsumeMisses)
	socketmetrics.SocketStatsUDPConsumeMisses.WithLabelValues(l.labelString()...).Add(c)

	// Post UDP Latency numbers
	// Prometheus buckets are cumulative, so we keep adding the values for higher buckets.
	// Bucket values in ProtocolConfig are lower limits, while metrics need upper limits as
	// "le" label value, so we always use (N+1)th bucket for that.
	if s.Latency != nil && s.Latency.Buckets != nil {
		bstr := append(l.labelString(), strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket01)))
		c = float64(s.Latency.Buckets[0].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(bstr...).Add(c)

		bstr = append(l.labelString(), strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket10)))
		c += float64(s.Latency.Buckets[1].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(bstr...).Add(c)

		bstr = append(l.labelString(), strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket25)))
		c += float64(s.Latency.Buckets[2].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(bstr...).Add(c)

		bstr = append(l.labelString(), strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket50)))
		c += float64(s.Latency.Buckets[3].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(bstr...).Add(c)

		bstr = append(l.labelString(), strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket75)))
		c += float64(s.Latency.Buckets[4].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(bstr...).Add(c)

		bstr = append(l.labelString(), strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket90)))
		c += float64(s.Latency.Buckets[5].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(bstr...).Add(c)

		bstr = append(l.labelString(), strconv.Itoa(int(udpconfig.LatencyConfig.LatBucket99)))
		c += float64(s.Latency.Buckets[6].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(bstr...).Add(c)

		bstr = append(l.labelString(), "+Inf")
		c += float64(s.Latency.Buckets[7].Count)
		socketmetrics.UdpLatencyBucket.WithLabelValues(bstr...).Add(c)
		socketmetrics.UdpLatencyCount.WithLabelValues(l.labelString()...).Add(c)
		socketmetrics.UdpLatencySum.WithLabelValues(l.labelString()...).Add(float64(s.Latency.Sum))
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
	if res.Socket.Protocol == tetragon.SocketProtocol_TCP {
		l := createTCPSocketLabels(res)
		if tcpconfig.MetricsEnabled {
			postTCPSocketStats(l, res.Stats)
		}
	} else if res.Socket.Protocol == tetragon.SocketProtocol_UDP {
		l := createUDPSocketLabels(res)
		if udpconfig.MetricsEnabled {
			postUDPSocketStats(l, res.Stats)
			postUDPMulticastSocketStats(res)
		}
	}
}

func HandleSocketEvent(res *tetragon.ProcessSockStats) {
	postStatsEventSocketStats(res)
}

type srcSocketLabels struct {
	ns       string
	workload string
	pod      string
	binary   string
}

func createTCPSrcSocketLabels(res *tetragon.Process) *srcSocketLabels {
	b, p, w, ns := oss.GetProcessInfo(res)

	if !tcpconfig.CurrentLabels["ns"] {
		ns = ""
	}
	if !tcpconfig.CurrentLabels["workload"] {
		w = ""
	}
	if !tcpconfig.CurrentLabels["pod"] {
		p = ""
	}
	if !tcpconfig.CurrentLabels["binary"] {
		b = ""
	}

	return &srcSocketLabels{
		ns:       ns,
		workload: w,
		pod:      p,
		binary:   b,
	}
}

func createSrcSocketLabels(res *tetragon.Process) *srcSocketLabels {
	b, p, w, ns := oss.GetProcessInfo(res)

	return &srcSocketLabels{
		ns:       ns,
		workload: w,
		pod:      p,
		binary:   b,
	}
}

func (s srcSocketLabels) labelString() []string {
	return []string{s.ns, s.workload, s.pod, s.binary}
}

func HandleRawsockCreateEvent(res *tetragon.ProcessRawsockCreate) {
	if !rawsockconfig.MetricsEnabled {
		return
	}
	l := createSrcSocketLabels(res.Process)
	labelStrings := l.labelString()
	socketmetrics.RawsockCreateVol.WithLabelValues(labelStrings...).Inc()
}

func HandleRawsockCloseEvent(res *tetragon.ProcessRawsockClose) {
	if !rawsockconfig.MetricsEnabled {
		return
	}
	l := createSrcSocketLabels(res.Process)
	labelStrings := l.labelString()
	socketmetrics.RawsockCloseVol.WithLabelValues(labelStrings...).Inc()
}

func postUDPBurstStats(l *srcSocketLabels, s *tetragon.ProcessNetworkBurst) {
	labelStrings := l.labelString()

	if s.Direction == "egress" {
		if s.BurstState == "start" {
			socketmetrics.SocketStatsUDPTxBursts.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(labelStrings...).Set(1)
		} else {
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	} else {
		if s.BurstState == "start" {
			socketmetrics.SocketStatsUDPRxBursts.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(labelStrings...).Set(1)
		} else {
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	}
}

func postTCPBurstStats(l *srcSocketLabels, s *tetragon.ProcessNetworkBurst) {
	labelStrings := l.labelString()

	if s.Direction == "egress" {
		if s.BurstState == "start" {
			socketmetrics.SocketStatsTxBursts.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(labelStrings...).Set(1)
		} else {
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	} else {
		if s.BurstState == "start" {
			socketmetrics.SocketStatsRxBursts.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(labelStrings...).Set(1)
		} else {
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	}
}

func postProcessNetworkBurstEventStats(res *tetragon.ProcessNetworkBurst) {
	switch res.Protocol {
	case tetragon.SocketProtocol_UDP.String():
		l := createSrcSocketLabels(res.Process)
		if udpconfig.MetricsEnabled {
			postUDPBurstStats(l, res)
		}
	case tetragon.SocketProtocol_TCP.String():
		l := createTCPSrcSocketLabels(res.Process)
		if tcpconfig.MetricsEnabled {
			postTCPBurstStats(l, res)
		}
	}
}

func HandleProcessBurstEvent(res *tetragon.ProcessNetworkBurst) {
	postProcessNetworkBurstEventStats(res)
}

func postUDPWatermarksBurstStats(l *srcSocketLabels, s *tetragon.ProcessNetworkWatermark) {
	labelStrings := l.labelString()

	if s.Direction == "egress" {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsUDPTxBursts.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(labelStrings...).Set(1)
		} else {
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	} else {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsUDPRxBursts.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(labelStrings...).Set(1)
		} else {
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	}
}

func postUDPWatermarksDipStats(l *srcSocketLabels, s *tetragon.ProcessNetworkWatermark) {
	labelStrings := l.labelString()

	if s.Direction == "egress" {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsUDPTxDips.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(labelStrings...).Set(-1)
		} else {
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	} else {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsUDPRxDips.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(labelStrings...).Set(-1)
		} else {
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	}
}

func postTCPWatermarksBurstStats(l *srcSocketLabels, s *tetragon.ProcessNetworkWatermark) {
	labelStrings := l.labelString()

	if s.Direction == "egress" {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsTxBursts.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(labelStrings...).Set(1)
		} else {
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	} else {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsRxBursts.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsRxWatermarksState.WithLabelValues(labelStrings...).Set(1)
		} else {
			socketmetrics.SocketStatsRxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	}
}

func postTCPWatermarksDipStats(l *srcSocketLabels, s *tetragon.ProcessNetworkWatermark) {
	labelStrings := l.labelString()

	if s.Direction == "egress" {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsTxDips.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(labelStrings...).Set(-1)
		} else {
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	} else {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsRxDips.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsRxWatermarksState.WithLabelValues(labelStrings...).Set(-1)
		} else {
			socketmetrics.SocketStatsRxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	}
}

func postProcessNetworkWatermarksEventStats(res *tetragon.ProcessNetworkWatermark) {
	switch res.Protocol {
	case tetragon.SocketProtocol_UDP.String():
		l := createSrcSocketLabels(res.Process)

		if !udpconfig.MetricsEnabled {
			break
		}
		if res.WatermarksType == "burst" {
			postUDPWatermarksBurstStats(l, res)
		} else {
			postUDPWatermarksDipStats(l, res)
		}

	case tetragon.SocketProtocol_TCP.String():
		l := createTCPSrcSocketLabels(res.Process)

		if !tcpconfig.MetricsEnabled {
			break
		}
		if res.WatermarksType == "burst" {
			postTCPWatermarksBurstStats(l, res)
		} else {
			postTCPWatermarksDipStats(l, res)
		}
	}
}

func HandleProcessWatermarksEvent(res *tetragon.ProcessNetworkWatermark) {
	postProcessNetworkWatermarksEventStats(res)
}
