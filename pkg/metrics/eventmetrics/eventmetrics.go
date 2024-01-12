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
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/helpers"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	oss "github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
	"github.com/cilium/tetragon/pkg/reader/exec"
	"github.com/isovalent/hubble-fgs/pkg/metrics/httpmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/icmpmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/interfacemetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/tlsmetrics"
	"github.com/isovalent/hubble-fgs/pkg/sensors/tcp/tcpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/udp/dnsconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/udp/udpconfig"
)

// An RCode is a DNS response status code.
const (
	// Message.Rcode
	RCodeSuccess        uint16 = 0
	RCodeFormatError    uint16 = 1
	RCodeServerFailure  uint16 = 2
	RCodeNameError      uint16 = 3
	RCodeNotImplemented uint16 = 4
	RCodeRefused        uint16 = 5
)

var rCodeNames = map[uint16]string{
	RCodeSuccess:        "Success",
	RCodeFormatError:    "FormatError",
	RCodeServerFailure:  "ServerFailure",
	RCodeNameError:      "NameError",
	RCodeNotImplemented: "NotImplemented",
	RCodeRefused:        "Refused",
}

func getRCodeString(rc *wrapperspb.Int32Value) string {
	if rc != nil {
		return rCodeNames[uint16(rc.Value)]
	}
	return "Unknown"
}

func HandleOriginalEvent(originalEvent interface{}) {
	var flags uint32
	switch msg := originalEvent.(type) {
	case *processapi.MsgExecveEventUnix:
		flags = msg.Process.Flags
	}
	for _, flag := range exec.DecodeCommonFlags(flags) {
		oss.FlagCount.WithLabelValues(flag).Inc()
	}
}

var (
	dnsRequestTotal = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "dns_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Dns request/response statistics",
	}, []string{"namespace", "workload", "pod", "binary", "names", "rcodes", "response"})
)

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(dnsRequestTotal)
}

func postDnsMetric(res *tetragon.ProcessDns) {
	var rr string

	binary, pod, workload, ns := oss.GetProcessInfo(res.Process)

	dns := res.Dns
	names := strings.Join(dns.GetNames(), ",")
	codes := getRCodeString(dns.GetReturnCode())

	if dns.Response {
		rr = "Response"
	} else {
		rr = "Request"
	}

	dnsRequestTotal.WithLabelValues(ns, workload, pod, binary, names, codes, rr).Inc()
}

func HandleDnsEvent(res *tetragon.ProcessDns) {
	if dnsconfig.MetricsEnabled {
		postDnsMetric(res)
	}
}

func HandleProcessedEvent(processedEvent interface{}) {
	var eventType, namespace, workload, pod, binary string
	switch ev := processedEvent.(type) {
	case *tetragon.GetEventsResponse:
		binary, pod, workload, namespace = oss.GetProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))
		var err error
		eventType, err = helpers.ResponseTypeString(ev)
		if err != nil {
			logger.GetLogger().WithField("event", processedEvent).WithError(err).Warn("metrics: handleProcessedEvent: unhandled event")
			eventType = "unhandled"
		}
	default:
		eventType = "unknown"
	}
	oss.EventsProcessed.ToProm().WithLabelValues(eventType, namespace, workload, pod, binary).Inc()
}

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

func getPromBucket(min, max, upperLimitPercent uint32) string {
	if upperLimitPercent == 100 {
		return "+Inf"
	}
	return strconv.Itoa(int(min + (max-min)*upperLimitPercent/100))
}

func getTcpRttPromBucket(upperLimitPercent uint32) string {
	return getPromBucket(tcpconfig.RttHistogramMin, tcpconfig.RttHistogramMax, upperLimitPercent)
}

func getDstPodInfo(dstPod *tetragon.Pod) (pod, workload, ns string) {
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
	dstpod, dstworkload, dstns := getDstPodInfo(dstPod)
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

func postIcmpStats(res *tetragon.ProcessIcmp) {
	binary, pod, workload, ns := oss.GetProcessInfo(res.Process)
	dstPod := res.DestinationPod
	dstpod, dstworkload, dstns := getDstPodInfo(dstPod)
	dstLabels := strings.Join(res.DestinationNames, ",")

	icmpmetrics.IcmpStatsVol.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Inc()
}

func HandleIcmpEvent(res *tetragon.ProcessIcmp) {
	postIcmpStats(res)
}

func postUDPBurstStats(ns, workload, pod, binary string, s *tetragon.ProcessNetworkBurst) {
	if s.Direction == "egress" {
		if s.BurstState == "start" {
			socketmetrics.SocketStatsUDPTxBursts.WithLabelValues(ns, workload, pod, binary).Inc()
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(1)
		} else {
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(0)
		}
	} else {
		if s.BurstState == "start" {
			socketmetrics.SocketStatsUDPRxBursts.WithLabelValues(ns, workload, pod, binary).Inc()
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(1)
		} else {
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(0)
		}
	}
}

func postTCPBurstStats(ns, workload, pod, binary string, s *tetragon.ProcessNetworkBurst) {
	if s.Direction == "egress" {
		if s.BurstState == "start" {
			socketmetrics.SocketStatsTxBursts.WithLabelValues(ns, workload, pod, binary).Inc()
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(1)
		} else {
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(0)
		}
	} else {
		if s.BurstState == "start" {
			socketmetrics.SocketStatsRxBursts.WithLabelValues(ns, workload, pod, binary).Inc()
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(1)
		} else {
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(0)
		}
	}
}

func postProcessNetworkBurstEventStats(res *tetragon.ProcessNetworkBurst) {
	binary, pod, workload, ns := oss.GetProcessInfo(res.Process)
	switch res.Protocol {
	case tetragon.SocketProtocol_UDP.String():
		if udpconfig.MetricsEnabled {
			postUDPBurstStats(ns, workload, pod, binary, res)
		}
	case tetragon.SocketProtocol_TCP.String():
		if tcpconfig.MetricsEnabled {
			postTCPBurstStats(ns, workload, pod, binary, res)
		}
	}
}

func HandleProcessBurstEvent(res *tetragon.ProcessNetworkBurst) {
	postProcessNetworkBurstEventStats(res)
}

func postUDPWatermarksBurstStats(ns, workload, pod, binary string, s *tetragon.ProcessNetworkWatermark) {
	if s.Direction == "egress" {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsUDPTxBursts.WithLabelValues(ns, workload, pod, binary).Inc()
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(1)
		} else {
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(0)
		}
	} else {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsUDPRxBursts.WithLabelValues(ns, workload, pod, binary).Inc()
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(1)
		} else {
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(0)
		}
	}
}

func postUDPWatermarksDipStats(ns, workload, pod, binary string, s *tetragon.ProcessNetworkWatermark) {
	if s.Direction == "egress" {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsUDPTxDips.WithLabelValues(ns, workload, pod, binary).Inc()
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(-1)
		} else {
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(0)
		}
	} else {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsUDPRxDips.WithLabelValues(ns, workload, pod, binary).Inc()
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(-1)
		} else {
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(0)
		}
	}
}

func postTCPWatermarksBurstStats(ns, workload, pod, binary string, s *tetragon.ProcessNetworkWatermark) {
	if s.Direction == "egress" {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsTxBursts.WithLabelValues(ns, workload, pod, binary).Inc()
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(1)
		} else {
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(0)
		}
	} else {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsRxBursts.WithLabelValues(ns, workload, pod, binary).Inc()
			socketmetrics.SocketStatsRxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(1)
		} else {
			socketmetrics.SocketStatsRxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(0)
		}
	}
}

func postTCPWatermarksDipStats(ns, workload, pod, binary string, s *tetragon.ProcessNetworkWatermark) {
	if s.Direction == "egress" {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsTxDips.WithLabelValues(ns, workload, pod, binary).Inc()
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(-1)
		} else {
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(0)
		}
	} else {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsRxDips.WithLabelValues(ns, workload, pod, binary).Inc()
			socketmetrics.SocketStatsRxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(-1)
		} else {
			socketmetrics.SocketStatsRxWatermarksState.WithLabelValues(ns, workload, pod, binary).Set(0)
		}
	}
}

func postProcessNetworkWatermarksEventStats(res *tetragon.ProcessNetworkWatermark) {
	binary, pod, workload, ns := oss.GetProcessInfo(res.Process)
	switch res.Protocol {
	case tetragon.SocketProtocol_UDP.String():
		if !udpconfig.MetricsEnabled {
			break
		}
		if res.WatermarksType == "burst" {
			postUDPWatermarksBurstStats(ns, workload, pod, binary, res)
		} else {
			postUDPWatermarksDipStats(ns, workload, pod, binary, res)
		}

	case tetragon.SocketProtocol_TCP.String():
		if !tcpconfig.MetricsEnabled {
			break
		}
		if res.WatermarksType == "burst" {
			postTCPWatermarksBurstStats(ns, workload, pod, binary, res)
		} else {
			postTCPWatermarksDipStats(ns, workload, pod, binary, res)
		}
	}
}

func HandleProcessWatermarksEvent(res *tetragon.ProcessNetworkWatermark) {
	postProcessNetworkWatermarksEventStats(res)
}

func postProcessUdpSeqCheckErrors(res *tetragon.ProcessUdpSeqCheckError) {
	binary, pod, workload, ns := oss.GetProcessInfo(res.Process)
	socketmetrics.SocketStatsUDPSeqCheckErrors.WithLabelValues(ns, workload, pod, binary).Inc()
}

func HandleProcessUdpSeqCheckError(res *tetragon.ProcessUdpSeqCheckError) {
	postProcessUdpSeqCheckErrors(res)
}

func postHttpStats(res *tetragon.ProcessHttp) {
	binary, pod, workload, ns := oss.GetProcessInfo(res.Process)
	dstPod := res.Socket.GetDestinationPod()
	dstpod, dstworkload, dstns := getDstPodInfo(dstPod)
	dstLabels := strings.Join(res.Socket.DestinationNames, ",")

	http := res.Http
	code := fmt.Sprintf("%d", http.Response.Code)
	host := http.Request.Host

	// We may consider adding URI here as well, but without a configuration mechanism
	// to enable/disable it this could have poor scaling properties. Imagine a user
	// scanning for URIs behind a host.
	httpmetrics.HttpResponseTotal.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, host, code).Inc()

	c := float64(http.Latency.AsDuration().Seconds())
	httpmetrics.HttpRequestDurationSeconds.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, host).Observe(c)
}

func HandleHttpEvent(res *tetragon.ProcessHttp) {
	postHttpStats(res)
}

func HandleTlsEvent(res *tetragon.Tls) {
	tlsmetrics.TlsHandshakeTotal(res).Inc()
}

func HandleInterfaceStatsEvent(res *tetragon.InterfaceStats) {
	name := res.InterfaceName
	var ns, workload, pod string

	if res.Pod != nil {
		ns = res.Pod.Namespace
		workload = res.Pod.Workload
		pod = res.Pod.Name
	}

	interfacemetrics.InterfaceBytesSent.WithLabelValues(name, ns, workload, pod).Set(float64(res.BytesSent))
	interfacemetrics.InterfaceBytesReceived.WithLabelValues(name, ns, workload, pod).Set(float64(res.BytesReceived))
	interfacemetrics.InterfaceSegmentsSent.WithLabelValues(name, ns, workload, pod).Set(float64(res.PacketsSent))
	interfacemetrics.InterfaceSegmentsReceived.WithLabelValues(name, ns, workload, pod).Set(float64(res.PacketsReceived))
	interfacemetrics.InterfaceTxErrors.WithLabelValues(name, ns, workload, pod).Set(float64(res.TxErrors))
	interfacemetrics.InterfaceRxErrors.WithLabelValues(name, ns, workload, pod).Set(float64(res.RxErrors))
	interfacemetrics.InterfaceTxDrops.WithLabelValues(name, ns, workload, pod).Set(float64(res.TxDrops))
	interfacemetrics.InterfaceRxDrops.WithLabelValues(name, ns, workload, pod).Set(float64(res.RxDrops))

	if res.Qlen != nil {
		c := float64(res.Qlen.Buckets[0].Count)
		interfacemetrics.InterfaceQlenBucket.WithLabelValues(name, ns, workload, pod, getIfaceQLenPromBucket(1)).Set(c)
		c += float64(res.Qlen.Buckets[1].Count)
		interfacemetrics.InterfaceQlenBucket.WithLabelValues(name, ns, workload, pod, getIfaceQLenPromBucket(10)).Set(c)
		c += float64(res.Qlen.Buckets[2].Count)
		interfacemetrics.InterfaceQlenBucket.WithLabelValues(name, ns, workload, pod, getIfaceQLenPromBucket(25)).Set(c)
		c += float64(res.Qlen.Buckets[3].Count)
		interfacemetrics.InterfaceQlenBucket.WithLabelValues(name, ns, workload, pod, getIfaceQLenPromBucket(50)).Set(c)
		c += float64(res.Qlen.Buckets[4].Count)
		interfacemetrics.InterfaceQlenBucket.WithLabelValues(name, ns, workload, pod, getIfaceQLenPromBucket(75)).Set(c)
		c += float64(res.Qlen.Buckets[5].Count)
		interfacemetrics.InterfaceQlenBucket.WithLabelValues(name, ns, workload, pod, getIfaceQLenPromBucket(90)).Set(c)
		c += float64(res.Qlen.Buckets[6].Count)
		interfacemetrics.InterfaceQlenBucket.WithLabelValues(name, ns, workload, pod, getIfaceQLenPromBucket(99)).Set(c)
		c += float64(res.Qlen.Buckets[7].Count)
		interfacemetrics.InterfaceQlenBucket.WithLabelValues(name, ns, workload, pod, getIfaceQLenPromBucket(100)).Set(c)
		interfacemetrics.InterfaceQlenCount.WithLabelValues(name, ns, workload, pod).Set(c)
		interfacemetrics.InterfaceQlenSum.WithLabelValues(name, ns, workload, pod).Set(float64(res.Qlen.Sum))
	}
}

func getIfaceQLenPromBucket(upperLimitPercent uint32) string {
	// min and max are defined in bpf_dev_queue_xmit.c
	return getPromBucket(0, 990, upperLimitPercent)
}
