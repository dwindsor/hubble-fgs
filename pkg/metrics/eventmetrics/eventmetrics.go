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
	"strings"

	// This is needed to get tests passing since gotest seems to implicitly import this
	// package before running inits
	_ "github.com/isovalent/hubble-fgs/pkg/metrics/fixuposs"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/helpers"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	oss "github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/cilium/tetragon/pkg/reader/exec"
	"github.com/isovalent/hubble-fgs/pkg/metrics/httpmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/interfacemetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/tlsmetrics"
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

func getRCodeString(r uint16) string {
	return rCodeNames[r]
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
	dnsRequestTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "dns_total",
		Help: "Dns request/response statistics",
	}, []string{"namespace", "pod", "binary", "names", "rcodes", "response"})
)

func postDnsMetric(res *tetragon.ProcessDns) {
	var rr string

	binary, pod, ns := eventmetrics.GetProcessInfo(res.Process)

	dns := res.Dns
	names := strings.Join(dns.GetNames(), ",")
	codes := getRCodeString(uint16(dns.GetRcode()))

	if dns.Response {
		rr = "Response"
	} else {
		rr = "Request"
	}

	dnsRequestTotal.WithLabelValues(ns, pod, binary, names, codes, rr).Inc()
}

func HandleDnsEvent(res *tetragon.ProcessDns) {
	postDnsMetric(res)
}

func HandleProcessedEvent(processedEvent interface{}) {
	var eventType, namespace, pod, binary string
	switch ev := processedEvent.(type) {
	case *tetragon.GetEventsResponse:
		binary, pod, namespace = eventmetrics.GetProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))
		var err error
		eventType, err = helpers.ResponseTypeString(ev)
		if err != nil {
			logger.GetLogger().WithField("event", processedEvent).WithError(err).Warn("metrics: handleProcessedEvent: unhandled event")
			eventType = "unhandled"
		}
	default:
		eventType = "unknown"
	}
	oss.EventsProcessed.WithLabelValues(eventType, namespace, pod, binary).Inc()
}

func postUDPSocketStats(ns, pod, binary, dstns, dstpod, dstLabels string, s *tetragon.SocketStats) {
	c := float64(s.BytesSubmitted)
	socketmetrics.SocketStatsUDPTxBytes.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
	c = float64(s.SegsSubmitted)
	socketmetrics.SocketStatsUDPTxSegs.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)

	c = float64(s.BytesConsumed)
	socketmetrics.SocketStatsUDPRxBytes.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
	c = float64(s.SegsConsumed)
	socketmetrics.SocketStatsUDPRxSegs.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)

	c = float64(s.BytesSent)
	socketmetrics.SocketStatsUDPStackTxBytes.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
	c = float64(s.SegsOut)
	socketmetrics.SocketStatsUDPStackTxSegs.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)

	c = float64(s.BytesReceived)
	socketmetrics.SocketStatsUDPStackRxBytes.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
	c = float64(s.SegsIn)
	socketmetrics.SocketStatsUDPStackRxSegs.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)

	c = float64(s.SkDrop)
	socketmetrics.SocketStatsUDPDrops.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)

	c = float64(s.SkbConsumeMisses)
	socketmetrics.SocketStatsUDPConsumeMisses.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
}

func postUDPMulticastSocketStats(ns, pod, binary, dstns, dstpod, dstLabels string, res *tetragon.ProcessSockStats) {
	source := res.Socket.SourceIp
	sip := net.ParseIP(source)
	dest := res.Socket.DestinationIp
	dip := net.ParseIP(dest)

	s := res.Stats

	if !sip.IsMulticast() && !dip.IsMulticast() {
		return
	}

	c := float64(s.BytesSubmitted)
	socketmetrics.SocketStatsUDPMulticastTxBytes.WithLabelValues(ns, pod, binary, source, dstns, dstpod, dest).Add(c)

	c = float64(s.SegsSubmitted)
	socketmetrics.SocketStatsUDPMulticastTxSegs.WithLabelValues(ns, pod, binary, source, dstns, dstpod, dest).Add(c)

	c = float64(s.BytesConsumed)
	socketmetrics.SocketStatsUDPMulticastRxBytes.WithLabelValues(ns, pod, binary, source, dstns, dstpod, dest).Add(c)

	c = float64(s.SegsConsumed)
	socketmetrics.SocketStatsUDPMulticastRxSegs.WithLabelValues(ns, pod, binary, source, dstns, dstpod, dest).Add(c)

	c = float64(s.SkDrop)
	socketmetrics.SocketStatsUDPMulticastDrops.WithLabelValues(ns, pod, binary, source, dstns, dstpod, dest).Add(c)

	c = float64(s.SkbConsumeMisses)
	socketmetrics.SocketStatsUDPMulticastConsumeMisses.WithLabelValues(ns, pod, binary, source, dstns, dstpod, dest).Add(c)
}

func postTCPSocketStats(ns, pod, binary, dstns, dstpod, dstLabels string, s *tetragon.SocketStats) {
	c := float64(s.BytesSent)
	socketmetrics.SocketStatsTxBytes.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
	c = float64(s.SegsOut)
	socketmetrics.SocketStatsTxSegs.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)

	c = float64(s.BytesReceived)
	socketmetrics.SocketStatsRxBytes.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
	c = float64(s.SegsIn)
	socketmetrics.SocketStatsRxSegs.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)

	c = float64(s.RetransmitsBytes)
	socketmetrics.SocketStatsRetranBytes.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
	c = float64(s.RetransmitsSegs)
	socketmetrics.SocketStatsRetranSegs.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)

	c = float64(s.ToZeroWindow)
	socketmetrics.SocketStatsZeroWindow.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)

	c = float64(s.Srtt)
	socketmetrics.SocketStatsSrtt.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Observe(c)

	c = float64(s.SkDrop)
	socketmetrics.SocketStatsDrops.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)

	// Post TCP Latency numbers
	if s.Rtt != nil && s.Rtt.Buckets != nil {
		c = float64(s.Rtt.Buckets[0].Count)
		socketmetrics.SocketStatsRttLatencyB00.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
		c = float64(s.Rtt.Buckets[1].Count)
		socketmetrics.SocketStatsRttLatencyB01.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
		c = float64(s.Rtt.Buckets[2].Count)
		socketmetrics.SocketStatsRttLatencyB10.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
		c = float64(s.Rtt.Buckets[3].Count)
		socketmetrics.SocketStatsRttLatencyB25.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
		c = float64(s.Rtt.Buckets[4].Count)
		socketmetrics.SocketStatsRttLatencyB50.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
		c = float64(s.Rtt.Buckets[5].Count)
		socketmetrics.SocketStatsRttLatencyB75.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
		c = float64(s.Rtt.Buckets[6].Count)
		socketmetrics.SocketStatsRttLatencyB90.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
		c = float64(s.Rtt.Buckets[7].Count)
		socketmetrics.SocketStatsRttLatencyB99.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels).Add(c)
	}
}

func getDstPodInfo(dstPod *tetragon.Pod) (pod, ns string) {
	if dstPod != nil {
		ns = dstPod.Namespace
		pod = dstPod.Name
	}
	return pod, ns
}

func postStatsEventSocketStats(res *tetragon.ProcessSockStats) {
	binary, pod, ns := eventmetrics.GetProcessInfo(res.Process)
	dstPod := res.Socket.GetDestinationPod()
	dstpod, dstns := getDstPodInfo(dstPod)
	dstLabels := strings.Join(res.Socket.DestinationNames, ",")

	if res.Socket.Protocol == tetragon.SocketProtocol_TCP {
		postTCPSocketStats(ns, pod, binary, dstns, dstpod, dstLabels, res.Stats)
	} else if res.Socket.Protocol == tetragon.SocketProtocol_UDP {
		postUDPSocketStats(ns, pod, binary, dstns, dstpod, dstLabels, res.Stats)
		postUDPMulticastSocketStats(ns, pod, binary, dstns, dstpod, dstLabels, res)
	}
}

func HandleSocketEvent(res *tetragon.ProcessSockStats) {
	postStatsEventSocketStats(res)
}

func postUDPBurstStats(ns, pod, binary string, s *tetragon.ProcessNetworkBurst) {
	if s.Direction == "egress" {
		socketmetrics.SocketStatsUDPTxBursts.WithLabelValues(ns, pod, binary).Inc()
	} else {
		socketmetrics.SocketStatsUDPRxBursts.WithLabelValues(ns, pod, binary).Inc()
	}
}

func postTCPBurstStats(ns, pod, binary string, s *tetragon.ProcessNetworkBurst) {
	if s.Direction == "egress" {
		socketmetrics.SocketStatsTxBursts.WithLabelValues(ns, pod, binary).Inc()
	} else {
		socketmetrics.SocketStatsRxBursts.WithLabelValues(ns, pod, binary).Inc()
	}
}

func postProcessNetworkBurstEventStats(res *tetragon.ProcessNetworkBurst) {
	binary, pod, ns := eventmetrics.GetProcessInfo(res.Process)
	if res.BurstState == "start" {
		switch res.Protocol {
		case tetragon.SocketProtocol_UDP.String():
			postUDPBurstStats(ns, pod, binary, res)
		case tetragon.SocketProtocol_TCP.String():
			postTCPBurstStats(ns, pod, binary, res)
		}
	}
}

func HandleProcessBurstEvent(res *tetragon.ProcessNetworkBurst) {
	postProcessNetworkBurstEventStats(res)
}

func postIpErrorStats(ns, pod, binary, version, details string, s *tetragon.ProcessIpError) {
	socketmetrics.IpErrors.WithLabelValues(ns, pod, binary, version, details).Inc()
}

func HandleIpErrorEvent(res *tetragon.ProcessIpError) {
	binary, pod, ns := eventmetrics.GetProcessInfo(res.Process)
	postIpErrorStats(ns, pod, binary, res.Version, res.Details, res)
}

func postHttpStats(res *tetragon.ProcessHttp) {
	binary, pod, ns := eventmetrics.GetProcessInfo(res.Process)
	dstPod := res.GetDestinationPod()
	dstpod, dstns := getDstPodInfo(dstPod)
	dstLabels := strings.Join(res.Socket.DestinationNames, ",")

	http := res.Http
	code := fmt.Sprintf("%d", http.Response.Code)
	host := http.Request.Host

	// We may consider adding URI here as well, but without a configuration mechanism
	// to enable/disable it this could have poor scaling properties. Imagine a user
	// scanning for URIs behind a host.
	httpmetrics.HttpResponseTotal.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels, host, code).Inc()

	c := float64(http.Latency.AsDuration().Seconds())
	httpmetrics.HttpRequestDurationSeconds.WithLabelValues(ns, pod, binary, dstns, dstpod, dstLabels, host).Observe(c)
}

func HandleHttpEvent(res *tetragon.ProcessHttp) {
	postHttpStats(res)
}

func HandleTlsEvent(res *tetragon.Tls) {
	binary, pod, ns := eventmetrics.GetProcessInfo(res.Process)
	version := tlsmetrics.GetNegotiatedVersion(res)
	tlsmetrics.TlsHandshakeTotal.WithLabelValues(ns, pod, binary, version, res.Cipher, res.SniName).Inc()
}

func HandleInterfaceStatsEvent(res *tetragon.InterfaceStats) {
	name := res.InterfaceName
	ns := ""
	pod := ""

	if res.Pod != nil {
		ns = res.Pod.Namespace
		pod = res.Pod.Name
	}

	interfacemetrics.InterfaceBytesSent.WithLabelValues(name, ns, pod).Set(float64(res.BytesSent))
	interfacemetrics.InterfaceBytesReceived.WithLabelValues(name, ns, pod).Set(float64(res.BytesReceived))
	interfacemetrics.InterfaceSegmentsSent.WithLabelValues(name, ns, pod).Set(float64(res.PacketsSent))
	interfacemetrics.InterfaceSegmentsReceived.WithLabelValues(name, ns, pod).Set(float64(res.PacketsReceived))
	interfacemetrics.InterfaceTxErrors.WithLabelValues(name, ns, pod).Set(float64(res.TxErrors))
	interfacemetrics.InterfaceRxErrors.WithLabelValues(name, ns, pod).Set(float64(res.RxErrors))
	interfacemetrics.InterfaceTxDrops.WithLabelValues(name, ns, pod).Set(float64(res.TxDrops))
	interfacemetrics.InterfaceRxDrops.WithLabelValues(name, ns, pod).Set(float64(res.RxDrops))

	if res.Qlen == nil {
		return
	}
	if res.Qlen.Buckets[7].Count > 0 {
		interfacemetrics.InterfaceQlen99.WithLabelValues(name, ns, pod).Set(float64(res.Qlen.Buckets[7].Count))
	}
	if res.Qlen.Buckets[6].Count > 0 {
		interfacemetrics.InterfaceQlen90.WithLabelValues(name, ns, pod).Set(float64(res.Qlen.Buckets[6].Count))
	}
	if res.Qlen.Buckets[5].Count > 0 {
		interfacemetrics.InterfaceQlen75.WithLabelValues(name, ns, pod).Set(float64(res.Qlen.Buckets[5].Count))
	}
	if res.Qlen.Buckets[4].Count > 0 {
		interfacemetrics.InterfaceQlen50.WithLabelValues(name, ns, pod).Set(float64(res.Qlen.Buckets[4].Count))
	}
	if res.Qlen.Buckets[3].Count > 0 {
		interfacemetrics.InterfaceQlen25.WithLabelValues(name, ns, pod).Set(float64(res.Qlen.Buckets[3].Count))
	}
	if res.Qlen.Buckets[2].Count > 0 {
		interfacemetrics.InterfaceQlen10.WithLabelValues(name, ns, pod).Set(float64(res.Qlen.Buckets[2].Count))
	}
	if res.Qlen.Buckets[1].Count > 0 {
		interfacemetrics.InterfaceQlen01.WithLabelValues(name, ns, pod).Set(float64(res.Qlen.Buckets[1].Count))
	}
	if res.Qlen.Buckets[0].Count > 0 {
		interfacemetrics.InterfaceQlen00.WithLabelValues(name, ns, pod).Set(float64(res.Qlen.Buckets[0].Count))
	}
}
