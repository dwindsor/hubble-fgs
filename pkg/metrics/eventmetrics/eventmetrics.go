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
	"strings"

	// This is needed to get tests passing since gotest seems to implicitly import this
	// package before running inits
	_ "github.com/isovalent/hubble-fgs/pkg/metrics/fixuposs"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/logger"
	oss "github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	readerdns "github.com/cilium/tetragon/pkg/reader/dns"
	"github.com/cilium/tetragon/pkg/reader/exec"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/api/v1/fgs/codegen/helpers"
	"github.com/isovalent/hubble-fgs/pkg/filters"
	"github.com/isovalent/hubble-fgs/pkg/metrics/httpmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/interfacemetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/tlsmetrics"
)

func getProcessInfo(process *fgs.Process) (binary, pod, namespace string) {
	if process != nil {
		binary = process.Binary
		if process.Pod != nil {
			namespace = process.Pod.Namespace
			pod = process.Pod.Name
		}
	}
	return binary, pod, namespace
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

func postDnsMetric(ev *fgs.GetEventsResponse, res *fgs.ProcessDns) {
	var rr string

	binary, pod, ns := getProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))

	dns := res.Dns
	names := strings.Join(dns.GetNames(), ",")
	codes := readerdns.GetRCodeString(uint16(dns.GetRcode()))

	if dns.Response {
		rr = "Response"
	} else {
		rr = "Request"
	}

	oss.DnsRequestTotal.WithLabelValues(ns, pod, binary, names, codes, rr).Inc()
}

func HandleDnsEvent(processedEvent interface{}) {
	switch ev := processedEvent.(type) {
	case *fgs.GetEventsResponse:
		switch res := ev.Event.(type) {
		case *fgs.GetEventsResponse_ProcessDns:
			postDnsMetric(ev, res.ProcessDns)
		}
	}
}

func HandleProcessedEvent(processedEvent interface{}) {
	var eventType, namespace, pod, binary string
	switch ev := processedEvent.(type) {
	case *fgs.GetEventsResponse:
		binary, pod, namespace = getProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))
		var err error
		eventType, err = helpers.EventTypeString(ev.Event)
		if err != nil {
			logger.GetLogger().WithField("event", processedEvent).WithError(err).Warn("metrics: handleProcessedEvent: unhandled event")
			eventType = "unhandled"
		}
	default:
		eventType = "unknown"
	}
	oss.EventsProcessed.WithLabelValues(eventType, namespace, pod, binary).Inc()
}

func postUDPSocketStats(ns, pod, binary, dstns, dstpod, dstLabels string, s *fgs.SocketStats) {
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

func postTCPSocketStats(ns, pod, binary, dstns, dstpod, dstLabels string, s *fgs.SocketStats) {
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
}

func getDstPodInfo(dstPod *fgs.Pod) (pod, ns string) {
	if dstPod != nil {
		ns = dstPod.Namespace
		pod = dstPod.Name
	}
	return pod, ns
}

func postStatsEventSocketStats(ev *fgs.GetEventsResponse, res *fgs.ProcessSockStats) {
	binary, pod, ns := getProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))
	dstPod := res.Socket.GetDestinationPod()
	dstpod, dstns := getDstPodInfo(dstPod)
	dstLabels := strings.Join(res.Socket.DestinationNames, ",")

	if res.Socket.Protocol == fgs.SocketProtocol_TCP {
		postTCPSocketStats(ns, pod, binary, dstns, dstpod, dstLabels, res.Stats)
	} else if res.Socket.Protocol == fgs.SocketProtocol_UDP {
		postUDPSocketStats(ns, pod, binary, dstns, dstpod, dstLabels, res.Stats)
	}
}

func HandleSocketEvent(processedEvent interface{}) {
	switch ev := processedEvent.(type) {
	case *fgs.GetEventsResponse:
		switch res := ev.Event.(type) {
		case *fgs.GetEventsResponse_ProcessSockStats:
			postStatsEventSocketStats(ev, res.ProcessSockStats)
		}
	}
}

func postUDPBurstStats(ns, pod, binary string, s *fgs.ProcessNetworkBurst) {
	if s.Direction == "egress" {
		socketmetrics.SocketStatsUDPTxBursts.WithLabelValues(ns, pod, binary).Inc()
	} else {
		socketmetrics.SocketStatsUDPRxBursts.WithLabelValues(ns, pod, binary).Inc()
	}
}

func postTCPBurstStats(ns, pod, binary string, s *fgs.ProcessNetworkBurst) {
	if s.Direction == "egress" {
		socketmetrics.SocketStatsTxBursts.WithLabelValues(ns, pod, binary).Inc()
	} else {
		socketmetrics.SocketStatsRxBursts.WithLabelValues(ns, pod, binary).Inc()
	}
}

func postProcessNetworkBurstEventStats(ev *fgs.GetEventsResponse, res *fgs.ProcessNetworkBurst) {
	binary, pod, ns := getProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))
	if res.BurstState == "start" {
		switch res.Protocol {
		case fgs.SocketProtocol_UDP.String():
			postUDPBurstStats(ns, pod, binary, res)
		case fgs.SocketProtocol_TCP.String():
			postTCPBurstStats(ns, pod, binary, res)
		}
	}
}

func HandleProcessBurstEvent(processedEvent interface{}) {
	switch ev := processedEvent.(type) {
	case *fgs.GetEventsResponse:
		switch res := ev.Event.(type) {
		case *fgs.GetEventsResponse_ProcessNetworkBurst:
			postProcessNetworkBurstEventStats(ev, res.ProcessNetworkBurst)
		}
	}
}

func postHttpStats(ev *fgs.GetEventsResponse, res *fgs.ProcessHttp) {
	binary, pod, ns := getProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))
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

func HandleHttpEvent(processedEvent interface{}) {
	switch ev := processedEvent.(type) {
	case *fgs.GetEventsResponse:
		switch res := ev.Event.(type) {
		case *fgs.GetEventsResponse_ProcessHttp:
			postHttpStats(ev, res.ProcessHttp)
		}
	}
}

func HandleTlsEvent(processedEvent interface{}) {
	switch ev := processedEvent.(type) {
	case *fgs.GetEventsResponse:
		switch res := ev.Event.(type) {
		case *fgs.GetEventsResponse_Tls:
			binary, pod, ns := getProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))
			version := tlsmetrics.GetNegotiatedVersion(res.Tls)
			tlsmetrics.TlsHandshakeTotal.WithLabelValues(ns, pod, binary, version, res.Tls.Cipher, res.Tls.SniName).Inc()
		}
	}
}

func HandleInterfaceStatsEvent(processedEvent interface{}) {
	switch ev := processedEvent.(type) {
	case *fgs.GetEventsResponse:
		switch res := ev.Event.(type) {
		case *fgs.GetEventsResponse_InterfaceStats:
			name := res.InterfaceStats.InterfaceName
			ns := res.InterfaceStats.Netns
			interfacemetrics.InterfaceBytesSent.WithLabelValues(name, ns).Set(float64(res.InterfaceStats.BytesSent))
			interfacemetrics.InterfaceBytesReceived.WithLabelValues(name, ns).Set(float64(res.InterfaceStats.BytesReceived))
			interfacemetrics.InterfaceSegmentsSent.WithLabelValues(name, ns).Set(float64(res.InterfaceStats.PacketsSent))
			interfacemetrics.InterfaceSegmentsReceived.WithLabelValues(name, ns).Set(float64(res.InterfaceStats.PacketsReceived))
			interfacemetrics.InterfaceTxErrors.WithLabelValues(name, ns).Set(float64(res.InterfaceStats.TxErrors))
			interfacemetrics.InterfaceRxErrors.WithLabelValues(name, ns).Set(float64(res.InterfaceStats.RxErrors))
			interfacemetrics.InterfaceTxDrops.WithLabelValues(name, ns).Set(float64(res.InterfaceStats.TxDrops))
			interfacemetrics.InterfaceRxDrops.WithLabelValues(name, ns).Set(float64(res.InterfaceStats.RxDrops))
		}
	}
}

func ProcessEvent(originalEvent interface{}, processedEvent interface{}) {
	HandleOriginalEvent(originalEvent)
	HandleProcessedEvent(processedEvent)
	HandleSocketEvent(processedEvent)
	HandleProcessBurstEvent(processedEvent)
	HandleHttpEvent(processedEvent)
	HandleDnsEvent(processedEvent)
	HandleTlsEvent(processedEvent)
	HandleInterfaceStatsEvent(processedEvent)
}
