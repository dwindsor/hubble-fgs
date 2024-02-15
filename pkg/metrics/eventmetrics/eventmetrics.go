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
	"github.com/isovalent/hubble-fgs/pkg/sensors/udp/dnsconfig"
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

func postIcmpStats(res *tetragon.ProcessIcmp) {
	binary, pod, workload, ns := oss.GetProcessInfo(res.Process)
	dstPod := res.DestinationPod
	dstpod, dstworkload, dstns := GetDstPodInfo(dstPod)
	dstLabels := strings.Join(res.DestinationNames, ",")

	icmpmetrics.IcmpStatsVol.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels).Inc()
}

func HandleIcmpEvent(res *tetragon.ProcessIcmp) {
	postIcmpStats(res)
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
	dstpod, dstworkload, dstns := GetDstPodInfo(dstPod)
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
	return GetPromBucket(0, 990, upperLimitPercent)
}
