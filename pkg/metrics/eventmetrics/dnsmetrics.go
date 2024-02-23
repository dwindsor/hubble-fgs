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
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	oss "github.com/cilium/tetragon/pkg/metrics/eventmetrics"
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

func getRCodeString(rc *wrapperspb.Int32Value) string {
	if rc != nil {
		return rCodeNames[uint16(rc.Value)]
	}
	return "Unknown"
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
