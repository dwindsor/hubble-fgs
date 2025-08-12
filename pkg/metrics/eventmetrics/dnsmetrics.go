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

	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"

	"github.com/cilium/tetragon/api/v1/tetragon"

	enterpriseMetrics "github.com/isovalent/hubble-fgs/pkg/metrics"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/dnsconfig"
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

type dnsRR int

// TODO: That's a bit silly, we might want to revisit this label.
const (
	rrRequest dnsRR = iota
	rrResponse
)

var dnsRRLabelValues = map[dnsRR]string{
	rrRequest:  "Request",
	rrResponse: "Response",
}

func (rr dnsRR) String() string {
	return dnsRRLabelValues[rr]
}

var (
	dnsRequestTotal = metrics.MustNewGranularCounter[metrics.ProcessLabels](prometheus.CounterOpts{
		Name:      "dns_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Dns request/response statistics",
	}, []string{"names", "rcodes", "response"})
)

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(dnsRequestTotal)
}

func InitMetricsForDocs(registry *prometheus.Registry) {
	InitMetrics(registry)

	processLabels := metrics.NewProcessLabels(
		consts.ExampleNamespace, consts.ExampleWorkload, consts.ExamplePod, consts.ExampleBinary,
	)
	dnsRequestTotal.WithLabelValues(processLabels, enterpriseMetrics.ExampleDNSNamesLabel, "", rrRequest.String()).Add(0)
	for _, rcode := range rCodeNames {
		dnsRequestTotal.WithLabelValues(processLabels, enterpriseMetrics.ExampleDNSNamesLabel, rcode, rrResponse.String()).Add(0)
	}
}

func getRCodeString(rc *wrapperspb.Int32Value) string {
	if rc != nil {
		return rCodeNames[uint16(rc.Value)]
	}
	return "Unknown"
}

func postDnsMetric(res *tetragon.ProcessDns) {
	dns := res.Dns
	names := strings.Join(dns.GetNames(), ",")
	codes := getRCodeString(dns.GetReturnCode())

	rr := rrRequest
	if dns.Response {
		rr = rrResponse
	}

	processLabels := createProcessLabels(dnsconfig.CurrentLabels, res.Process)
	dnsRequestTotal.WithLabelValues(processLabels, names, codes, rr.String()).Inc()
}

func HandleDnsEvent(res *tetragon.ProcessDns) {
	if dnsconfig.MetricsEnabled {
		postDnsMetric(res)
	}
}
