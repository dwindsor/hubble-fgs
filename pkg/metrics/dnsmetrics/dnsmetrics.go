// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dnsmetrics

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/isovalent/hubble-fgs/pkg/api/dnsapi"
	enterpriseMetrics "github.com/isovalent/hubble-fgs/pkg/metrics"
	"github.com/isovalent/hubble-fgs/pkg/option"
)

var (
	dnsCacheErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name:      "dns_cache_misses_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Number of IPs not found in the DNS cache. Note that this is expected for IPs that don't have FQDNs",
	})

	dnsCacheEvictions = prometheus.NewCounter(prometheus.CounterOpts{
		Name:      "dns_cache_evictions_total",
		Namespace: consts.MetricsNamespace,
		Help:      "DNS cache evictions. Some churn is expected, but this metric can be useful to determine the rate of churn",
	})

	dnsQtypes = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "dns_qtypes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "DNS question types total",
	}, []string{"namespace", "workload", "pod", "binary", "node_name", "names", "qtype"})

	dnsRtypes = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "dns_rtypes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "DNS response types total",
	}, []string{"namespace", "workload", "pod", "binary", "node_name", "names", "rtype"})
)

func DnsCacheMisses() prometheus.Counter {
	return dnsCacheErrors
}

func DnsCacheEvictions() prometheus.Counter {
	return dnsCacheEvictions
}

func AddDnsQType(ns, workload, pod, binary, names string, qtype dnsmessage.Type) {
	if option.Config.EnableUserDNSDebug {
		dnsQtypes.WithLabelValues(ns, workload, pod, binary, names, qtype.String()).Inc()
	}
}

func AddDnsRType(ns, workload, pod, binary, names string, rtype dnsmessage.Type) {
	if option.Config.EnableUserDNSDebug {
		dnsRtypes.WithLabelValues(ns, workload, pod, binary, names, rtype.String()).Inc()
	}
}

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(dnsCacheErrors)
	registry.MustRegister(dnsCacheEvictions)
	registry.MustRegister(dnsQtypes)
	registry.MustRegister(dnsRtypes)
}

func InitMetricsForDocs(registry *prometheus.Registry) {
	InitMetrics(registry)

	for _, t := range dnsapi.KnownDNSTypes {
		dnsQtypes.WithLabelValues(append(consts.ExampleProcessLabels, enterpriseMetrics.ExampleDNSNamesLabel, t.String())...).Add(0)
		dnsRtypes.WithLabelValues(append(consts.ExampleProcessLabels, enterpriseMetrics.ExampleDNSNamesLabel, t.String())...).Add(0)
	}
}
