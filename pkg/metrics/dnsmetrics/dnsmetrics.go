//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package dnsmetrics

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
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
)

func DnsCacheMisses() prometheus.Counter {
	return dnsCacheErrors
}

func DnsCacheEvictions() prometheus.Counter {
	return dnsCacheEvictions
}

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(dnsCacheErrors)
	registry.MustRegister(dnsCacheEvictions)
}
