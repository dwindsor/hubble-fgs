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
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	DnsCacheErrorCiliumEndpoint       = "CiliumEndpointError"
	DnsCacheErrorCiliumFQDNCache      = "CiliumFQDNCacheError"
	DnsCacheErrorTetragonMissingEntry = "TetragonMissingEntry"
)

var (
	dnsCacheErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "dns_cache_errors",
		Help: "DNS cache errors",
	}, []string{"ip", "error"})

	dnsCacheEvictions = promauto.NewCounter(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "dns_cache_evictions",
		Help: "DNS cache evictions",
	})
)

func DnsCacheErrors(ip string, errType string) prometheus.Counter {
	return dnsCacheErrors.WithLabelValues(ip, errType)
}

func DnsCacheEvictions() prometheus.Counter {
	return dnsCacheEvictions
}
