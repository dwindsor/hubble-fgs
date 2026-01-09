// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package endpointmetrics

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	endpointCacheEvictions = prometheus.NewCounter(prometheus.CounterOpts{
		Name:      "endpoint_cache_evictions_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Endpoint cache evictions. Some churn is expected, but this metric can be useful to determine the rate of churn",
	})
)

func EndpointCacheEvictions() prometheus.Counter {
	return endpointCacheEvictions
}

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(endpointCacheEvictions)
}

func InitMetricsForDocs(registry *prometheus.Registry) {
	InitMetrics(registry)
}
