// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package processcachecleanmetrics

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	ProcessCacheRemovedStale = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: consts.MetricsNamespace,
		Name:      "process_cache_clean_total",
		Help:      "Number of stale entries cleaned from the process cache.",
	})
	ProcessCacheRemovedUnderflow = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: consts.MetricsNamespace,
		Name:      "process_cache_underflow_total",
		Help:      "Number of underflow entries cleaned from the process cache.",
	})
)

func InitEventsMetrics(registry *prometheus.Registry) {
	registry.MustRegister(ProcessCacheRemovedStale)
	registry.MustRegister(ProcessCacheRemovedUnderflow)
}

func InitEventsMetricsForDocs(registry *prometheus.Registry) {
	InitEventsMetrics(registry)
}
