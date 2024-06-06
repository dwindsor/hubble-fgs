//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package udp

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

type cacheSizeMetrics struct {
	used     *prometheus.Desc
	capacity *prometheus.Desc
}

func (m *cacheSizeMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- m.used
	ch <- m.capacity
}

func (m *cacheSizeMetrics) Collect(ch chan<- prometheus.Metric) {
	used := 0
	if stats != nil {
		used = stats.Len()
	}
	ch <- prometheus.MustNewConstMetric(
		m.used,
		prometheus.GaugeValue,
		float64(used),
	)
	ch <- prometheus.MustNewConstMetric(
		m.capacity,
		prometheus.GaugeValue,
		float64(udpStatsCacheSize),
	)
}

func NewCacheCollector() prometheus.Collector {
	return &cacheSizeMetrics{
		prometheus.NewDesc(
			prometheus.BuildFQName(consts.MetricsNamespace, "", "udp_stats_cache_entries"),
			"The number of entries in the UDP stats cache.",
			nil, nil,
		),
		prometheus.NewDesc(
			prometheus.BuildFQName(consts.MetricsNamespace, "", "udp_stats_cache_capacity"),
			"The capacity of the UDP stats cache. Expected to be constant.",
			nil, nil,
		),
	}
}
