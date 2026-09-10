// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package splunkhecmetrics

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	DroppedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: consts.MetricsNamespace,
		Name:      "splunk_hec_dropped_total",
		Help:      "Total number of JSON records dropped before reaching the Splunk HTTP Event Collector.",
	})

	FailedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: consts.MetricsNamespace,
		Name:      "splunk_hec_failed_total",
		Help:      "Total number of JSON records that failed to send to the Splunk HTTP Event Collector.",
	})

	SentTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: consts.MetricsNamespace,
		Name:      "splunk_hec_sent_total",
		Help:      "Total number of JSON records sent to the Splunk HTTP Event Collector by sourcetype.",
	}, []string{"sourcetype"})
)

func RecordDropped(count uint64) {
	DroppedTotal.Add(float64(count))
}

func RecordFailed(count uint64) {
	FailedTotal.Add(float64(count))
}

func RecordSent(sourcetype string, count uint64) {
	SentTotal.WithLabelValues(sourcetype).Add(float64(count))
}

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(DroppedTotal)
	registry.MustRegister(FailedTotal)
	registry.MustRegister(SentTotal)
}

func InitMetricsForDocs(registry *prometheus.Registry) {
	InitMetrics(registry)
	SentTotal.WithLabelValues("tetragon:events").Add(0)
}
