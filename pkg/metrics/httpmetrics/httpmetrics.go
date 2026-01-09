// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package httpmetrics

import (
	"strconv"

	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/isovalent/hubble-fgs/pkg/api/httpapi"
	enterpriseMetrics "github.com/isovalent/hubble-fgs/pkg/metrics"
)

var (
	httpCollectorErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name:      "http_collector_errors_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Total number of errors during the collector runs for the http parser",
	})
	httpParserStatesTotal = metrics.NewBPFCounter(prometheus.NewDesc(
		prometheus.BuildFQName(consts.MetricsNamespace, "", "http_parser_states_total"),
		"Number of HTTP parser states",
		[]string{"state"}, nil,
	))
	HttpResponseTotal = metrics.MustNewGranularCounter[HTTPLabels](prometheus.CounterOpts{
		Name:      "http_response_total",
		Namespace: consts.MetricsNamespace,
		Help:      "HTTP return code statistics",
	}, []string{"code"})
	// The buckets are defined based on OpenTelemetry semantic conventions for HTTP metrics:
	// https://opentelemetry.io/docs/specs/otel/metrics/semantic_conventions/http-metrics/#metric-httpserverduration
	HttpRequestDurationSeconds = metrics.MustNewGranularHistogram[HTTPLabels](prometheus.HistogramOpts{
		Name:      "http_stats_latency",
		Namespace: consts.MetricsNamespace,
		Help:      "Duration of HTTP request processing.",
		Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10},
	}, nil)
)

func InitHealthMetrics(registry *prometheus.Registry) {
	registry.MustRegister(httpCollectorErrors)

	registry.MustRegister(NewBPFCollector())
}

func InitHealthMetricsForDocs(registry *prometheus.Registry) {
	registry.MustRegister(httpCollectorErrors)

	registry.MustRegister(NewBPFZeroCollector())
}

func InitEventsMetrics(registry *prometheus.Registry) {
	registry.MustRegister(HttpResponseTotal)
	registry.MustRegister(HttpRequestDurationSeconds)
}

func InitEventsMetricsForDocs(registry *prometheus.Registry) {
	InitEventsMetrics(registry)

	httpLabels := NewHTTPLabels(
		consts.ExampleNamespace, consts.ExampleWorkload, consts.ExamplePod, consts.ExampleBinary,
		consts.ExampleNamespace, consts.ExampleWorkload, consts.ExamplePod, enterpriseMetrics.ExampleDNSNamesLabel,
		enterpriseMetrics.ExampleDomain,
	)

	for _, code := range httpapi.KnownHTTPStatusCodes {
		HttpResponseTotal.WithLabelValues(httpLabels, strconv.Itoa(code)).Add(0)
	}
	HttpRequestDurationSeconds.WithLabelValues(httpLabels)
}
