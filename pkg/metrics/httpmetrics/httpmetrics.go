//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package httpmetrics

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	HttpResponseTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "http_response_total",
		Namespace: consts.MetricsNamespace,
		Help:      "HTTP return code statistics",
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns", "host", "code"})
	HttpRequestDurationSeconds = promauto.NewSummaryVec(prometheus.SummaryOpts{
		Name:       "http_stats_latency",
		Namespace:  consts.MetricsNamespace,
		Help:       "HTTP latency statistics",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
	}, []string{"namespace", "pod", "binary", "dstnamespace", "dstpod", "dstdns", "host"})
)
