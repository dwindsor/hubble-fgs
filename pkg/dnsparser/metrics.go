//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package dnsparser

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var dnsParserErrorMetric = metrics.MustNewCustomCounter(
	metrics.NewOpts(
		consts.MetricsNamespace, "dns_parser", "error_total",
		"The total and type of errors encountered while parsing DNS answers. Internal use only.",
		nil, nil, []metrics.UnconstrainedLabel{{Name: "error_number", ExampleValue: "1"}}, // could be constrained
	),
)

func NewDNSParserErrorCollector() prometheus.Collector {
	return metrics.NewCustomCollector(
		metrics.CustomMetrics{
			dnsParserErrorMetric,
		},
		collect,
		collectForDocs,
	)
}

func collect(ch chan<- prometheus.Metric) {
	mapFile := filepath.Join(bpf.MapPrefixPath(), ErrorMapName)
	m, err := ebpf.LoadPinnedMap(mapFile, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", mapFile).Error("DNS parser error metrics: failure to load map")
		return
	}
	defer m.Close()

	errorMap := NewErrorMap(m)

	values, err := errorMap.ReadAll()
	if err != nil {
		logger.GetLogger().WithError(err).Error("DNS parser error metrics: failed to read the error map")
		return
	}

	for index, value := range values {
		ch <- dnsParserErrorMetric.MustMetric(float64(value), fmt.Sprint(index))
	}
}

func collectForDocs(ch chan<- prometheus.Metric) {
	ch <- dnsParserErrorMetric.MustMetric(0, "0")
}
