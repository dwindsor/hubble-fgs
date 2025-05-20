//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package dnsparsermetrics

import (
	"sync"

	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	dnsParserMetrics     metrics.Group
	dnsParserMetricsOnce sync.Once
)

func GetDebugDNSParserGroup() metrics.Group {
	dnsParserMetricsOnce.Do(func() {
		dnsParserMetrics = metrics.NewMetricsGroup(false)
	})
	return dnsParserMetrics
}

func EnableDebugDNSParserMetrics(registry *prometheus.Registry) metrics.Group {
	dnsParserMetrics := GetDebugDNSParserGroup()
	dnsParserMetrics.MustRegister(dnsparser.NewDNSParserErrorCollector())
	registry.MustRegister(dnsParserMetrics)
	return dnsParserMetrics
}
