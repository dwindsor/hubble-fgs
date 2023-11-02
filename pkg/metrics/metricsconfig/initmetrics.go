//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package metricsconfig

import (
	"sync"

	"github.com/cilium/tetragon/pkg/metrics"
	oss "github.com/cilium/tetragon/pkg/metrics/metricsconfig"
	"github.com/isovalent/hubble-fgs/pkg/metrics/dnsmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/filemetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/httpmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/interfacemetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/iperrormetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/lrumetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/tlsmetrics"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	registryOnce sync.Once
)

func initAllEEMetrics(registry *prometheus.Registry) {
	dnsmetrics.InitMetrics(registry)
	eventmetrics.InitMetrics(registry)
	filemetrics.InitMetrics(registry)
	httpmetrics.InitMetrics(registry)
	interfacemetrics.InitMetrics(registry)
	iperrormetrics.InitMetrics(registry)
	lrumetrics.InitMetrics(registry)
	socketmetrics.InitMetrics(registry)
	tlsmetrics.InitMetrics(registry)
}

func InitAllMetrics(registry *prometheus.Registry) {
	oss.InitAllMetrics(registry)
	initAllEEMetrics(registry)
}

func RegisterEEMetrics() {
	registryOnce.Do(func() {
		initAllEEMetrics(metrics.GetRegistry())
	})
}
