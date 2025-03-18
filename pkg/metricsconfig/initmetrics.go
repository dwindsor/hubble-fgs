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
	oss "github.com/cilium/tetragon/pkg/metricsconfig"
	"github.com/isovalent/hubble-fgs/pkg/metrics/dnsmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/filemetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/httpmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/icmpmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/interfacemetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/iperrormetrics"
	processcachecleanmetrics "github.com/isovalent/hubble-fgs/pkg/metrics/processcacheclean"
	"github.com/isovalent/hubble-fgs/pkg/metrics/sandboxmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/tlsmetrics"
	"github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/prometheus/client_golang/prometheus"
)

func initAllDNSHealthMetrics(registry *prometheus.Registry) {
	dnsmetrics.InitMetrics(registry)
}

func InitDNSHealthMetricsForDocs(registry *prometheus.Registry) {
	dnsmetrics.InitMetricsForDocs(registry)
}

func initAllDNSEventsMetrics(registry *prometheus.Registry) {
	eventmetrics.InitMetrics(registry)
}

func InitDNSEventsMetricsForDocs(registry *prometheus.Registry) {
	eventmetrics.InitMetricsForDocs(registry)
}

func initAllFileHealthMetrics(registry *prometheus.Registry) {
	filemetrics.InitHealthMetrics(registry)
}

func InitFileHealthMetricsForDocs(registry *prometheus.Registry) {
	filemetrics.InitHealthMetricsForDocs(registry)
}

func initAllFileEventsMetrics(registry *prometheus.Registry) {
	filemetrics.InitEventsMetrics(registry)
}

func InitFileEventsMetricsForDocs(registry *prometheus.Registry) {
	filemetrics.InitEventsMetricsForDocs(registry)
}

func initAllHTTPHealthMetrics(registry *prometheus.Registry) {
	httpmetrics.InitHealthMetrics(registry)
}

func InitHTTPHealthMetricsForDocs(registry *prometheus.Registry) {
	httpmetrics.InitHealthMetricsForDocs(registry)
}

func initAllHTTPEventsMetrics(registry *prometheus.Registry) {
	httpmetrics.InitEventsMetrics(registry)
}

func InitHTTPEventsMetricsForDocs(registry *prometheus.Registry) {
	httpmetrics.InitEventsMetricsForDocs(registry)
}

func initAllICMPEventsMetrics(registry *prometheus.Registry) {
	icmpmetrics.InitMetrics(registry)
}

func InitICMPEventsMetricsForDocs(registry *prometheus.Registry) {
	icmpmetrics.InitMetricsForDocs(registry)
}

func initAllInterfaceEventsMetrics(registry *prometheus.Registry) {
	interfacemetrics.InitMetrics(registry)
}

func InitInterfaceEventsMetricsForDocs(registry *prometheus.Registry) {
	interfacemetrics.InitMetricsForDocs(registry)
}

func initAllNetworkHealthMetrics(registry *prometheus.Registry) {
	iperrormetrics.InitMetrics(registry)
	layer3.InitUDPHealthMetrics(registry)
	socketmetrics.InitHealthMetrics(registry)
}

func InitNetworkHealthMetricsForDocs(registry *prometheus.Registry) {
	iperrormetrics.InitMetrics(registry)
	layer3.InitUDPHealthMetrics(registry)
	socketmetrics.InitHealthMetrics(registry)
}

func initAllTCPEventsMetrics(registry *prometheus.Registry) {
	socketmetrics.InitTCPEventsMetrics(registry)
}

func InitTCPEventsMetricsForDocs(registry *prometheus.Registry) {
	socketmetrics.InitTCPEventsMetricsForDocs(registry)
}

func initAllUDPEventsMetrics(registry *prometheus.Registry) {
	socketmetrics.InitUDPEventsMetrics(registry)
}

func InitUDPEventsMetricsForDocs(registry *prometheus.Registry) {
	socketmetrics.InitUDPEventsMetricsForDocs(registry)
}

func initAllRawSocketEventsMetrics(registry *prometheus.Registry) {
	socketmetrics.InitRawSocketEventsMetrics(registry)
}

func InitRawSocketEventsMetricsForDocs(registry *prometheus.Registry) {
	socketmetrics.InitRawSocketEventsMetricsForDocs(registry)
}

func initAllTLSHealthMetrics(registry *prometheus.Registry) {
	tlsmetrics.InitHealthMetrics(registry)
}

func InitTLSHealthMetricsForDocs(registry *prometheus.Registry) {
	tlsmetrics.InitHealthMetrics(registry)
}

func initAllTLSEventsMetrics(registry *prometheus.Registry) {
	tlsmetrics.InitEventsMetrics(registry)
}

func InitTLSEventsMetricsForDocs(registry *prometheus.Registry) {
	tlsmetrics.InitEventsMetricsForDocs(registry)
}

func initAllSandboxMetrics(registry *prometheus.Registry) {
	sandboxmetrics.InitEventsMetrics(registry)
}

func InitSandboxMetricsForDocs(registry *prometheus.Registry) {
	sandboxmetrics.InitEventsMetricsForDocs(registry)
}

func initAllProcessCacheCleanMetrics(registry *prometheus.Registry) {
	processcachecleanmetrics.InitEventsMetrics(registry)
}

func InitProcessCacheCleanMetricsForDocs(registry *prometheus.Registry) {
	processcachecleanmetrics.InitEventsMetricsForDocs(registry)
}

func initAllDebugDNSParserMetrics(registry *prometheus.Registry) {
	if option.Config.EnableBPFDNSParser {
		dnsmetrics.EnableDebugDNSParserMetrics(registry)
	}
}

func InitAllEEMetrics(registry *prometheus.Registry) {
	initAllDNSHealthMetrics(registry)
	initAllDNSEventsMetrics(registry)
	initAllFileHealthMetrics(registry)
	initAllFileEventsMetrics(registry)
	initAllHTTPHealthMetrics(registry)
	initAllHTTPEventsMetrics(registry)
	initAllICMPEventsMetrics(registry)
	initAllInterfaceEventsMetrics(registry)
	initAllNetworkHealthMetrics(registry)
	initAllTCPEventsMetrics(registry)
	initAllUDPEventsMetrics(registry)
	initAllRawSocketEventsMetrics(registry)
	initAllTLSHealthMetrics(registry)
	initAllTLSEventsMetrics(registry)
	initAllSandboxMetrics(registry)
	initAllProcessCacheCleanMetrics(registry)
	initAllDebugDNSParserMetrics(registry)
}

func InitAllMetrics(registry *prometheus.Registry) {
	oss.InitAllMetrics(registry)
	InitAllEEMetrics(registry)
}
