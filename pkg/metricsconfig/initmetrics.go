// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package metricsconfig

import (
	oss "github.com/cilium/tetragon/pkg/metricsconfig"
	"github.com/prometheus/client_golang/prometheus"

	// errmetrics registers the enterprise file IDs for OSS metrics
	_ "github.com/isovalent/hubble-fgs/pkg/errmetrics"

	"github.com/isovalent/hubble-fgs/pkg/metrics/alertmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/appmodelmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/dnsmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/dnsparsermetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/filemetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/httpmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/icmpmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/igmpmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/interfacemetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/iperrormetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/networkmetrics"
	processcachecleanmetrics "github.com/isovalent/hubble-fgs/pkg/metrics/processcacheclean"
	"github.com/isovalent/hubble-fgs/pkg/metrics/sandboxmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/splunkhecmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/tlsmetrics"
	"github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
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

func initAllIGMPEventsMetrics(registry *prometheus.Registry) {
	igmpmetrics.InitMetrics(registry)
}

func InitIGMPEventsMetricsForDocs(registry *prometheus.Registry) {
	igmpmetrics.InitMetricsForDocs(registry)
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

func initAllAlertMetrics(registry *prometheus.Registry) {
	alertmetrics.InitMetrics(registry)
}

func InitAlertMetricsForDocs(registry *prometheus.Registry) {
	alertmetrics.InitMetricsForDocs(registry)
}

func initAllAppModelMetrics(registry *prometheus.Registry) {
	appmodelmetrics.InitMetrics(registry)
}

func InitAppModelMetricsForDocs(registry *prometheus.Registry) {
	appmodelmetrics.InitMetricsForDocs(registry)
}

func initAllSplunkHECMetrics(registry *prometheus.Registry) {
	splunkhecmetrics.InitMetrics(registry)
}

func InitSplunkHECMetricsForDocs(registry *prometheus.Registry) {
	splunkhecmetrics.InitMetricsForDocs(registry)
}

func InitNetworkMetricsForDocs(registry *prometheus.Registry) {
	networkmetrics.InitMetricsForDocs(registry)
}

func initAllNetworkMetrics(registry *prometheus.Registry) {
	networkmetrics.InitMetrics(registry)
}

func initAllDebugDNSParserMetrics(registry *prometheus.Registry) {
	if option.Config.EnableBPFDNSParser {
		dnsparsermetrics.EnableDebugDNSParserMetrics(registry)
	}
}

func InitAllEEHealthMetrics(registry *prometheus.Registry) {
	initAllDNSHealthMetrics(registry)
	initAllFileHealthMetrics(registry)
	initAllHTTPHealthMetrics(registry)
	initAllNetworkHealthMetrics(registry)
	initAllRawSocketEventsMetrics(registry)
	initAllTLSHealthMetrics(registry)
	initAllSandboxMetrics(registry)
	initAllProcessCacheCleanMetrics(registry)
	initAllAlertMetrics(registry)
	initAllDebugDNSParserMetrics(registry)
	initAllNetworkMetrics(registry)
	initAllAppModelMetrics(registry)
	initAllSplunkHECMetrics(registry)
}

func InitAllEEEventMetrics(registry *prometheus.Registry) {
	initAllDNSEventsMetrics(registry)
	initAllFileEventsMetrics(registry)
	initAllHTTPEventsMetrics(registry)
	initAllICMPEventsMetrics(registry)
	initAllIGMPEventsMetrics(registry)
	initAllInterfaceEventsMetrics(registry)
	initAllTCPEventsMetrics(registry)
	initAllUDPEventsMetrics(registry)
	initAllTLSEventsMetrics(registry)
}

func InitAllHealthMetrics(registry *prometheus.Registry) {
	oss.InitHealthMetrics((registry))
	InitAllEEHealthMetrics(registry)
}

func InitAllEventMetrics(registry *prometheus.Registry) {
	oss.InitEventsMetrics((registry))
	InitAllEEEventMetrics(registry)
}
