// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/tetragon/cmd/tetragon-metrics-docs/metricsmd"
	"github.com/cilium/tetragon/pkg/metricsconfig"

	"github.com/isovalent/hubble-fgs/pkg/metrics/dnsparsermetrics"
	enterpriseMetricsConfig "github.com/isovalent/hubble-fgs/pkg/metricsconfig"
)

func main() {
	targets := map[string]string{
		"health":              "Tetragon Health",
		"resources":           "Tetragon Resources",
		"health-dns":          "Tetragon DNS Sensor Health",
		"health-file":         "Tetragon File Sensor Health",
		"health-http":         "Tetragon HTTP Sensor Health",
		"health-network":      "Tetragon Network Sensors Health",
		"health-tls":          "Tetragon TLS Sensor Health",
		"events":              "Tetragon Events",
		"dns":                 "Tetragon DNS",
		"network":             "Tetragon Network Telemetry",
		"file":                "Tetragon File",
		"http":                "Tetragon HTTP",
		"icmp":                "Tetragon ICMP",
		"interface":           "Tetragon Interface",
		"tcp":                 "Tetragon TCP",
		"udp":                 "Tetragon UDP",
		"rawsocket":           "Tetragon Raw Socket",
		"tls":                 "Tetragon TLS",
		"sandbox":             "Tetragon SandboxPolicy metrics",
		"process-cache-clean": "Tetragon Process Cache Clean metrics",
		"debug-dns-parser":    "Tetragon Debug DNS Parser",
		"alerts":              "Tetragon Alerts",
		"appmodel":            "Tetragon Application Model",
	}

	if err := metricsmd.New(targets, initMetrics).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func initMetrics(target string, reg *prometheus.Registry, _ *slog.Logger) error {
	switch target {
	case "health":
		metricsconfig.EnableHealthMetrics(reg).InitForDocs()
	case "resources":
		metricsconfig.InitResourcesMetricsForDocs(reg)
	case "health-dns":
		enterpriseMetricsConfig.InitDNSHealthMetricsForDocs(reg)
	case "health-file":
		enterpriseMetricsConfig.InitFileHealthMetricsForDocs(reg)
	case "health-http":
		enterpriseMetricsConfig.InitHTTPHealthMetricsForDocs(reg)
	case "health-network":
		enterpriseMetricsConfig.InitNetworkHealthMetricsForDocs(reg)
	case "health-tls":
		enterpriseMetricsConfig.InitTLSHealthMetricsForDocs(reg)
	case "events":
		metricsconfig.InitEventsMetricsForDocs(reg)
		enterpriseMetricsConfig.InitSandboxMetricsForDocs(reg)
	case "dns":
		enterpriseMetricsConfig.InitDNSEventsMetricsForDocs(reg)
	case "file":
		enterpriseMetricsConfig.InitFileEventsMetricsForDocs(reg)
	case "http":
		enterpriseMetricsConfig.InitHTTPEventsMetricsForDocs(reg)
	case "icmp":
		enterpriseMetricsConfig.InitICMPEventsMetricsForDocs(reg)
	case "interface":
		enterpriseMetricsConfig.InitInterfaceEventsMetricsForDocs(reg)
	case "tcp":
		enterpriseMetricsConfig.InitTCPEventsMetricsForDocs(reg)
	case "udp":
		enterpriseMetricsConfig.InitUDPEventsMetricsForDocs(reg)
	case "rawsocket":
		enterpriseMetricsConfig.InitRawSocketEventsMetricsForDocs(reg)
	case "tls":
		enterpriseMetricsConfig.InitTLSEventsMetricsForDocs(reg)
	case "process-cache-clean":
		enterpriseMetricsConfig.InitProcessCacheCleanMetricsForDocs(reg)
	case "debug-dns-parser":
		dnsparsermetrics.EnableDebugDNSParserMetrics(reg).InitForDocs()
	case "network":
		enterpriseMetricsConfig.InitNetworkMetricsForDocs(reg)
	case "alerts":
		enterpriseMetricsConfig.InitAlertMetricsForDocs(reg)
	case "appmodel":
		enterpriseMetricsConfig.InitAppModelMetricsForDocs(reg)
	}
	return nil
}
