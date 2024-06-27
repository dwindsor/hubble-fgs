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

	"github.com/isovalent/metricstool/pkg/metricsmd"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/pkg/metricsconfig"

	enterpriseMetricsConfig "github.com/isovalent/hubble-fgs/pkg/metricsconfig"
)

func main() {
	if err := New().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func New() *cobra.Command {
	targets := map[string]string{
		"health":         "Tetragon Health",
		"resources":      "Tetragon Resources",
		"health-dns":     "Tetragon DNS Sensor Health",
		"health-file":    "Tetragon File Sensor Health",
		"health-http":    "Tetragon HTTP Sensor Health",
		"health-network": "Tetragon Network Sensors Health",
		"health-tls":     "Tetragon TLS Sensor Health",
		"events":         "Tetragon Events",
		"dns":            "Tetragon DNS",
		"file":           "Tetragon File",
		"http":           "Tetragon HTTP",
		"icmp":           "Tetragon ICMP",
		"interface":      "Tetragon Interface",
		"tcp":            "Tetragon TCP",
		"udp":            "Tetragon UDP",
		"rawsocket":      "Tetragon Raw Socket",
		"tls":            "Tetragon TLS",
		"sandbox":        "Tetragon SandboxPolicy metrics",
	}

	overrides := []metricsmd.LabelOverrides{
		// Theses metrics takes VCS info into account supplied at build
		// time, which changes every build, so override those.
		{
			Metric: "go_info",
			Overrides: []metricsmd.LabelValues{
				{
					Label:  "version",
					Values: []string{"go1.22.0"},
				},
			},
		},
		{
			Metric: "tetragon_build_info",
			Overrides: []metricsmd.LabelValues{
				{
					Label:  "commit",
					Values: []string{"931b70f2c9878ba985ba6b589827bea17da6ec33"},
				},
				{
					Label:  "go_version",
					Values: []string{"go1.22.0"},
				},
				{
					Label:  "modified",
					Values: []string{"false"},
				},
				{
					Label:  "time",
					Values: []string{"2022-05-13T15:54:45Z"},
				},
			},
		},
	}

	config := &metricsmd.Config{
		Targets:        targets,
		LabelOverrides: overrides,
		InitMetrics:    initMetrics,
		HeadingLevel:   1,
	}

	cmd, err := metricsmd.NewCmd(nil, nil, config)
	if err != nil {
		slog.Error("failed to create metrics-docs command", "error", err)
	}
	return cmd
}

func initMetrics(target string, reg *prometheus.Registry, _ *slog.Logger) error {
	switch target {
	case "health":
		metricsconfig.InitHealthMetricsForDocs(reg)
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
	}
	return nil
}
