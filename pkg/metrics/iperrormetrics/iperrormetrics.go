//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package iperrormetrics

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/prometheus/client_golang/prometheus"
)

var IpErrorToString = []string{
	0:  "Header error",
	1:  "No heap available",
	2:  "Read IPv6 next failed (probe)",
	3:  "Read IPv6 next failed (skb_load)",
	4:  "Read IPv6 next failed (skb)",
	5:  "Unknown IPv6 extension",
	6:  "Too many IPv6 extensions",
	7:  "UDP stack no cookie",
	8:  "UDP stack read version failed",
	9:  "UDP stack read IP header failed",
	10: "UDP stack read UDP header failed",
	11: "UDP stack no payload offset",
	12: "UDP stack invalid IP version",
	13: "UDP stack burst no process",
	14: "UDP stack burst no PID",
	15: "UDP stack read payload failed",
	16: "UDP send no socket info",
	17: "UDP send no cookie",
	18: "UDP recv no cookie",
	19: "UDP recv read IP header failed",
	20: "UDP recv read UDP header failed",
	21: "UDP recv invalid IP version",
	22: "UDP sock create no cookie",
	23: "UDP sock release no cookie",
	24: "UDP failed to read IP option",
	25: "UDP retprobe add failed",
	26: "UDP retprobe delete failed",
	27: "UDP sock release no sock",
	28: "UDP send missing process",
	29: "UDP recv missing process",
	30: "Update socketmap no process",
	31: "Socket discovery no process",
	32: "Socket discovery read error",
	33: "UDP sock create no process",
	34: "Socket discovery no sk",
	35: "UDP sock create PID=0",
	36: "UDP sequence check read payload flags",
	37: "UDP sequence check read payload data",
}

var (
	processIpErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "layer3_event_errors_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Errors propagated to userspace by the L3 event sensors",
	}, []string{"error", "version"})
)

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(processIpErrors)

	for _, error := range IpErrorToString {
		for _, version := range networkapi.IPFamilies {
			ProcessIpErrors(error, version).Add(0)
		}
	}
}

func ProcessIpErrors(err string, version string) prometheus.Counter {
	return processIpErrors.WithLabelValues(err, version)
}
