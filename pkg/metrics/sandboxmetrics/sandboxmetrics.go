//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package sandboxmetrics

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

var (
	eventsSyscalls = metrics.MustNewGranularCounter[metrics.ProcessLabels](prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "sandboxpolicy_syscalls_total",
		Help:        "Sandboxpolicy syscall events observed.",
		ConstLabels: nil,
	}, []string{"policy", "syscall"})
)

func InitEventsMetrics(registry *prometheus.Registry) {
	registry.MustRegister(eventsSyscalls)
}

func InitEventsMetricsForDocs(registry *prometheus.Registry) {
	InitEventsMetrics(registry)
	processLabels := metrics.NewProcessLabels(consts.ExampleNamespace, consts.ExampleWorkload, consts.ExamplePod, consts.ExampleBinary, consts.ExampleNodeName)
	eventsSyscalls.WithLabelValues(processLabels, "example-sandboxpolicy", "example_syscall").Add(0)
}

func HandleEvent(ev *tetragon.ProcessSandboxSyscall) {
	binary, pod, workload, namespace := eventmetrics.GetProcessInfo(ev.Process)
	processLabels := option.CreateProcessLabels(namespace, workload, pod, binary, "")
	eventsSyscalls.WithLabelValues(processLabels, ev.Policy, ev.Name)
}
