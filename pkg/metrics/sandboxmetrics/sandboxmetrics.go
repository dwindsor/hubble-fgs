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
	"slices"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	eventsSyscalls = metrics.MustNewGranularCounter(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "sandboxpolicy_syscalls_total",
		Help:        "Sadnboxoplicy syscall events observed.",
		ConstLabels: nil,
	}, []string{"policy", "syscall"})
)

func InitEventsMetrics(registry *prometheus.Registry) {
	registry.MustRegister(eventsSyscalls.ToProm())
}

func InitEventsMetricsForDocs(registry *prometheus.Registry) {
	InitEventsMetrics(registry)
	eventsSyscalls.WithLabelValues(slices.Concat([]string{"example-sandboxpolicy", "example_syscall"}, consts.ExampleProcessLabels)...).Add(0)
}

func HandleEvent(ev *tetragon.ProcessSandboxSyscall) {
	binary, pod, workload, namespace := eventmetrics.GetProcessInfo(ev.Process)
	eventsSyscalls.WithLabelValues(ev.Policy, ev.Name, namespace, workload, pod, binary)
}
