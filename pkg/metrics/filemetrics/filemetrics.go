//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package filemetrics

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	fileTotalEvents = prometheus.NewCounter(prometheus.CounterOpts{
		Name:      "file_events_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Total number of process_file events (independently of going through the eventcache).",
	})

	fileTotalCacheEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "file_cache_events_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Total number of process_file events (that go in/out the eventcache).",
	}, []string{"direction"})

	fileTotalActionEvents = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "file_actions_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Total file events per action",
	}, []string{"node", "namespace", "workload", "pod", "policy", "rule", "action", "operation"})

	fileTotalErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "file_errors_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Total number of process_file event errors (can be from the grpc or sensor).",
	}, []string{"reason"})

	fileFailedDigest = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "file_digest_fail_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Total number of failures in getting the file digest.",
	}, []string{"event"})
)

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(fileTotalEvents)
	registry.MustRegister(fileTotalCacheEvents)
	registry.MustRegister(fileTotalActionEvents)
	registry.MustRegister(fileTotalErrors)
	registry.MustRegister(fileFailedDigest)
}

func FileTotalEventsInc() {
	fileTotalEvents.Inc()
}

func FileTotalCacheInEventsInc() {
	fileTotalCacheEvents.WithLabelValues("in").Inc()
}

func FileTotalCacheOutEventsInc() {
	fileTotalCacheEvents.WithLabelValues("out").Inc()
}

func FileTotalActionEventsInc(node, namespace, workload, pod, policy, rule, action, operation string) {
	fileTotalActionEvents.WithLabelValues(node, namespace, workload, pod, policy, rule, action, operation).Inc()
}

func FileTotalErrorsInc(reason string) {
	fileTotalErrors.WithLabelValues(reason).Inc()
}

func FileFailedDigestInc(event string) {
	fileFailedDigest.WithLabelValues(event).Inc()
}
