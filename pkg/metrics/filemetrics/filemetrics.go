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
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	// Needed to fix metrics prefix
	_ "github.com/isovalent/hubble-fgs/pkg/metrics/fixuposs"
)

var (
	fileTotalEvents = promauto.NewCounter(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "file_total_events",
		Help: "Total number of process_file events (independently of going through the eventcache).",
	})

	fileTotalCacheEvents = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "file_total_cache_events",
		Help: "Total number of process_file events (that go in/out the eventcache).",
	}, []string{"direction"})

	fileTotalActionEvents = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "file_total_actions",
		Help: "Total file events per action",
	}, []string{"action"})

	fileTotalErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "file_total_errors",
		Help: "Total number of process_file event errors (can be from the grpc or sensor).",
	})
)

func FileTotalEvents() prometheus.Counter {
	return fileTotalEvents
}

func FileTotalCacheInEventsInc() {
	fileTotalCacheEvents.WithLabelValues("in").Inc()
}

func FileTotalCacheOutEventsInc() {
	fileTotalCacheEvents.WithLabelValues("out").Inc()
}

func FileTotalActionEvents() *prometheus.CounterVec {
	return fileTotalActionEvents
}

func FileTotalErrors() prometheus.Counter {
	return fileTotalErrors
}
