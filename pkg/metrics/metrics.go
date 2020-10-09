// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metrics

import (
	"net/http"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/covalentio/hubble-fgs/api/v1/fgs"
	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/filters"
	"github.com/covalentio/hubble-fgs/pkg/reader"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type ErrorType string

const (
	// Parent process was not found in the pid map for a process without the clone flag.
	NoParentNoClone ErrorType = "no_parent_no_clone"
	// Process not found on get() call.
	ProcessCacheMissOnGet ErrorType = "process_cache_miss_on_get"
	// Process evicted from the cache.
	ProcessCacheEvicted ErrorType = "process_cache_evicted"
	// Process not found on remove() call.
	ProcessCacheMissOnRemove ErrorType = "process_cache_miss_on_remove"
)

var (
	EventsProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        "isovalent_fgs_events_total",
		Help:        "The total number of FGS events",
		ConstLabels: nil,
	}, []string{"type", "namespace", "binary"})
	FlagCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        "isovalent_fgs_flags_total",
		Help:        "The total number of FGS flags. For internal use only.",
		ConstLabels: nil,
	}, []string{"type"})
	ErrorCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        "isovalent_fgs_errors_total",
		Help:        "The total number of FGS errors. For internal use only.",
		ConstLabels: nil,
	}, []string{"type"})
	ExecveMapSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        "isovalent_fgs_map_in_use_gauge",
		Help:        "The total number of in-use entries per map.",
		ConstLabels: nil,
	}, []string{"map", "total"})
	LruMapSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        "isovalent_fgs_lru_in_use_gauge",
		Help:        "The total number of LRU in-use entries.",
		ConstLabels: nil,
	}, []string{"map", "total"})
)

func getProcessInfo(process *fgs.Process) (binary string, namespace string) {
	if process != nil {
		binary = process.Binary
		if process.Pod != nil {
			namespace = process.Pod.Namespace
		}
	}
	return binary, namespace
}

func handleOriginalEvent(originalEvent interface{}) {
	var flags uint32
	switch msg := originalEvent.(type) {
	case *api.MsgExecveEventUnix:
		flags = msg.Process.Flags
	}
	for _, flag := range reader.DecodeCommonFlags(flags) {
		FlagCount.WithLabelValues(flag).Inc()
	}
}

func handleProcessedEvent(processedEvent interface{}) {
	var eventType, namespace, binary string
	switch ev := processedEvent.(type) {
	case *fgs.GetEventsResponse:
		binary, namespace = getProcessInfo(filters.GetProcess(&v1.Event{Event: ev}))
		switch ev.Event.(type) {
		case *fgs.GetEventsResponse_ProcessConnect:
			eventType = fgs.EventType_PROCESS_CONNECT.String()
		case *fgs.GetEventsResponse_ProcessClose:
			eventType = fgs.EventType_PROCESS_CLOSE.String()
		case *fgs.GetEventsResponse_ProcessExec:
			eventType = fgs.EventType_PROCESS_EXEC.String()
		case *fgs.GetEventsResponse_ProcessListen:
			eventType = fgs.EventType_PROCESS_LISTEN.String()
		case *fgs.GetEventsResponse_Tls:
			eventType = fgs.EventType_PROCESS_TLS.String()
		case *fgs.GetEventsResponse_ProcessExit:
			eventType = fgs.EventType_PROCESS_EXIT.String()
		case *fgs.GetEventsResponse_ProcessCred:
			eventType = fgs.EventType_PROCESS_CRED.String()
		}
	default:
		eventType = "unknown"
	}
	EventsProcessed.WithLabelValues(eventType, namespace, binary).Inc()

}

func ProcessEvent(originalEvent interface{}, processedEvent interface{}) {
	handleOriginalEvent(originalEvent)
	handleProcessedEvent(processedEvent)
}

func EnableMetrics(address string) {
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(address, nil)
}
