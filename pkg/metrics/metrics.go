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

	"github.com/covalentio/hubble-fgs/api/v1/fgs"
	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/reader"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type ErrorType string

const (
	// Parent process was not found in the pid map for a process without the clone flag.
	NoParentNoClone ErrorType = "no_parent_no_clone"
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

func getTlsInfo(tls *fgs.Tls) (binary string, namespace string) {
	return "", ""
}

func handleOriginalEvent(originalEvent interface{}) {
	var flags uint32
	switch msg := originalEvent.(type) {
	case *api.MsgExecveEventUnix:
		flags = msg.Pid.Curr.Flags
	}
	for _, flag := range reader.DecodeCommonFlags(flags) {
		FlagCount.WithLabelValues(flag).Inc()
	}
}

func handleProcessedEvent(processedEvent interface{}) {
	var eventType, namespace, binary string
	switch ev := processedEvent.(type) {
	case *fgs.GetEventsResponse:
		switch ev.Event.(type) {
		case *fgs.GetEventsResponse_ProcessConnect:
			binary, namespace = getProcessInfo(ev.GetProcessConnect().GetProcess())
			eventType = "process_connect"
		case *fgs.GetEventsResponse_ProcessExec:
			binary, namespace = getProcessInfo(ev.GetProcessExec().GetProcess())
			eventType = "process_exec"
		case *fgs.GetEventsResponse_ProcessListen:
			binary, namespace = getProcessInfo(ev.GetProcessListen().GetProcess())
			eventType = "process_listen"
		case *fgs.GetEventsResponse_Tls:
			binary, namespace = getTlsInfo(ev.GetTls())
			eventType = "tls"
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
