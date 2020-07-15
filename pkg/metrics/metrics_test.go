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
	"strings"
	"testing"

	"github.com/covalentio/hubble-fgs/api/v1/fgs"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestProcessEvent(t *testing.T) {
	assert.NoError(t, testutil.CollectAndCompare(eventsProcessed, strings.NewReader("")))
	ProcessEvent(nil)
	// empty process
	ProcessEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessConnect{ProcessConnect: &fgs.ProcessConnect{}}})
	ProcessEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExec{ProcessExec: &fgs.ProcessExec{}}})
	ProcessEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessListen{ProcessListen: &fgs.ProcessListen{}}})

	// empty pod
	ProcessEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessConnect{ProcessConnect: &fgs.ProcessConnect{
		Process: &fgs.Process{Binary: "binary_a"},
	}}})
	ProcessEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExec{ProcessExec: &fgs.ProcessExec{
		Process: &fgs.Process{Binary: "binary_b"},
	}}})
	ProcessEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessListen{ProcessListen: &fgs.ProcessListen{
		Process: &fgs.Process{Binary: "binary_c"},
	}}})

	// with pod
	ProcessEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessConnect{ProcessConnect: &fgs.ProcessConnect{
		Process: &fgs.Process{
			Binary: "binary_a",
			Pod:    &fgs.Pod{Namespace: "namespace_a"},
		},
	}}})
	ProcessEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExec{ProcessExec: &fgs.ProcessExec{
		Process: &fgs.Process{
			Binary: "binary_b",
			Pod:    &fgs.Pod{Namespace: "namespace_b"},
		},
	}}})
	ProcessEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessListen{ProcessListen: &fgs.ProcessListen{
		Process: &fgs.Process{
			Binary: "binary_c",
			Pod:    &fgs.Pod{Namespace: "namespace_c"},
		},
	}}})

	expected := strings.NewReader(`# HELP isovalent_fgs_events_total The total number of FGS events
# TYPE isovalent_fgs_events_total counter
isovalent_fgs_events_total{binary="",namespace="",type="process_connect"} 1
isovalent_fgs_events_total{binary="",namespace="",type="process_exec"} 1
isovalent_fgs_events_total{binary="",namespace="",type="process_listen"} 1
isovalent_fgs_events_total{binary="",namespace="",type="unknown"} 1
isovalent_fgs_events_total{binary="binary_a",namespace="",type="process_connect"} 1
isovalent_fgs_events_total{binary="binary_a",namespace="namespace_a",type="process_connect"} 1
isovalent_fgs_events_total{binary="binary_b",namespace="",type="process_exec"} 1
isovalent_fgs_events_total{binary="binary_b",namespace="namespace_b",type="process_exec"} 1
isovalent_fgs_events_total{binary="binary_c",namespace="",type="process_listen"} 1
isovalent_fgs_events_total{binary="binary_c",namespace="namespace_c",type="process_listen"} 1
`)
	assert.NoError(t, testutil.CollectAndCompare(eventsProcessed, expected))
}
