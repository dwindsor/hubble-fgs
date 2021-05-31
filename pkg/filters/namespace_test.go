// Copyright 2019-2020 Authors of Hubble
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

package filters

import (
	"context"
	"testing"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/stretchr/testify/assert"
)

func TestNamespace(t *testing.T) {
	f := []*fgs.Filter{{Namespace: []string{"kube-system", ""}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&NamespaceFilter{}})
	assert.NoError(t, err)
	ev := v1.Event{
		Event: &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessConnect{
				ProcessConnect: &fgs.ProcessConnect{Process: &fgs.Process{Pod: &fgs.Pod{Namespace: "kube-system"}}},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = v1.Event{
		Event: &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{Process: &fgs.Process{Pod: &fgs.Pod{Namespace: "kube-system"}}},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = v1.Event{
		Event: &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessListen{
				ProcessListen: &fgs.ProcessListen{Process: &fgs.Process{Pod: &fgs.Pod{Namespace: "kube-system"}}},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = v1.Event{
		Event: &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessListen{
				ProcessListen: &fgs.ProcessListen{Process: &fgs.Process{Pod: &fgs.Pod{Namespace: "default"}}},
			},
		},
	}
	assert.False(t, fl.MatchOne(&ev))

	ev = v1.Event{Event: &fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessConnect{ProcessConnect: &fgs.ProcessConnect{}}}}
	assert.False(t, fl.MatchOne(&ev))
	ev = v1.Event{Event: &fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExec{ProcessExec: &fgs.ProcessExec{}}}}
	assert.False(t, fl.MatchOne(&ev))
	ev = v1.Event{Event: &fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessListen{ProcessListen: &fgs.ProcessListen{}}}}
	assert.False(t, fl.MatchOne(&ev))

	// Empty namespace matches process without pod info.
	ev = v1.Event{Event: &fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessConnect{ProcessConnect: &fgs.ProcessConnect{Process: &fgs.Process{}}}}}
	assert.True(t, fl.MatchOne(&ev))
	ev = v1.Event{Event: &fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExec{ProcessExec: &fgs.ProcessExec{Process: &fgs.Process{}}}}}
	assert.True(t, fl.MatchOne(&ev))
	ev = v1.Event{Event: &fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessListen{ProcessListen: &fgs.ProcessListen{Process: &fgs.Process{}}}}}
	assert.True(t, fl.MatchOne(&ev))
}
