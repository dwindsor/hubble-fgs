//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

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
