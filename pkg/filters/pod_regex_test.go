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
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/stretchr/testify/assert"
)

func TestPodRegexFilterBasic(t *testing.T) {
	f := []*fgs.Filter{{PodRegex: []string{"client", "server"}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&PodRegexFilter{}})
	assert.NoError(t, err)
	ev := v1.Event{
		Event: &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessConnect{
				ProcessConnect: &fgs.ProcessConnect{
					Process: &tetragon.Process{
						Pod: &tetragon.Pod{
							Name: "client",
						},
					},
				},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = v1.Event{
		Event: &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessConnect{
				ProcessConnect: &fgs.ProcessConnect{
					Process: &tetragon.Process{
						Pod: &tetragon.Pod{
							Name: "client-deadb33f",
						},
					},
				},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = v1.Event{
		Event: &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &tetragon.Process{
						Pod: &tetragon.Pod{
							Name: "server",
						},
					},
				},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = v1.Event{
		Event: &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessConnect{
				ProcessConnect: &fgs.ProcessConnect{
					Process: &tetragon.Process{
						Pod: &tetragon.Pod{
							Name: "server-deadb33f",
						},
					},
				},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = v1.Event{
		Event: &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessListen{
				ProcessListen: &fgs.ProcessListen{
					Process: &tetragon.Process{
						Pod: &tetragon.Pod{
							Name: "kube-proxy",
						},
					},
				},
			},
		},
	}
	assert.False(t, fl.MatchOne(&ev))
}

func TestPodRegexFilterAdvanced(t *testing.T) {
	f := []*fgs.Filter{{PodRegex: []string{"client.*", "^server$"}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&PodRegexFilter{}})
	assert.NoError(t, err)
	ev := v1.Event{
		Event: &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessConnect{
				ProcessConnect: &fgs.ProcessConnect{
					Process: &tetragon.Process{
						Pod: &tetragon.Pod{
							Name: "client",
						},
					},
				},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = v1.Event{
		Event: &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessConnect{
				ProcessConnect: &fgs.ProcessConnect{
					Process: &tetragon.Process{
						Pod: &tetragon.Pod{
							Name: "client-deadb33f",
						},
					},
				},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = v1.Event{
		Event: &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &tetragon.Process{
						Pod: &tetragon.Pod{
							Name: "server",
						},
					},
				},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = v1.Event{
		Event: &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessConnect{
				ProcessConnect: &fgs.ProcessConnect{
					Process: &tetragon.Process{
						Pod: &tetragon.Pod{
							Name: "server-ab41ed2",
						},
					},
				},
			},
		},
	}
	assert.False(t, fl.MatchOne(&ev))
	ev = v1.Event{
		Event: &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessListen{
				ProcessListen: &fgs.ProcessListen{
					Process: &tetragon.Process{
						Pod: &tetragon.Pod{
							Name: "kube-proxy",
						},
					},
				},
			},
		},
	}
	assert.False(t, fl.MatchOne(&ev))
}

func TestPodRegexFilterInvalidRegex(t *testing.T) {
	f := []*fgs.Filter{{PodRegex: []string{"*"}}}
	_, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&PodRegexFilter{}})
	assert.Error(t, err)
}

func TestPodRegexFilterInvalidEvent(t *testing.T) {
	f := []*fgs.Filter{{PodRegex: []string{".*"}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&PodRegexFilter{}})
	assert.NoError(t, err)
	assert.False(t, fl.MatchOne(nil))
	assert.False(t, fl.MatchOne(&v1.Event{Event: nil}))
	assert.False(t, fl.MatchOne(&v1.Event{Event: struct{}{}}))
	assert.False(t, fl.MatchOne(&v1.Event{Event: &fgs.GetEventsResponse{Event: nil}}))
	assert.False(t, fl.MatchOne(&v1.Event{Event: &fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessConnect{ProcessConnect: &fgs.ProcessConnect{Process: nil}},
	}}))
	assert.False(t, fl.MatchOne(&v1.Event{Event: &fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessExec{ProcessExec: &fgs.ProcessExec{Process: nil}},
	}}))
	assert.False(t, fl.MatchOne(&v1.Event{Event: &fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessListen{ProcessListen: &fgs.ProcessListen{Process: nil}},
	}}))
}
