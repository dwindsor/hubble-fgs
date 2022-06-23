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

func TestBinaryRegexFilterBasic(t *testing.T) {
	f := []*fgs.Filter{{BinaryRegex: []string{"iptable", "systemd"}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&BinaryRegexFilter{}})
	assert.NoError(t, err)
	ev := v1.Event{
		Event: &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessConnect{
				ProcessConnect: &fgs.ProcessConnect{
					Process: &tetragon.Process{Binary: "/sbin/iptables"},
				},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = v1.Event{
		Event: &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &tetragon.Process{Binary: "/sbin/iptables-restore"},
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
						Binary: "/usr/lib/systemd/systemd",
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
						Binary: "/usr/lib/systemd/systemd-journald",
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
						Binary: "kube-proxy",
					},
				},
			},
		},
	}
	assert.False(t, fl.MatchOne(&ev))
}

func TestBinaryRegexFilterAdvanced(t *testing.T) {
	f := []*fgs.Filter{{BinaryRegex: []string{"/usr/sbin/.*", "^/usr/lib/systemd/systemd$"}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&BinaryRegexFilter{}})
	assert.NoError(t, err)
	ev := v1.Event{
		Event: &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessConnect{
				ProcessConnect: &fgs.ProcessConnect{
					Process: &tetragon.Process{
						Binary: "/usr/sbin/dnsmasq",
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
						Binary: "/usr/sbin/logrotate",
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
						Binary: "/usr/lib/systemd/systemd",
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
						Binary: "/usr/lib/systemd/systemd-logind",
					},
				},
			},
		},
	}
	assert.False(t, fl.MatchOne(&ev))
}

func TestBinaryRegexFilterInvalidRegex(t *testing.T) {
	f := []*fgs.Filter{{BinaryRegex: []string{"*"}}}
	_, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&BinaryRegexFilter{}})
	assert.Error(t, err)
}

func TestBinaryRegexFilterInvalidEvent(t *testing.T) {
	f := []*fgs.Filter{{BinaryRegex: []string{".*"}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&BinaryRegexFilter{}})
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
