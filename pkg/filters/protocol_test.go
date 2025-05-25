// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package filters

import (
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/event"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetProtocol(t *testing.T) {
	// Connect event with UDP protocol
	ev := &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessConnect{
			ProcessConnect: &tetragon.ProcessConnect{
				Protocol: tetragon.SocketProtocol_UDP,
			},
		},
	}

	proto, ok := getProtocol(ev)
	assert.True(t, ok, "getProtocol should succeed")
	assert.Equal(t, tetragon.SocketProtocol_UDP, proto)

	// Connect event with no protocol defined
	ev = &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessConnect{
			ProcessConnect: &tetragon.ProcessConnect{},
		},
	}

	proto, ok = getProtocol(ev)
	assert.True(t, ok, "getProtocol should succeed")
	assert.Equal(t, tetragon.SocketProtocol_UNKNOWN, proto)

	// Accept event with TCP protocol
	ev = &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessAccept{
			ProcessAccept: &tetragon.ProcessAccept{
				Protocol: tetragon.SocketProtocol_TCP,
			},
		},
	}

	proto, ok = getProtocol(ev)
	assert.True(t, ok, "getProtocol should succeed")
	assert.Equal(t, tetragon.SocketProtocol_TCP, proto)

	// Icmp event with TCP protocol
	ev = &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessIcmp{
			ProcessIcmp: &tetragon.ProcessIcmp{
				Protocol: tetragon.SocketProtocol_TCP,
			},
		},
	}

	proto, ok = getProtocol(ev)
	assert.True(t, ok, "getProtocol should succeed")
	assert.Equal(t, tetragon.SocketProtocol_TCP, proto)

	// Listen event with TCP protocol
	ev = &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessListen{
			ProcessListen: &tetragon.ProcessListen{
				Protocol: tetragon.SocketProtocol_TCP,
			},
		},
	}

	proto, ok = getProtocol(ev)
	assert.True(t, ok, "getProtocol should succeed")
	assert.Equal(t, tetragon.SocketProtocol_TCP, proto)

	// Close event with TCP protocol
	ev = &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessClose{
			ProcessClose: &tetragon.ProcessClose{
				Protocol: tetragon.SocketProtocol_TCP,
			},
		},
	}

	proto, ok = getProtocol(ev)
	assert.True(t, ok, "getProtocol should succeed")
	assert.Equal(t, tetragon.SocketProtocol_TCP, proto)

	// Event type with no protocol
	ev = &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{},
	}

	_, ok = getProtocol(ev)
	assert.False(t, ok, "getProtocol should fail")
}

func TestFilterByProtocolMatch(t *testing.T) {
	ev := &event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessConnect{
				ProcessConnect: &tetragon.ProcessConnect{
					Protocol: tetragon.SocketProtocol_UDP,
				},
			},
		},
	}

	ff, err := filterByProtocol([]tetragon.SocketProtocol{tetragon.SocketProtocol_UDP})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")
}

func TestFilterByProtocolNoMatch(t *testing.T) {
	ev := &event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessConnect{
				ProcessConnect: &tetragon.ProcessConnect{
					Protocol: tetragon.SocketProtocol_UDP,
				},
			},
		},
	}

	ff, err := filterByProtocol([]tetragon.SocketProtocol{tetragon.SocketProtocol_TCP})
	require.NoError(t, err)
	assert.False(t, ff(ev), "filter should fail")
}

func TestFilterByProtocolMulti(t *testing.T) {
	ev := &event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessConnect{
				ProcessConnect: &tetragon.ProcessConnect{
					Protocol: tetragon.SocketProtocol_UDP,
				},
			},
		},
	}

	ff, err := filterByProtocol([]tetragon.SocketProtocol{tetragon.SocketProtocol_TCP, tetragon.SocketProtocol_UDP})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")
}

func TestFilterByProtocolEmpty(t *testing.T) {
	ev := &event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessConnect{
				ProcessConnect: &tetragon.ProcessConnect{
					Protocol: tetragon.SocketProtocol_UDP,
				},
			},
		},
	}

	ff, err := filterByProtocol([]tetragon.SocketProtocol{})
	require.NoError(t, err)
	assert.False(t, ff(ev), "filter should fail")
}
