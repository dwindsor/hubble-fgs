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
	"context"
	"testing"

	"github.com/cilium/tetragon/pkg/event"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

func TestGetIPAddrsFromEvents(t *testing.T) {
	// Event type with source and dest IPs but no IP field
	ev := &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessConnect{
			ProcessConnect: &tetragon.ProcessConnect{
				SourceIp:      "127.0.0.1",
				DestinationIp: "0.0.0.0",
			},
		},
	}

	ip, ok := getSourceIP(ev)
	assert.True(t, ok, "getSourceIP should succeed")
	assert.Equal(t, "127.0.0.1", ip)

	ip, ok = getDestinationIP(ev)
	assert.True(t, ok, "getDestinationIP should succeed")
	assert.Equal(t, "0.0.0.0", ip)

	ip, ok = getIP(ev)
	assert.False(t, ok, "getIP should fail")
	assert.Equal(t, "", ip)

	// Event type with no IPs
	ev = &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{},
	}

	ip, ok = getSourceIP(ev)
	assert.False(t, ok, "getSourceIP should fail")
	assert.Equal(t, "", ip)

	ip, ok = getDestinationIP(ev)
	assert.False(t, ok, "getDestinationIP should fail")
	assert.Equal(t, "", ip)

	ip, ok = getIP(ev)
	assert.False(t, ok, "getIP should fail")
	assert.Equal(t, "", ip)
}

func TestFilterByCIDR(t *testing.T) {
	ev := &event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessListen{
				ProcessListen: &tetragon.ProcessListen{
					Ip: "134.20.1.2",
				},
			},
		},
	}

	// Full mask should match here
	ff, err := filterByCIDR([]string{"134.20.1.2/32"}, &IPCIDRFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")

	// A bare IP without a mask should produce a filter equivalent to a full mask
	ff, err = filterByCIDR([]string{"134.20.1.2"}, &IPCIDRFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")

	ff, err = filterByCIDR([]string{"134.20.1.0"}, &IPCIDRFilter{})
	require.NoError(t, err)
	assert.False(t, ff(ev), "filter should fail")

	ff, err = filterByCIDR([]string{"0.0.0.0"}, &IPCIDRFilter{})
	require.NoError(t, err)
	assert.False(t, ff(ev), "filter should fail")

	ev = &event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessListen{
				ProcessListen: &tetragon.ProcessListen{
					Ip: "134.20.1.137",
				},
			},
		},
	}

	// Full mask should fail to match here
	ff, err = filterByCIDR([]string{"134.20.1.2/32"}, &IPCIDRFilter{})
	require.NoError(t, err)
	assert.False(t, ff(ev), "filter should fail")

	// A bare IP without a mask should produce a filter equivalent to a full mask
	ff, err = filterByCIDR([]string{"134.20.1.2"}, &IPCIDRFilter{})
	require.NoError(t, err)
	assert.False(t, ff(ev), "filter should fail")
}

func TestFilterByCIDR_IPv6(t *testing.T) {
	ev := &event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessListen{
				ProcessListen: &tetragon.ProcessListen{
					Ip: "::1",
				},
			},
		},
	}

	// Full mask should match here
	ff, err := filterByCIDR([]string{"::1"}, &IPCIDRFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")

	// Full mask should match here
	ff, err = filterByCIDR([]string{"::1/128"}, &IPCIDRFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")

	ev = &event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessListen{
				ProcessListen: &tetragon.ProcessListen{
					Ip: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
				},
			},
		},
	}

	// Full mask should match here
	ff, err = filterByCIDR([]string{"2001:0db8:85a3:0000:0000:8a2e:0370:7334"}, &IPCIDRFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")

	// Full mask should match here
	ff, err = filterByCIDR([]string{"2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"}, &IPCIDRFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")

	// Mask first 32 bits
	ff, err = filterByCIDR([]string{"2001:0db8::/32"}, &IPCIDRFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")

	// Mask everything
	ff, err = filterByCIDR([]string{"::/0"}, &IPCIDRFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")

	// Empty CIDR
	ff, err = filterByCIDR([]string{"::"}, &IPCIDRFilter{})
	require.NoError(t, err)
	assert.False(t, ff(ev), "filter should not pass")
}

func TestFilterWithNoField(t *testing.T) {
	ev := &event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{},
			},
		},
	}

	f := []*tetragon.Filter{{IpCidr: []string{"134.20.1.2"}}}
	fl, err := filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&IPCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "filter not match events without an IP field")
}

func TestIPCIDRFilter(t *testing.T) {
	ev := &event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessListen{
				ProcessListen: &tetragon.ProcessListen{
					Ip: "134.20.137.137",
				},
			},
		},
	}

	f := []*tetragon.Filter{{IpCidr: []string{"134.20.1.2/8"}}}
	fl, err := filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&IPCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "CIDR should match first 8 bits of IP")

	f = []*tetragon.Filter{{IpCidr: []string{"134.20.1.2/16"}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&IPCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "CIDR should match first 16 bits of IP")

	f = []*tetragon.Filter{{IpCidr: []string{"134.20.1.2/24"}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&IPCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "CIDR should not match first 24 bits of IP")

	f = []*tetragon.Filter{{IpCidr: []string{"134.20.1.2/32"}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&IPCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "CIDR should not match full IP")
}

func TestSourceCIDRFilter(t *testing.T) {
	ev := &event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessConnect{
				ProcessConnect: &tetragon.ProcessConnect{
					SourceIp: "134.20.137.137",
				},
			},
		},
	}

	f := []*tetragon.Filter{{SourceIpCidr: []string{"134.20.1.2/8"}}}
	fl, err := filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&SourceCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "CIDR should match first 8 bits of IP")

	f = []*tetragon.Filter{{SourceIpCidr: []string{"134.20.1.2/16"}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&SourceCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "CIDR should match first 16 bits of IP")

	f = []*tetragon.Filter{{SourceIpCidr: []string{"134.20.1.2/24"}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&SourceCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "CIDR should not match first 24 bits of IP")

	f = []*tetragon.Filter{{SourceIpCidr: []string{"134.20.1.2/32"}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&SourceCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "CIDR should not match full IP")
}

func TestDestinationCIDRFilter(t *testing.T) {
	ev := &event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessConnect{
				ProcessConnect: &tetragon.ProcessConnect{
					DestinationIp: "134.20.137.137",
				},
			},
		},
	}

	f := []*tetragon.Filter{{DestinationIpCidr: []string{"134.20.1.2/8"}}}
	fl, err := filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "CIDR should match first 8 bits of IP")

	f = []*tetragon.Filter{{DestinationIpCidr: []string{"134.20.1.2/16"}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "CIDR should match first 16 bits of IP")

	f = []*tetragon.Filter{{DestinationIpCidr: []string{"134.20.1.2/24"}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "CIDR should not match first 24 bits of IP")

	f = []*tetragon.Filter{{DestinationIpCidr: []string{"134.20.1.2/32"}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "CIDR should not match full IP")
}

func TestFilterEventTypeMatch(t *testing.T) {
	ev := &event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessConnect{
				ProcessConnect: &tetragon.ProcessConnect{
					DestinationIp: "134.20.137.137",
				},
			},
		},
	}

	f := []*tetragon.Filter{{
		EventSet:          []tetragon.EventType{tetragon.EventType_PROCESS_CONNECT},
		DestinationIpCidr: []string{"134.20.137.137/32"},
	}}
	fl, err := filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&filters.EventTypeFilter{}, &DestCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "filter should match")

	f = []*tetragon.Filter{{
		EventSet:          []tetragon.EventType{tetragon.EventType_PROCESS_LISTEN},
		DestinationIpCidr: []string{"134.20.137.137/32"},
	}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&filters.EventTypeFilter{}, &DestCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "filter should not match wrong event type")

	f = []*tetragon.Filter{{
		EventSet:          []tetragon.EventType{tetragon.EventType_PROCESS_LISTEN, tetragon.EventType_PROCESS_CONNECT},
		DestinationIpCidr: []string{"134.20.137.137/32"},
	}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&filters.EventTypeFilter{}, &DestCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "filter should match")
}

func TestCidrFiltersHttpDns(t *testing.T) {
	ev := &event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessHttp{
				ProcessHttp: &tetragon.ProcessHttp{
					Socket: &tetragon.SockInfo{
						SourceIp:      "1.1.1.1",
						DestinationIp: "2.2.2.2",
					},
				},
			},
		},
	}

	f := []*tetragon.Filter{{DestinationIpCidr: []string{"2.2.0.0/16"}}}
	fl, err := filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "filter should match")

	f = []*tetragon.Filter{{DestinationIpCidr: []string{"0.0.0.0"}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "filter should not match")

	f = []*tetragon.Filter{{SourceIpCidr: []string{"1.1.0.0/16"}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&SourceCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "filter should match")

	f = []*tetragon.Filter{{SourceIpCidr: []string{"0.0.0.0"}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&SourceCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "filter should not match")

	ev = &event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessDns{
				ProcessDns: &tetragon.ProcessDns{
					Socket: &tetragon.SockInfo{
						SourceIp:      "1.1.1.1",
						DestinationIp: "2.2.2.2",
					},
				},
			},
		},
	}

	f = []*tetragon.Filter{{DestinationIpCidr: []string{"2.2.0.0/16"}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "filter should match")

	f = []*tetragon.Filter{{DestinationIpCidr: []string{"0.0.0.0"}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "filter should not match")

	f = []*tetragon.Filter{{SourceIpCidr: []string{"1.1.0.0/16"}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&SourceCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "filter should match")

	f = []*tetragon.Filter{{SourceIpCidr: []string{"0.0.0.0"}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&SourceCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "filter should not match")
}
