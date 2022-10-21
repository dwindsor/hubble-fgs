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

	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	ev := &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessListen{
				ProcessListen: &tetragon.ProcessListen{
					Ip: "134.20.1.2",
				},
			},
		},
	}

	// Full mask should match here
	ff, err := filterByCIDR([]*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_LISTEN},
		Cidr:     []string{"134.20.1.2/32"},
	}}, &IPCIDRFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")

	// A bare IP without a mask should produce a filter equivalent to a full mask
	ff, err = filterByCIDR([]*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_LISTEN},
		Cidr:     []string{"134.20.1.2"},
	}}, &IPCIDRFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")

	ff, err = filterByCIDR([]*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_LISTEN},
		Cidr:     []string{"134.20.1.0"},
	}}, &IPCIDRFilter{})
	require.NoError(t, err)
	assert.False(t, ff(ev), "filter should fail")

	ff, err = filterByCIDR([]*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_LISTEN},
		Cidr:     []string{"0.0.0.0"},
	}}, &IPCIDRFilter{})
	require.NoError(t, err)
	assert.False(t, ff(ev), "filter should fail")

	ev = &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessListen{
				ProcessListen: &tetragon.ProcessListen{
					Ip: "134.20.1.137",
				},
			},
		},
	}

	// Full mask should fail to match here
	ff, err = filterByCIDR([]*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_LISTEN},
		Cidr:     []string{"134.20.1.2/32"},
	}}, &IPCIDRFilter{})
	require.NoError(t, err)
	assert.False(t, ff(ev), "filter should fail")

	// A bare IP without a mask should produce a filter equivalent to a full mask
	ff, err = filterByCIDR([]*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_LISTEN},
		Cidr:     []string{"134.20.1.2"},
	}}, &IPCIDRFilter{})
	require.NoError(t, err)
	assert.False(t, ff(ev), "filter should fail")
}

func TestFilterWithNoField(t *testing.T) {
	ev := &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{},
			},
		},
	}

	// f := []*tetragon.Filter{{IpCidr: map[string]string{"PROCESS_EXEC": "134.20.1.2/32"}}}
	f := []*tetragon.Filter{{IpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_LISTEN},
		Cidr:     []string{"134.20.1.2"},
	}}}}
	fl, err := filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&IPCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "filter should always match events without an IP field")
}

func TestIPCIDRFilter(t *testing.T) {
	ev := &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessListen{
				ProcessListen: &tetragon.ProcessListen{
					Ip: "134.20.137.137",
				},
			},
		},
	}

	// f := []*tetragon.Filter{{IpCidr: map[string]string{"PROCESS_LISTEN": "134.20.1.2/8"}}}
	f := []*tetragon.Filter{{IpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_LISTEN},
		Cidr:     []string{"134.20.1.2/8"},
	}}}}
	fl, err := filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&IPCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "CIDR should match first 8 bits of IP")

	f = []*tetragon.Filter{{IpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_LISTEN},
		Cidr:     []string{"134.20.1.2/16"},
	}}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&IPCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "CIDR should match first 16 bits of IP")

	f = []*tetragon.Filter{{IpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_LISTEN},
		Cidr:     []string{"134.20.1.2/24"},
	}}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&IPCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "CIDR should not match first 24 bits of IP")

	f = []*tetragon.Filter{{IpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_LISTEN},
		Cidr:     []string{"134.20.1.2/32"},
	}}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&IPCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "CIDR should not match full IP")
}

func TestSourceCIDRFilter(t *testing.T) {
	ev := &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessConnect{
				ProcessConnect: &tetragon.ProcessConnect{
					SourceIp: "134.20.137.137",
				},
			},
		},
	}

	f := []*tetragon.Filter{{SourceIpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_CONNECT},
		Cidr:     []string{"134.20.1.2/8"},
	}}}}
	fl, err := filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&SourceCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "CIDR should match first 8 bits of IP")

	f = []*tetragon.Filter{{SourceIpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_CONNECT},
		Cidr:     []string{"134.20.1.2/16"},
	}}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&SourceCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "CIDR should match first 16 bits of IP")

	f = []*tetragon.Filter{{SourceIpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_CONNECT},
		Cidr:     []string{"134.20.1.2/24"},
	}}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&SourceCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "CIDR should not match first 24 bits of IP")

	f = []*tetragon.Filter{{SourceIpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_CONNECT},
		Cidr:     []string{"134.20.1.2/32"},
	}}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&SourceCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "CIDR should not match full IP")
}

func TestDestinationCIDRFilter(t *testing.T) {
	ev := &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessConnect{
				ProcessConnect: &tetragon.ProcessConnect{
					DestinationIp: "134.20.137.137",
				},
			},
		},
	}

	f := []*tetragon.Filter{{DestinationIpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_CONNECT},
		Cidr:     []string{"134.20.1.2/8"},
	}}}}
	fl, err := filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "CIDR should match first 8 bits of IP")

	f = []*tetragon.Filter{{DestinationIpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_CONNECT},
		Cidr:     []string{"134.20.1.2/16"},
	}}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "CIDR should match first 16 bits of IP")

	f = []*tetragon.Filter{{DestinationIpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_CONNECT},
		Cidr:     []string{"134.20.1.2/24"},
	}}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "CIDR should not match first 24 bits of IP")

	f = []*tetragon.Filter{{DestinationIpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_CONNECT},
		Cidr:     []string{"134.20.1.2/32"},
	}}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "CIDR should not match full IP")
}

func TestFilterEventTypeMatch(t *testing.T) {
	ev := &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessConnect{
				ProcessConnect: &tetragon.ProcessConnect{
					DestinationIp: "134.20.137.137",
				},
			},
		},
	}

	f := []*tetragon.Filter{{DestinationIpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_CONNECT},
		Cidr:     []string{"134.20.137.137/32"},
	}}}}
	fl, err := filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "filter should match")

	// No connect filter defined for connect but we try to match a connect event.
	// Therefore we should get a match.
	f = []*tetragon.Filter{{DestinationIpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_LISTEN},
		Cidr:     []string{"0.0.0.0/32"},
	}}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "filter should match")

	// Connect filter defined with the wrong IP.
	f = []*tetragon.Filter{{DestinationIpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_CONNECT},
		Cidr:     []string{"0.0.0.0/32"},
	}}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "filter should not match")

	// Untyped filter defined with the wrong IP.
	f = []*tetragon.Filter{{DestinationIpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{},
		Cidr:     []string{"0.0.0.0/32"},
	}}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "filter should not match")

	// Multi-type filter defined with the wrong IP.
	f = []*tetragon.Filter{{DestinationIpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_CONNECT, tetragon.EventType_PROCESS_LISTEN},
		Cidr:     []string{"0.0.0.0/32"},
	}}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "filter should not match")

	// Multi-type filter defined with the correct IP.
	f = []*tetragon.Filter{{DestinationIpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_CONNECT, tetragon.EventType_PROCESS_LISTEN},
		Cidr:     []string{"134.20.137.137/32"},
	}}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "filter should match")

	// Define both a connect and listen filter with the wrong IP.
	f = []*tetragon.Filter{{DestinationIpCidr: []*tetragon.IPFilter{
		{
			EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_LISTEN},
			Cidr:     []string{"0.0.0.0/32"},
		},
		{
			EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_CONNECT},
			Cidr:     []string{"0.0.0.0/32"},
		},
	}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "filter should not match")

	// Define both a connect and listen filter but connect has the right IP.
	f = []*tetragon.Filter{{DestinationIpCidr: []*tetragon.IPFilter{
		{
			EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_LISTEN},
			Cidr:     []string{"0.0.0.0/32"},
		},
		{
			EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_CONNECT},
			Cidr:     []string{"134.20.137.137/32"},
		},
	}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "filter should match")
}

func TestCidrFiltersHttpDns(t *testing.T) {
	ev := &v1.Event{
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

	f := []*tetragon.Filter{{DestinationIpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_HTTP},
		Cidr:     []string{"2.2.0.0/16"},
	}}}}
	fl, err := filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "filter should match")

	f = []*tetragon.Filter{{DestinationIpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_HTTP},
		Cidr:     []string{"0.0.0.0"},
	}}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "filter should not match")

	f = []*tetragon.Filter{{SourceIpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_HTTP},
		Cidr:     []string{"1.1.0.0/16"},
	}}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&SourceCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "filter should match")

	f = []*tetragon.Filter{{SourceIpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_HTTP},
		Cidr:     []string{"0.0.0.0"},
	}}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&SourceCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "filter should not match")

	ev = &v1.Event{
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

	f = []*tetragon.Filter{{DestinationIpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_DNS},
		Cidr:     []string{"2.2.0.0/16"},
	}}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "filter should match")

	f = []*tetragon.Filter{{DestinationIpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_DNS},
		Cidr:     []string{"0.0.0.0"},
	}}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&DestCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "filter should not match")

	f = []*tetragon.Filter{{SourceIpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_DNS},
		Cidr:     []string{"1.1.0.0/16"},
	}}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&SourceCIDRFilter{}})
	require.NoError(t, err)
	assert.True(t, fl.MatchOne(ev), "filter should match")

	f = []*tetragon.Filter{{SourceIpCidr: []*tetragon.IPFilter{{
		EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_DNS},
		Cidr:     []string{"0.0.0.0"},
	}}}}
	fl, err = filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{&SourceCIDRFilter{}})
	require.NoError(t, err)
	assert.False(t, fl.MatchOne(ev), "filter should not match")
}
