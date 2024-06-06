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

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilterByDestinationNames(t *testing.T) {
	testCase := func(name string, ev *v1.Event) {
		ff, err := filterByURIRegex([]string{}, &DestinationNamesRegexFilter{})
		require.NoError(t, err)
		assert.False(t, ff(ev), name+": filter should fail")

		ff, err = filterByURIRegex([]string{"example"}, &DestinationNamesRegexFilter{})
		require.NoError(t, err)
		assert.True(t, ff(ev), name+": filter should pass")

		ff, err = filterByURIRegex([]string{"example.com"}, &DestinationNamesRegexFilter{})
		require.NoError(t, err)
		assert.True(t, ff(ev), name+": filter should pass")

		ff, err = filterByURIRegex([]string{"example.ca"}, &DestinationNamesRegexFilter{})
		require.NoError(t, err)
		assert.True(t, ff(ev), name+": filter should pass")

		ff, err = filterByURIRegex([]string{"example.co.uk"}, &DestinationNamesRegexFilter{})
		require.NoError(t, err)
		assert.False(t, ff(ev), name+": filter should false")

		ff, err = filterByURIRegex([]string{"ex.*"}, &DestinationNamesRegexFilter{})
		require.NoError(t, err)
		assert.True(t, ff(ev), name+": filter should pass")

		ff, err = filterByURIRegex([]string{"^www.ex.*$"}, &DestinationNamesRegexFilter{})
		require.NoError(t, err)
		assert.True(t, ff(ev), name+": filter should pass")

		ff, err = filterByURIRegex([]string{"^ex.*$"}, &DestinationNamesRegexFilter{})
		require.NoError(t, err)
		assert.False(t, ff(ev), name+": filter should fail")

		ff, err = filterByURIRegex([]string{"bad", "example"}, &DestinationNamesRegexFilter{})
		require.NoError(t, err)
		assert.True(t, ff(ev), name+": filter should pass")
	}

	testCase("connect", &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessConnect{
				ProcessConnect: &tetragon.ProcessConnect{
					DestinationNames: []string{"www.example.com", "www.example.ca"},
				},
			},
		},
	})

	testCase("close", &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessClose{
				ProcessClose: &tetragon.ProcessClose{
					DestinationNames: []string{"www.example.com", "www.example.ca"},
				},
			},
		},
	})

	testCase("accept", &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessAccept{
				ProcessAccept: &tetragon.ProcessAccept{
					DestinationNames: []string{"www.example.com", "www.example.ca"},
				},
			},
		},
	})

	testCase("http_sockinfo", &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessHttp{
				ProcessHttp: &tetragon.ProcessHttp{
					Socket: &tetragon.SockInfo{
						DestinationNames: []string{"www.example.com", "www.example.ca"},
					},
				},
			},
		},
	})

	testCase("dns_sockinfo", &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessDns{
				ProcessDns: &tetragon.ProcessDns{
					Socket: &tetragon.SockInfo{
						DestinationNames: []string{"www.example.com", "www.example.ca"},
					},
				},
			},
		},
	})

	testCase("sockstats_sockinfo", &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessSockStats{
				ProcessSockStats: &tetragon.ProcessSockStats{
					Socket: &tetragon.SockInfo{
						DestinationNames: []string{"www.example.com", "www.example.ca"},
					},
				},
			},
		},
	})
}

func TestFilterBySNIName(t *testing.T) {
	ev := &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_Tls{
				Tls: &tetragon.Tls{
					SniName: "example.com",
				},
			},
		},
	}

	ff, err := filterByURIRegex([]string{}, &SNIRegexFilter{})
	require.NoError(t, err)
	assert.False(t, ff(ev), "filter should fail")

	ff, err = filterByURIRegex([]string{"example"}, &SNIRegexFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")

	ff, err = filterByURIRegex([]string{"example.com"}, &SNIRegexFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")

	ff, err = filterByURIRegex([]string{"example.co.uk"}, &SNIRegexFilter{})
	require.NoError(t, err)
	assert.False(t, ff(ev), "filter should false")

	ff, err = filterByURIRegex([]string{"ex.*"}, &SNIRegexFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")

	ff, err = filterByURIRegex([]string{"^ex.*$"}, &SNIRegexFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")

	ff, err = filterByURIRegex([]string{"^www.ex.*$"}, &SNIRegexFilter{})
	require.NoError(t, err)
	assert.False(t, ff(ev), "filter should fail")

	ff, err = filterByURIRegex([]string{"bad", "example"}, &SNIRegexFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")
}

func TestFilterByURI(t *testing.T) {
	ev := &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessHttp{
				ProcessHttp: &tetragon.ProcessHttp{
					Http: &tetragon.HttpInfo{
						Request: &tetragon.HttpRequest{
							Uri: "example.com",
						},
					},
				},
			},
		},
	}

	ff, err := filterByURIRegex([]string{}, &URIRegexFilter{})
	require.NoError(t, err)
	assert.False(t, ff(ev), "filter should fail")

	ff, err = filterByURIRegex([]string{"example"}, &URIRegexFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")

	ff, err = filterByURIRegex([]string{"example.com"}, &URIRegexFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")

	ff, err = filterByURIRegex([]string{"example.co.uk"}, &URIRegexFilter{})
	require.NoError(t, err)
	assert.False(t, ff(ev), "filter should false")

	ff, err = filterByURIRegex([]string{"ex.*"}, &URIRegexFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")

	ff, err = filterByURIRegex([]string{"^ex.*$"}, &URIRegexFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")

	ff, err = filterByURIRegex([]string{"^www.ex.*$"}, &URIRegexFilter{})
	require.NoError(t, err)
	assert.False(t, ff(ev), "filter should fail")

	ff, err = filterByURIRegex([]string{"bad", "example"}, &URIRegexFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")
}

func TestFilterByDestinationPod(t *testing.T) {
	testCase := func(name string, ev *v1.Event) {
		ff, err := filterByURIRegex([]string{}, &DestinationPodRegexFilter{})
		require.NoError(t, err)
		assert.False(t, ff(ev), name+": filter should fail")

		ff, err = filterByURIRegex([]string{"amazing"}, &DestinationPodRegexFilter{})
		require.NoError(t, err)
		assert.True(t, ff(ev), name+": filter should pass")

		ff, err = filterByURIRegex([]string{"amazing-pod"}, &DestinationPodRegexFilter{})
		require.NoError(t, err)
		assert.True(t, ff(ev), name+": filter should pass")

		ff, err = filterByURIRegex([]string{"amazing-pod-foobar"}, &DestinationPodRegexFilter{})
		require.NoError(t, err)
		assert.False(t, ff(ev), name+": filter should fail")

		ff, err = filterByURIRegex([]string{"amazing$"}, &DestinationPodRegexFilter{})
		require.NoError(t, err)
		assert.False(t, ff(ev), name+": filter should fail")

		ff, err = filterByURIRegex([]string{"bad", "amazing"}, &DestinationPodRegexFilter{})
		require.NoError(t, err)
		assert.True(t, ff(ev), name+": filter should pass")
	}

	testCase("connect", &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessConnect{
				ProcessConnect: &tetragon.ProcessConnect{
					DestinationPod: &tetragon.Pod{
						Name: "amazing-pod",
					},
				},
			},
		},
	})

	testCase("close", &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessClose{
				ProcessClose: &tetragon.ProcessClose{
					DestinationPod: &tetragon.Pod{
						Name: "amazing-pod",
					},
				},
			},
		},
	})

	testCase("accept", &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessAccept{
				ProcessAccept: &tetragon.ProcessAccept{
					DestinationPod: &tetragon.Pod{
						Name: "amazing-pod",
					},
				},
			},
		},
	})

	testCase("http_sockinfo", &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessHttp{
				ProcessHttp: &tetragon.ProcessHttp{
					Socket: &tetragon.SockInfo{
						DestinationPod: &tetragon.Pod{
							Name: "amazing-pod",
						},
					},
				},
			},
		},
	})

	testCase("dns_sockinfo", &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessDns{
				ProcessDns: &tetragon.ProcessDns{
					Socket: &tetragon.SockInfo{
						DestinationPod: &tetragon.Pod{
							Name: "amazing-pod",
						},
					},
				},
			},
		},
	})

	testCase("sockstats_sockinfo", &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessSockStats{
				ProcessSockStats: &tetragon.ProcessSockStats{
					Socket: &tetragon.SockInfo{
						DestinationPod: &tetragon.Pod{
							Name: "amazing-pod",
						},
					},
				},
			},
		},
	})
}

func TestFilterByHost(t *testing.T) {
	ev := &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessHttp{
				ProcessHttp: &tetragon.ProcessHttp{
					Http: &tetragon.HttpInfo{
						Request: &tetragon.HttpRequest{
							Host: "example.com",
						},
					},
				},
			},
		},
	}

	ff, err := filterByURIRegex([]string{}, &HostRegexFilter{})
	require.NoError(t, err)
	assert.False(t, ff(ev), "filter should fail")

	ff, err = filterByURIRegex([]string{"example"}, &HostRegexFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")

	ff, err = filterByURIRegex([]string{"example.com"}, &HostRegexFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")

	ff, err = filterByURIRegex([]string{"example.co.uk"}, &HostRegexFilter{})
	require.NoError(t, err)
	assert.False(t, ff(ev), "filter should false")

	ff, err = filterByURIRegex([]string{"ex.*"}, &HostRegexFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")

	ff, err = filterByURIRegex([]string{"^ex.*$"}, &HostRegexFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")

	ff, err = filterByURIRegex([]string{"^www.ex.*$"}, &HostRegexFilter{})
	require.NoError(t, err)
	assert.False(t, ff(ev), "filter should fail")

	ff, err = filterByURIRegex([]string{"bad", "example"}, &HostRegexFilter{})
	require.NoError(t, err)
	assert.True(t, ff(ev), "filter should pass")
}
