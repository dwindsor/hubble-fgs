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
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

func TestCELCIDRRange(t *testing.T) {
	log := logger.GetLogger()

	f := []*tetragon.Filter{{CelExpression: []string{"cidr('10.0.0.0/16').containsIP(process_connect.source_ip) && !(process_connect.source_ip in ['10.0.20.137', '10.0.31.128'])"}}}
	ff, err := filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{filters.NewCELExpressionFilter(log)})
	require.NoError(t, err)

	ev := &event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessConnect{
				ProcessConnect: &tetragon.ProcessConnect{
					SourceIp: "10.0.0.1",
				},
			},
		},
	}
	assert.True(t, ff.MatchOne(ev), "cidr range must match")

	ev = &event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessConnect{
				ProcessConnect: &tetragon.ProcessConnect{
					SourceIp: "10.0.20.137",
				},
			},
		},
	}
	assert.False(t, ff.MatchOne(ev), "ip is in exceptions list")

	ev = &event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessConnect{
				ProcessConnect: &tetragon.ProcessConnect{
					SourceIp: "10.0.31.128",
				},
			},
		},
	}
	assert.False(t, ff.MatchOne(ev), "ip is in exceptions list")

	ev = &event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessConnect{
				ProcessConnect: &tetragon.ProcessConnect{
					SourceIp: "127.0.0.1",
				},
			},
		},
	}
	assert.False(t, ff.MatchOne(ev), "ip not in cidr range")
}
