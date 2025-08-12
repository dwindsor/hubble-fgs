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
