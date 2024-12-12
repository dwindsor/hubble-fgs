package filters

import (
	"context"
	"testing"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCELCIDRRange(t *testing.T) {
	log := logrus.New()

	f := []*tetragon.Filter{{CelExpression: []string{"cidr('10.0.0.0/16').containsIP(process_connect.source_ip) && !(process_connect.source_ip in ['10.0.20.137', '10.0.31.128'])"}}}
	ff, err := filters.BuildFilterList(context.Background(), f, []filters.OnBuildFilter{filters.NewCELExpressionFilter(log)})
	require.NoError(t, err)

	ev := &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessConnect{
				ProcessConnect: &tetragon.ProcessConnect{
					SourceIp: "10.0.0.1",
				},
			},
		},
	}
	assert.True(t, ff.MatchOne(ev), "cidr range must match")

	ev = &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessConnect{
				ProcessConnect: &tetragon.ProcessConnect{
					SourceIp: "10.0.20.137",
				},
			},
		},
	}
	assert.False(t, ff.MatchOne(ev), "ip is in exceptions list")

	ev = &v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessConnect{
				ProcessConnect: &tetragon.ProcessConnect{
					SourceIp: "10.0.31.128",
				},
			},
		},
	}
	assert.False(t, ff.MatchOne(ev), "ip is in exceptions list")

	ev = &v1.Event{
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
