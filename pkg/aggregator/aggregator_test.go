// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aggregator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

func Test_connectEventBasic(t *testing.T) {
	mock := mockServer{make(chan *tetragon.GetEventsResponse, 10)}
	options := tetragon.AggregationOptions{
		WindowSize:        &durationpb.Duration{Seconds: 1},
		ChannelBufferSize: 100,
	}
	agg, err := NewAggregator(&mock, &options)
	assert.NoError(t, err)
	connectA := tetragon.ProcessConnect{
		Process: &tetragon.Process{
			ExecId: "abcd",
		},
		Parent:           nil,
		SourceIp:         "1.1.1.1",
		SourcePort:       &wrapperspb.UInt32Value{Value: 45678},
		DestinationIp:    "2.2.2.2",
		DestinationPort:  &wrapperspb.UInt32Value{Value: 80},
		DestinationNames: nil,
	}
	for i := 0; i < 10; i++ {
		agg.GetEventChannel() <- &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessConnect{
				ProcessConnect: &connectA,
			},
		}
	}
	go agg.Start()
	result := <-mock.aggregatedEvents
	assert.Nil(t, result.GetProcessConnect().SourcePort)
	assert.Equal(t, uint64(10), result.AggregationInfo.Count)
}

func Test_acceptEventBasic(t *testing.T) {
	mock := mockServer{make(chan *tetragon.GetEventsResponse, 10)}
	options := tetragon.AggregationOptions{
		WindowSize:        &durationpb.Duration{Seconds: 1},
		ChannelBufferSize: 100,
	}
	agg, err := NewAggregator(&mock, &options)
	assert.NoError(t, err)
	acceptA := tetragon.ProcessAccept{
		Process: &tetragon.Process{
			ExecId: "abcd",
		},
		Parent:           nil,
		SourceIp:         "1.1.1.1",
		SourcePort:       &wrapperspb.UInt32Value{Value: 80},
		DestinationIp:    "2.2.2.2",
		DestinationPort:  &wrapperspb.UInt32Value{Value: 45678},
		DestinationNames: nil,
	}
	for i := 0; i < 10; i++ {
		agg.GetEventChannel() <- &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessAccept{
				ProcessAccept: &acceptA,
			},
		}
	}
	go agg.Start()
	result := <-mock.aggregatedEvents
	assert.Nil(t, result.GetProcessAccept().DestinationPort)
	assert.Equal(t, uint64(10), result.AggregationInfo.Count)
}

type mockServer struct {
	aggregatedEvents chan *tetragon.GetEventsResponse
}

func (m *mockServer) Send(response *tetragon.GetEventsResponse) error {
	m.aggregatedEvents <- response
	return nil
}

func (m *mockServer) SetHeader(_ metadata.MD) error {
	panic("implement me")
}

func (m *mockServer) SendHeader(_ metadata.MD) error {
	panic("implement me")
}

func (m *mockServer) SetTrailer(_ metadata.MD) {
	panic("implement me")
}

func (m *mockServer) Context() context.Context {
	return context.Background()
}

func (m *mockServer) SendMsg(_ interface{}) error {
	panic("implement me")
}

func (m *mockServer) RecvMsg(_ interface{}) error {
	panic("implement me")
}

func Test_getNameOrIp(t *testing.T) {
	assert.Equal(t, "1.1.1.1", getNameOrIp("1.1.1.1", []string{}))
	assert.Equal(t, "a.com,b.com,c.com", getNameOrIp("1.1.1.1", []string{"b.com", "c.com", "a.com"}))
}
