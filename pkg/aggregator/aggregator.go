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
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

type Aggregator struct {
	server tetragon.FineGuidanceSensors_GetEventsServer
	window time.Duration
	events chan *tetragon.GetEventsResponse
	cache  map[string]*tetragon.GetEventsResponse
}

func NewAggregator(
	server tetragon.FineGuidanceSensors_GetEventsServer,
	options *tetragon.AggregationOptions,
) (*Aggregator, error) {
	if options == nil {
		return nil, nil
	}
	window := 15 * time.Second
	if options.WindowSize != nil {
		window = options.WindowSize.AsDuration()
	}
	return &Aggregator{
		server,
		window,
		make(chan *tetragon.GetEventsResponse, options.ChannelBufferSize),
		make(map[string]*tetragon.GetEventsResponse),
	}, nil
}

func (a *Aggregator) Start() {
	// nolint Since Aggregator.Start is an endless function,
	// this qualifies as an acceptable use of time.Tick
	tick := time.Tick(a.window)
	for {
		select {
		case event := <-a.events:
			a.handleEvent(event)
		case <-tick:
			a.flush()
		}
	}
}

func (a *Aggregator) flush() {
	for _, event := range a.cache {
		if err := a.server.Send(event); err != nil {
			logger.GetLogger().Warn("Failed to send aggregated response", logfields.Error, err)
		}
	}
	// clear the cache.
	a.cache = make(map[string]*tetragon.GetEventsResponse)
}

func (a *Aggregator) handleEvent(event *tetragon.GetEventsResponse) {
	switch event.Event.(type) {
	case *tetragon.GetEventsResponse_ProcessAccept:
		a.handleProcessAccept(event)
	case *tetragon.GetEventsResponse_ProcessConnect:
		a.handleProcessConnect(event)
	default:
		if err := a.server.Send(event); err != nil {
			logger.GetLogger().Warn("Failed to send unaggregated response", logfields.Error, err)
		}
	}
}

func getNameOrIp(ip string, names []string) string {
	if len(names) > 0 {
		sort.Strings(names)
		return strings.Join(names, ",")
	}
	return ip
}

func (a *Aggregator) handleProcessAccept(event *tetragon.GetEventsResponse) {
	acceptEvent := event.GetProcessAccept()
	key := fmt.Sprintf("%d:%s:%s:%d:%s",
		tetragon.EventType_PROCESS_ACCEPT,
		acceptEvent.Process.ExecId,
		acceptEvent.SourceIp,
		acceptEvent.SourcePort.Value,
		getNameOrIp(acceptEvent.DestinationIp, acceptEvent.DestinationNames),
	)
	current := a.cache[key]
	if current == nil {
		acceptEvent.DestinationPort = nil
		event.AggregationInfo = &tetragon.AggregationInfo{Count: 1}
		a.cache[key] = event
	} else {
		current.AggregationInfo.Count++
	}
}

func (a *Aggregator) handleProcessConnect(event *tetragon.GetEventsResponse) {
	connectEvent := event.GetProcessConnect()
	key := fmt.Sprintf("%d:%s:%s:%s:%d",
		tetragon.EventType_PROCESS_CONNECT,
		connectEvent.Process.ExecId,
		connectEvent.SourceIp,
		getNameOrIp(connectEvent.DestinationIp, connectEvent.DestinationNames),
		connectEvent.DestinationPort.Value,
	)
	current := a.cache[key]
	if current == nil {
		connectEvent.SourcePort = nil
		event.AggregationInfo = &tetragon.AggregationInfo{Count: 1}
		a.cache[key] = event
	} else {
		current.AggregationInfo.Count++
	}
}

func (a *Aggregator) GetEventChannel() chan *tetragon.GetEventsResponse {
	return a.events
}
