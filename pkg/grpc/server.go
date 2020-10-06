// Copyright 2020 Authors of Hubble
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

package grpc

import (
	"context"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	hubbleFilters "github.com/cilium/hubble/pkg/filters"
	"github.com/covalentio/hubble-fgs/api/v1/fgs"
	"github.com/covalentio/hubble-fgs/pkg/filters"
	"github.com/covalentio/hubble-fgs/pkg/logger"
)

type observer interface {
	EnableSensor(ctx context.Context, name string) error
	DisableSensor(ctx context.Context, name string) error
}

type Server struct {
	notifier notifier
	observer observer
}

type getEventsListener struct {
	events chan *fgs.GetEventsResponse
}

func NewServer(notifier notifier, observer observer) *Server {
	return &Server{
		notifier: notifier,
		observer: observer,
	}
}

func newListener() *getEventsListener {
	return &getEventsListener{
		events: make(chan *fgs.GetEventsResponse, 100),
	}
}

func (l *getEventsListener) notify(res *fgs.GetEventsResponse) {
	l.events <- res
}

func (s *Server) GetEvents(request *fgs.GetEventsRequest, server fgs.FineGuidanceSensors_GetEventsServer) error {
	logger.GetLogger().WithField("request", request).Debug("Received a GetEvents request")
	allowList, err := filters.BuildFilterList(context.Background(), request.AllowList, filters.Filters)
	if err != nil {
		return err
	}
	denyList, err := filters.BuildFilterList(context.Background(), request.DenyList, filters.Filters)
	if err != nil {
		return err
	}
	l := newListener()
	s.notifier.addListener(l)
	defer s.notifier.removeListener(l)
	for {
		select {
		case event := <-l.events:
			if hubbleFilters.Apply(allowList, denyList, &v1.Event{Event: event}) {
				if err = server.Send(event); err != nil {
					return err
				}
			}
		case <-server.Context().Done():
			return server.Context().Err()
		}
	}
}

func (s *Server) GetHealth(ctx context.Context, request *fgs.GetHealthStatusRequest) (*fgs.GetHealthStatusResponse, error) {
	logger.GetLogger().WithField("request", request).Debug("Received a GetHealth request")
	return getHealth()
}

func (s *Server) EnableSensor(ctx context.Context, req *fgs.EnableSensorRequest) (*fgs.EnableSensorResponse, error) {
	logger.GetLogger().WithField("request", req).Debug("Received a EnableSensor request")
	name := req.GetName()
	err := s.observer.EnableSensor(ctx, name)
	var ret *fgs.EnableSensorResponse = nil
	if err == nil {
		// NB: just return the (same) name as an id for now.
		ret = &fgs.EnableSensorResponse{Id: name}
	}
	return ret, err
}

func (s *Server) DisableSensor(ctx context.Context, req *fgs.DisableSensorRequest) (*fgs.DisableSensorResponse, error) {
	logger.GetLogger().WithField("request", req).Debug("Received a DisableSensor request")
	res := &fgs.DisableSensorResponse{}
	err := s.observer.DisableSensor(ctx, req.GetId())
	return res, err
}
