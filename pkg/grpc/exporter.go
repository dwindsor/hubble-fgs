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

package grpc

import (
	"context"
	"encoding/json"

	"github.com/covalentio/hubble-fgs/api/v1/fgs"
	"github.com/covalentio/hubble-fgs/pkg/logger"
	"google.golang.org/grpc/metadata"
)

type Exporter struct {
	ctx     context.Context
	request *fgs.GetEventsRequest
	server  *Server
	encoder *json.Encoder
	done    chan bool
}

func NewExporter(
	ctx context.Context,
	request *fgs.GetEventsRequest,
	server *Server,
	encoder *json.Encoder,
) *Exporter {
	return &Exporter{ctx, request, server, encoder, make(chan bool)}
}

func (e *Exporter) Start() {
	if err := e.server.GetEvents(e.request, e); err != nil {
		logger.GetLogger().WithError(err).Error("Failed to start JSON exporter")
	}
	e.done <- true
}

func (e *Exporter) Send(event *fgs.GetEventsResponse) error {
	if err := e.encoder.Encode(event); err != nil {
		logger.GetLogger().WithError(err).Warning("Failed to JSON encode")
	}
	return nil
}

func (e *Exporter) SetHeader(metadata.MD) error {
	return nil
}

func (e *Exporter) SendHeader(metadata.MD) error {
	return nil
}

func (e *Exporter) SetTrailer(metadata.MD) {
}

func (e *Exporter) Context() context.Context {
	return e.ctx
}

func (e *Exporter) SendMsg(_ interface{}) error {
	return nil
}

func (e *Exporter) RecvMsg(_ interface{}) error {
	return nil
}
