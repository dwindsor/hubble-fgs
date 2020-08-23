// Copyright 2020 Authors of Hubble-FGS
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

package filters

import (
	"context"
	"fmt"
	"reflect"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	hubbleFilters "github.com/cilium/hubble/pkg/filters"
	"github.com/covalentio/hubble-fgs/api/v1/fgs"
	"github.com/covalentio/hubble-fgs/pkg/api"
)

func filterByEventType(types []reflect.Type) hubbleFilters.FilterFunc {
	return func(ev *v1.Event) bool {
		switch event := ev.Event.(type) {
		case *fgs.GetEventsResponse:
			r := reflect.TypeOf(event.Event)
			for _, t := range types {
				if t == r {
					return true
				}
			}
		}
		return false
	}
}

type EventTypeFilter struct{}

func (f *EventTypeFilter) OnBuildFilter(_ context.Context, ff *fgs.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc
	if ff.EventSet != nil {
		var types []reflect.Type

		for _, s := range ff.EventSet {
			var opCode reflect.Type

			switch s {
			case api.MSG_OP_IPV4_TCPCONNECT:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessConnect{})
			case api.MSG_OP_EXECVE:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessExec{})
			case api.MSG_OP_IPV4_LISTEN:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessListen{})
			case api.MSG_OP_TLS:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_Tls{})
			case api.MSG_OP_EXIT:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessExit{})
			case api.MSG_OP_IPV4_TCPCLOSE:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessClose{})
			default:
				return nil, fmt.Errorf("Unknown EventType %s", s)
			}
			types = append(types, opCode)
		}
		fs = append(fs, filterByEventType(types))
	}
	return fs, nil
}
