//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package filters

import (
	"context"
	"fmt"
	"reflect"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	hubbleFilters "github.com/cilium/hubble/pkg/filters"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
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
			case fgs.EventType_PROCESS_CONNECT:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessConnect{})
			case fgs.EventType_PROCESS_LISTEN:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessListen{})
			case fgs.EventType_PROCESS_EXEC:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessExec{})
			case fgs.EventType_PROCESS_TLS:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_Tls{})
			case fgs.EventType_PROCESS_EXIT:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessExit{})
			case fgs.EventType_PROCESS_CLOSE:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessClose{})
			case fgs.EventType_PROCESS_ACCEPT:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessAccept{})
			case fgs.EventType_PROCESS_CRED:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessCred{})
			case fgs.EventType_PROCESS_KPROBE:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessKprobe{})
			case fgs.EventType_PROCESS_TRACEPOINT:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessTracepoint{})
			case fgs.EventType_PROCESS_HTTP:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessHttp{})
			case fgs.EventType_PROCESS_SOCKSTATS:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessSockStats{})
			case fgs.EventType_INTERFACE_STATS:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_InterfaceStats{})
			case fgs.EventType_PROCESS_DNS:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessDns{})
			case fgs.EventType_PROCESS_NETWORK_BURST:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessNetworkBurst{})
			default:
				return nil, fmt.Errorf("Unknown EventType %s", s)
			}
			types = append(types, opCode)
		}
		fs = append(fs, filterByEventType(types))
	}
	return fs, nil
}
