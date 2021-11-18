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
	"github.com/isovalent/hubble-fgs/pkg/api"
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
			case api.MSG_OP_IPV4_ACCEPT:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessAccept{})
			case api.MSG_OP_CRED:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessCred{})
			case api.MSG_OP_TEST:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_Test{})
			case api.MSG_OP_GENERIC_KPROBE:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessKprobe{})
			case api.MSG_OP_HTTP:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessHttp{})
			case api.MSG_OP_IPV4_UDPSTATS:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessSockstats{})
			case api.MSG_OP_IPV4_TCPSTATS:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_ProcessSockstats{})
			case api.MSG_OP_INTERFACE_STATS:
				opCode = reflect.TypeOf(&fgs.GetEventsResponse_InterfaceStats{})
			default:
				return nil, fmt.Errorf("Unknown EventType %s", s)
			}
			types = append(types, opCode)
		}
		fs = append(fs, filterByEventType(types))
	}
	return fs, nil
}
