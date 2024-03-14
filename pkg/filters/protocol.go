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

	"github.com/cilium/tetragon/api/v1/tetragon"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
	hubbleFilters "github.com/cilium/tetragon/pkg/oldhubble/filters"
)

// ProtocolFilter filters by the protocol field on event types that support it.
// This can be used to filter network events for a specific socket protocol.
type ProtocolFilter struct{}

func (f *ProtocolFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc

	if ff.Protocol != nil {
		filter, err := filterByProtocol(ff.Protocol)
		if err != nil {
			return nil, err
		}
		fs = append(fs, filter)
	}

	return fs, nil
}

func filterByProtocol(fs []tetragon.SocketProtocol) (hubbleFilters.FilterFunc, error) {
	return func(ev *v1.Event) bool {
		res, ok := ev.Event.(*tetragon.GetEventsResponse)
		if !ok {
			return false
		}

		protocol, ok := getProtocol(res)
		if !ok {
			return false
		}

		for _, proto := range fs {
			if proto == protocol {
				return true
			}
		}

		return false
	}, nil
}

func getProtocol(res *tetragon.GetEventsResponse) (tetragon.SocketProtocol, bool) {
	get, ok := tetragon.UnwrapGetEventsResponse(res).(interface {
		GetProtocol() tetragon.SocketProtocol
	})

	if !ok {
		return tetragon.SocketProtocol_UNKNOWN, false
	}

	return get.GetProtocol(), true
}
