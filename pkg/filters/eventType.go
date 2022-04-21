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
	"reflect"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	hubbleFilters "github.com/cilium/hubble/pkg/filters"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	codegen "github.com/isovalent/hubble-fgs/api/v1/fgs/codegen/filters"
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
			opCode, err := codegen.OpCodeForEventType(s)
			if err != nil {
				return nil, err
			}
			types = append(types, opCode)
		}
		fs = append(fs, filterByEventType(types))
	}
	return fs, nil
}
