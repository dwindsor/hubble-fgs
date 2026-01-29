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
	"slices"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/event"
	ossFilters "github.com/cilium/tetragon/pkg/filters"
)

func filterByPolicyName(values []string) ossFilters.FilterFunc {
	return func(ev *event.Event) bool {
		policyName := ossFilters.GetPolicyName(ev)
		if policyName != "" {
			return slices.Contains(values, policyName)
		}

		if ev == nil {
			return false
		}
		response, ok := ev.Event.(*tetragon.GetEventsResponse)
		if !ok {
			return false
		}

		// EE Policies
		switch ev := (response.Event).(type) {
		case *tetragon.GetEventsResponse_ProcessFile:
			policyName = ev.ProcessFile.GetPolicyName()
		default:
			return false
		}
		return slices.Contains(values, policyName)
	}
}

type PolicyNamesFilter struct{}

func (f *PolicyNamesFilter) OnBuildFilter(_ context.Context, filter *tetragon.Filter) ([]ossFilters.FilterFunc, error) {
	var fs []ossFilters.FilterFunc

	if filter.PolicyNames != nil {
		fs = append(fs, filterByPolicyName(filter.PolicyNames))
	}
	return fs, nil
}
