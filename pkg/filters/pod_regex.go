// Copyright 2020 Authors of Cilium
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
	"regexp"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	hubbleFilters "github.com/cilium/hubble/pkg/filters"
	"github.com/cilium/tetragon/api/v1/tetragon"
)

func filterByPodRegex(podPatterns []string) (hubbleFilters.FilterFunc, error) {
	var pods []*regexp.Regexp
	for _, pattern := range podPatterns {
		query, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regexp: %v", err)
		}
		pods = append(pods, query)
	}
	return func(ev *v1.Event) bool {
		process := GetProcess(ev)
		if process == nil {
			return false
		}
		if process.Pod == nil {
			return false
		}
		for _, pod := range pods {
			if pod.MatchString(process.Pod.Name) {
				return true
			}
		}
		return false
	}, nil
}

type PodRegexFilter struct{}

func (f *PodRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc
	if ff.PodRegex != nil {
		dnsFilters, err := filterByPodRegex(ff.PodRegex)
		if err != nil {
			return nil, err
		}
		fs = append(fs, dnsFilters)
	}
	return fs, nil
}
