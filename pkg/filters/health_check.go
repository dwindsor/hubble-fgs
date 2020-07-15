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
	"path"
	"strings"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	hubbleFilters "github.com/cilium/hubble/pkg/filters"
	"github.com/covalentio/hubble-fgs/api/v1/fgs"
)

func commandToStrings(command []string) (string, string) {
	switch len(command) {
	case 0:
		return "", ""
	case 1:
		return command[0], ""
	default:
		return command[0], strings.Join(command[1:], " ")
	}
}

func canBeHealthCheck(process *fgs.Process) bool {
	if process != nil && process.Pod != nil && process.Pod.Container != nil {
		binary, args := commandToStrings(process.Pod.Container.LivenessExecProbe)
		if path.Base(binary) == path.Base(process.Binary) && args == process.Arguments {
			return true
		}
		binary, args = commandToStrings(process.Pod.Container.ReadinessExecProbe)
		if path.Base(binary) == path.Base(process.Binary) && args == process.Arguments {
			return true
		}
	}
	return false
}

func filterByHealthCheck(healthCheck bool) hubbleFilters.FilterFunc {
	return func(ev *v1.Event) bool {
		process := GetProcess(ev)
		if healthCheck == canBeHealthCheck(process) {
			return true
		}
		return false
	}
}

type HealthCheckFilter struct{}

func (f *HealthCheckFilter) OnBuildFilter(_ context.Context, ff *fgs.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc
	if ff.HealthCheck != nil {
		fs = append(fs, filterByHealthCheck(ff.HealthCheck.Value))
	}
	return fs, nil
}
