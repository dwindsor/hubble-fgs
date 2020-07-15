// Copyright 2019-2020 Authors of Hubble
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
	"testing"

	"github.com/covalentio/hubble-fgs/api/v1/fgs"
	"github.com/stretchr/testify/assert"
)

func Test_commandToStrings(t *testing.T) {
	binary, args := commandToStrings(nil)
	assert.Equal(t, "", binary)
	assert.Equal(t, "", args)
	binary, args = commandToStrings([]string{})
	assert.Equal(t, "", binary)
	assert.Equal(t, "", args)
	binary, args = commandToStrings([]string{"a"})
	assert.Equal(t, "a", binary)
	assert.Equal(t, "", args)
	binary, args = commandToStrings([]string{"a", "b"})
	assert.Equal(t, "a", binary)
	assert.Equal(t, "b", args)
	binary, args = commandToStrings([]string{"a", "b", "c"})
	assert.Equal(t, "a", binary)
	assert.Equal(t, "b c", args)
}

func Test_canBeHealthCheck(t *testing.T) {
	assert.False(t, canBeHealthCheck(nil))
	assert.False(t, canBeHealthCheck(&fgs.Process{
		Binary:    "myprogram",
		Arguments: "arg-a arg-b argc",
	}))
	assert.False(t, canBeHealthCheck(&fgs.Process{
		Binary:    "myprogram",
		Arguments: "arg-a arg-b argc",
		Pod:       &fgs.Pod{},
	}))
	assert.False(t, canBeHealthCheck(&fgs.Process{
		Binary:    "myprogram",
		Arguments: "arg-a arg-b argc",
		Pod: &fgs.Pod{
			Container: &fgs.Container{},
		},
	}))
	assert.False(t, canBeHealthCheck(&fgs.Process{
		Binary:    "/usr/bin/myprogram",
		Arguments: "arg-a arg-b arg-c",
		Pod: &fgs.Pod{
			Container: &fgs.Container{
				LivenessExecProbe: []string{"myprogram", "arg-a", "arg-b"},
			},
		},
	}))
	assert.False(t, canBeHealthCheck(&fgs.Process{
		Binary:    "/usr/bin/myprogram",
		Arguments: "arg-a arg-b arg-c",
		Pod: &fgs.Pod{
			Container: &fgs.Container{
				ReadinessExecProbe: []string{"myprogram", "arg-a", "arg-b"},
			},
		},
	}))
	assert.True(t, canBeHealthCheck(&fgs.Process{
		Binary:    "/usr/bin/myprogram",
		Arguments: "arg-a arg-b arg-c",
		Pod: &fgs.Pod{
			Container: &fgs.Container{
				LivenessExecProbe: []string{"myprogram", "arg-a", "arg-b", "arg-c"},
			},
		},
	}))
	assert.True(t, canBeHealthCheck(&fgs.Process{
		Binary:    "/usr/bin/myprogram",
		Arguments: "arg-a arg-b arg-c",
		Pod: &fgs.Pod{
			Container: &fgs.Container{
				ReadinessExecProbe: []string{"myprogram", "arg-a", "arg-b", "arg-c"},
			},
		},
	}))
}
