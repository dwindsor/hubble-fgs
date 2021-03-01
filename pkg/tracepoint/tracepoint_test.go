// Copyright 2021 Authors of Hubble
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

package tracepoint

import (
	"reflect"
	"testing"
)

func TestTracepointLoadFormat(t *testing.T) {
	gt := Tracepoint{
		Subsys: "task",
		Event:  "task_newtask",
	}

	err := gt.LoadFormat()
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	fields := []TracepointFieldFormat{
		TracepointFieldFormat{
			FieldStr: "unsigned short common_type",
			Offset:   0,
			Size:     2,
			IsSigned: false,
		},
		TracepointFieldFormat{
			FieldStr: "unsigned char common_flags",
			Offset:   2,
			Size:     1,
			IsSigned: false,
		},
		TracepointFieldFormat{
			FieldStr: "unsigned char common_preempt_count",
			Offset:   3,
			Size:     1,
			IsSigned: false,
		},
		TracepointFieldFormat{
			FieldStr: "int common_pid",
			Offset:   4,
			Size:     4,
			IsSigned: true,
		},
		TracepointFieldFormat{
			FieldStr: "pid_t pid",
			Offset:   8,
			Size:     4,
			IsSigned: true,
		},
		TracepointFieldFormat{
			FieldStr: "char comm[16]",
			Offset:   12,
			Size:     16,
			IsSigned: true,
		},
		TracepointFieldFormat{
			FieldStr: "unsigned long clone_flags",
			Offset:   32,
			Size:     8,
			IsSigned: false,
		},
		TracepointFieldFormat{
			FieldStr: "short oom_score_adj",
			Offset:   40,
			Size:     2,
			IsSigned: true,
		},
	}

	// NB: ID does not seem to be the same across systems, so we check only fields
	if !reflect.DeepEqual(&fields, &gt.Format.Fields) {
		t.Logf("Unexpected result:\nexpected:%v\ngot     :%v\n", &fields, &gt.Format.Fields)
		t.Fail()
	}
}

func TestTracepointsAll(t *testing.T) {

	tracepoints, err := GetAllTracepoints()
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	for _, tp := range tracepoints {
		err := tp.LoadFormat()
		if err != nil {
			t.Logf("failed to load information for %s/%s: %s", tp.Subsys, tp.Event, err)
			t.Fail()
		}
		for _, field := range tp.Format.Fields {
			err := field.ParseField()
			if err != nil {
				t.Logf("FYI: failed to parse field '%s' of %s/%s: %s", field.FieldStr, tp.Subsys, tp.Event, err)
				// NB: we do not support all different types yet, so we dont fail here.
				// t.Fail()
			}
		}
	}
}
