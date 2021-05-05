// Copyright 2019 Authors of Hubble
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

package config

import (
	_ "embed"
	"reflect"
	"testing"

	"github.com/covalentio/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
)

var writev = `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_write"
spec:
  description: "write hook"
  kprobes:
  - call: "__x64_sys_write"
    return: false
    syscall: true
    args:
      - index: 0
        type: "int"
      - index: 1
        type: "char_buf"
        sizeargindex: 3
      - index: 2
        type: "size_t"
    selectors:
      - matchpids:
        - operator: In
          followforks: true
          isnamespacepid: false
          values:
            - 1
        matchargs:
        - index: 0
          operator: "equal"
          values:
            - "1"
`

var expectedWrite = GenericTracingConf{
	ApiVersion: "hubble-enterprise.io/v1",
	Metadata:   Metadata{Name: "sys_write"},
	Spec: v1alpha1.TracingPolicySpec{
		KProbes: []v1alpha1.KProbeSpec{
			{
				Call:    "__x64_sys_write",
				Return:  false,
				Syscall: true,
				Args: []v1alpha1.KProbeArg{
					{
						Index: 0,
						Type:  "int",
					},
					{
						Index:        1,
						Type:         "char_buf",
						SizeArgIndex: 3,
					},
					{
						Index: 2,
						Type:  "size_t",
					},
				},
				Selectors: []v1alpha1.KProbeSelector{
					{
						MatchPIDs: []v1alpha1.PIDSelector{
							{
								Operator:       "In",
								Values:         []uint32{1},
								FollowForks:    true,
								IsNamespacePID: false,
							},
						},
						MatchArgs: []v1alpha1.ArgSelector{
							{
								Index:    0,
								Operator: "equal",
								Values:   []string{"1"},
							},
						},
					},
				},
			},
		},
	},
}

var data = `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_write"
spec:
  description: "Syscall hook points"
  kprobes:
  - call: "example_func"
    return: true
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1 
      type: "int"
    - index: 2
      type: "int"
    - index: 3
      type: "string"
    - index: 4
      type: "skb"
  - call: "another_func"
    return: false
    syscall: false
    args:
    - index: 0
      type: "string"
    - index: 1 
      type: "string"
    - index: 2
      type: "string"
    - index: 3
      type: "string"
    selectors:
      - matchpids:
        - operator: In
          followforks: true
          isnamespacepid: false
          values:
            - 1
            - 2
        matchargs:
        - index: 0
          operator: "equal"
          values:
            - "1"
        - index: 1
          operator: "notequal" 
          values:
            - "world"
`

var expectedData = GenericTracingConf{
	ApiVersion: "hubble-enterprise.io/v1",
	Metadata:   Metadata{Name: "sys_write"},
	Spec: v1alpha1.TracingPolicySpec{
		KProbes: []v1alpha1.KProbeSpec{
			{
				Call:    "example_func",
				Return:  true,
				Syscall: true,
				Args: []v1alpha1.KProbeArg{
					{
						Index: 0,
						Type:  "int",
					},
					{
						Index: 1,
						Type:  "int",
					},
					{
						Index: 2,
						Type:  "int",
					},
					{
						Index: 3,
						Type:  "string",
					},
					{
						Index: 4,
						Type:  "skb",
					},
				},
			},
			{
				Call:    "another_func",
				Return:  false,
				Syscall: false,
				Args: []v1alpha1.KProbeArg{
					{
						Index: 0,
						Type:  "string",
					},
					{
						Index: 1,
						Type:  "string",
					},
					{
						Index: 2,
						Type:  "string",
					},
					{
						Index: 3,
						Type:  "string",
					},
				},
				Selectors: []v1alpha1.KProbeSelector{
					{
						MatchPIDs: []v1alpha1.PIDSelector{
							{
								Operator:       "In",
								Values:         []uint32{1, 2},
								FollowForks:    true,
								IsNamespacePID: false,
							},
						},
						MatchArgs: []v1alpha1.ArgSelector{
							{
								Index:    0,
								Operator: "equal",
								Values:   []string{"1"},
							},
							{
								Index:    1,
								Operator: "notequal",
								Values:   []string{"world"},
							},
						},
					},
				},
			},
		},
	},
}

func TestYamlWritev(t *testing.T) {
	k, err := ReadConfigYaml(writev)
	if err != nil {
		t.Errorf("YamlWritev error %s", err)
	}
	if reflect.DeepEqual(*k, expectedWrite) != true {
		t.Errorf("not equal\nk=%v\ne= %v\n", k, expectedWrite)
	}
}

func TestYamlData(t *testing.T) {
	k, err := ReadConfigYaml(data)
	if err != nil {
		t.Errorf("YamlData error %s", err)
	}
	if reflect.DeepEqual(*k, expectedData) != true {
		t.Errorf("not equal\nk=%v\ne= %v\n", k, expectedData)
	}
}

//go:embed examples/tracepoint-lseek-pid.yaml
var lseekExample string

func TestYamlLseek(t *testing.T) {

	expected := GenericTracingConf{
		ApiVersion: "hubble-enterprise.io/v1",
		Metadata:   Metadata{Name: "tracepoint-lseek"},
		Spec: v1alpha1.TracingPolicySpec{
			Tracepoints: []v1alpha1.TracepointSpec{{
				Subsystem: "syscalls",
				Event:     "sys_enter_lseek",
				Args: []v1alpha1.KProbeArg{
					{Index: 7},
					{Index: 5},
				},
				Selectors: []v1alpha1.KProbeSelector{{
					MatchPIDs: []v1alpha1.PIDSelector{
						{
							Operator:       "eq",
							FollowForks:    true,
							IsNamespacePID: false,
							Values:         []uint32{1111},
						},
					},
					MatchArgs: []v1alpha1.ArgSelector{
						{
							Index:    7,
							Operator: "eq",
							Values:   []string{"4444"},
						},
					},
				}},
			}},
		},
	}

	k, err := ReadConfigYaml(lseekExample)
	if err != nil {
		t.Errorf("ReadConfigYaml failed: %s", err)
	}

	if reflect.DeepEqual(expected, *k) != true {
		t.Errorf("\ngot:\n%+v\nexpected:\n%+v", *k, expected)
	}
}
