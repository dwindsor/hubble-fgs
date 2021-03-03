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
	"reflect"
	"testing"
)

var writev = `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_write"
spec:
  description: "write hook"
  kprobe:
    function:
    - call: "__x64_sys_write"
      return: false 
      syscall: true
      args:
      - type: "int"
        filters:
        - op: "eq"
          value: "1"
      - type: "char_buf"
        meta: "3"
      - type: "size_t"
      filters:
      - type: pidset
        op: "eq"
        value: "1"
`

var expectedWrite = GenericKprobeConfig{
	ApiVersion: "hubble-enterprise.io/v1",
	Metadata:   Metadata{Name: "sys_write"},
	Spec: Spec{
		Description: "write hook",
		Kprobe: Kprobe{
			Function: []Function{
				{
					Call:    "__x64_sys_write",
					Return:  false,
					Syscall: true,
					Args: []Arg{
						{
							Type: "int",
							Filters: []Filter{
								{
									Op:    "eq",
									Value: "1",
								},
							},
						},
						{
							Type: "char_buf",
							Meta: "3",
						},
						{
							Type: "size_t",
						},
					},
					Filters: []Filter{
						{
							Type:  "pidset",
							Op:    "eq",
							Value: "1",
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
  kprobe:
    function:
    - call: "example_func"
      return: true
      syscall: true
      args:
      - type: "int"
        filters:
        - op: "lt"
          value: "3"
      - type: "int"
        filters:
        - op: "gt"
          value: "4"
      - type: "int"
        filters:
        - op: "eq"
          value: "4"
      - type: "string"
      - type: "skb"
    - call: "another_func"
      return: false
      syscall: false
      args:
      - type: string
        filters:
        - value: "fooby"
      - type: string
        filters:
        - value: "fooby"
      - type: string
        filters:
        - value: "fooby"
      filters:
      - type: nspid
        op: "eq"
        value: "3"
      - type: pid
        op: "eq"
        value: "1"
      - type: pidset
        op: "eq"
        value: "1"
      - type: notpidset
        op: "eq"
        value: "1"
      - type: notnspidset
        op: "eq"
        value: "1"
`

var expectedData = GenericKprobeConfig{
	ApiVersion: "hubble-enterprise.io/v1",
	Metadata:   Metadata{Name: "sys_write"},
	Spec: Spec{
		Description: "Syscall hook points",
		Kprobe: Kprobe{
			Function: []Function{
				{
					Call:    "example_func",
					Return:  true,
					Syscall: true,
					Args: []Arg{
						{
							Type: "int",
							Filters: []Filter{
								{
									Op:    "lt",
									Value: "3",
								},
							},
						},
						{
							Type: "int",
							Filters: []Filter{
								{
									Op:    "gt",
									Value: "4",
								},
							},
						},
						{
							Type: "int",
							Filters: []Filter{
								{
									Op:    "eq",
									Value: "4",
								},
							},
						},
						{
							Type: "string",
						},
						{
							Type: "skb",
						},
					},
					Filters: nil,
				}, {

					Call:    "another_func",
					Return:  false,
					Syscall: false,
					Args: []Arg{
						{
							Type: "string",
							Filters: []Filter{
								{
									Value: "fooby",
								},
							},
						},
						{
							Type: "string",
							Filters: []Filter{
								{
									Value: "fooby",
								},
							},
						},
						{
							Type: "string",
							Filters: []Filter{
								{
									Value: "fooby",
								},
							},
						},
					},
					Filters: []Filter{
						{
							Type:  "nspid",
							Op:    "eq",
							Value: "3",
						},
						{
							Type:  "pid",
							Op:    "eq",
							Value: "1",
						},
						{
							Type:  "pidset",
							Op:    "eq",
							Value: "1",
						},
						{
							Type:  "notpidset",
							Op:    "eq",
							Value: "1",
						},
						{
							Type:  "notnspidset",
							Op:    "eq",
							Value: "1",
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
		t.Errorf("not equal\nk=%v\ne= %v\n", k, expectedData)
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
