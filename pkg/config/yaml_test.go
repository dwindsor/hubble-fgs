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

package config

import (
	_ "embed"
	"reflect"
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
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
        sizeArgIndex: 3
      - index: 2
        type: "size_t"
    selectors:
      - matchPIDs:
        - operator: In
          followForks: true
          isNamespacePID: false
          values:
            - 1
        matchArgs:
        - index: 0
          operator: "equal"
          values:
            - "1"
        matchNamespaces:
        - namespace: Net
          operator: In
          values:
            - "4026532024"
            - "4026532025"
        - namespace: Mnt
          operator: NotIn
          values:
            - "4026532099"
        matchNamespaceChanges:
        - operator: In
          values:
          - "Mnt"
          - "Pid"
          - "User"
          - "Uts"
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
						MatchNamespaces: []v1alpha1.NamespaceSelector{
							{
								Namespace: "Net",
								Operator:  "In",
								Values:    []string{"4026532024", "4026532025"},
							},
							{
								Namespace: "Mnt",
								Operator:  "NotIn",
								Values:    []string{"4026532099"},
							},
						},
						MatchNamespaceChanges: []v1alpha1.NamespaceChangesSelector{
							{
								Operator: "In",
								Values:   []string{"Mnt", "Pid", "User", "Uts"},
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
      - matchPIDs:
        - operator: In
          followForks: true
          isNamespacePID: false
          values:
            - 1
            - 2
        matchArgs:
        - index: 0
          operator: "equal"
          values:
            - "1"
        - index: 1
          operator: "notequal" 
          values:
            - "world"
        matchNamespaces:
        - namespace: Pid
          operator: In
          values:
          - 4026532024
        matchNamespaceChanges:
        - operator: In
          values:
          - "Mnt"
          - "Pid"
          - "Net"
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
						MatchNamespaces: []v1alpha1.NamespaceSelector{
							{
								Namespace: "Pid",
								Operator:  "In",
								Values:    []string{"4026532024"},
							},
						},
						MatchNamespaceChanges: []v1alpha1.NamespaceChangesSelector{
							{
								Operator: "In",
								Values:   []string{"Mnt", "Pid", "Net"},
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

var (
	tlsExample = `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "tls-example"
spec:
  description: "tls parser spec"
  parser:
    tls:
      mode: "tc"
`
)

func TestYamlTls(t *testing.T) {
	expected := GenericTracingConf{
		ApiVersion: "hubble-enterprise.io/v1",
		Metadata:   Metadata{Name: "tls-example"},
		Spec: v1alpha1.TracingPolicySpec{
			Parser: v1alpha1.ParserPolicySpec{
				Tls: v1alpha1.TlsSpec{
					Mode: "tc",
				},
			},
		},
	}

	k, err := ReadConfigYaml(tlsExample)
	if err != nil {
		t.Errorf("ReadConfigYaml failed: %s", err)
	}

	if reflect.DeepEqual(expected, *k) != true {
		t.Errorf("\ngot:\n%+v\nexpected:\n%+v", *k, expected)
	}
}
