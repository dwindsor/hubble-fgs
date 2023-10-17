//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package sandboxpolicy

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/syscallinfo"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sv1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// tracing policy builder
type tpBuilder struct {
	name   string
	tpSpec v1alpha1.TracingPolicySpec
}

// newTpBuilder creates a new tracing policy builder
func newTpBuilder(
	name string,
	podSelector *slimv1.LabelSelector,
) *tpBuilder {
	return &tpBuilder{
		name: name,
		tpSpec: v1alpha1.TracingPolicySpec{
			PodSelector: podSelector,
		},
	}
}

func syscallList(name string, l []v1alpha1.SandboxSyscallItem) v1alpha1.ListSpec {
	var values []string
	for _, s := range l {
		values = append(values, s.Name)
	}

	return v1alpha1.ListSpec{
		Name:      name,
		Values:    values,
		Type:      "syscalls",
		Validated: false,
	}
}

func ActionsHavePost(actions []v1alpha1.SandboxAction) bool {
	for i := range actions {
		if actions[i].Type == "Post" {
			return true
		}
	}

	return false
}

// addSyscallSpec adds a syscall spec to the tracing policy
func (b *tpBuilder) addSyscallSpec(
	name string,
	spec *v1alpha1.SandboxSyscallsSpec,
) error {

	var op string
	switch spec.Op {
	case "In":
		op = "InMap"
	case "NotIn":
		op = "NotInMap"
	default:
		return fmt.Errorf("unknown op: '%s'", spec.Op)
	}

	var matchActions []v1alpha1.ActionSelector
	if !ActionsHavePost(spec.Actions) {
		matchActions = append(matchActions, v1alpha1.ActionSelector{
			Action: "NoPost",
		})
	}

	b.tpSpec.Lists = append(b.tpSpec.Lists, syscallList(name, spec.List))
	b.tpSpec.Tracepoints = append(b.tpSpec.Tracepoints,
		v1alpha1.TracepointSpec{
			Subsystem: "raw_syscalls",
			Event:     "sys_enter",
			Args: []v1alpha1.KProbeArg{{
				Index: 4,
				Type:  "syscall64",
			}},
			Selectors: []v1alpha1.KProbeSelector{{
				MatchArgs: []v1alpha1.ArgSelector{{
					Index:    0,
					Operator: op,
					Values: []string{
						fmt.Sprintf("list:%s", name),
					},
				}},
				MatchActions: matchActions,
			}},
		},
	)

	return nil
}

func rawSyscallTracepointTranslate(
	orig *tracing.MsgGenericTracepointUnix,
	ev *tetragon.ProcessSandboxSyscall,
) error {
	if orig.Subsys != "raw_syscalls" {
		return fmt.Errorf("unexpected tracepoint subystem: '%s'", orig.Subsys)
	}

	if orig.Event != "sys_enter" {
		return fmt.Errorf("unexpected tracepoint event: '%s'", orig.Event)
	}

	if len(orig.Args) != 1 {
		return fmt.Errorf("unexpected tracepoint arguments: '%s'", orig.Args)
	}

	syscallID, ok := orig.Args[0].(uint64)
	if !ok {
		return fmt.Errorf("unexpected tracepoint argument type: %T", orig.Args[0])
	}

	ev.Name = syscallinfo.GetSyscallName(int(syscallID))
	if ev.Name == "" {
		ev.Name = fmt.Sprintf("syscall-%d", syscallID)
	}

	return nil
}

func (b *tpBuilder) Policy() (*SandboxTracingPolicy, error) {
	return &SandboxTracingPolicy{
		tracingpolicy.GenericTracingPolicy{
			TypeMeta: k8sv1.TypeMeta{
				Kind:       "TracingPolicy",
				APIVersion: "cilium.io/v1alpha1",
			},
			Metadata: k8sv1.ObjectMeta{
				Name: fmt.Sprintf("tpsp-%s", b.name),
			},
			Spec: b.tpSpec,
		},
		nil,
		rawSyscallTracepointTranslate,
	}, nil
}
