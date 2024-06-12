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
	"syscall"

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

	enforcerLists map[string]struct{}
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
		enforcerLists: map[string]struct{}{},
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

func actionsHaveAct(actions []v1alpha1.SandboxAction, act string) bool {
	for i := range actions {
		if actions[i].Type == act {
			return true
		}
	}

	return false
}

func actionsHavePost(actions []v1alpha1.SandboxAction) bool {
	return actionsHaveAct(actions, "Post")
}

func actionsHaveBlock(actions []v1alpha1.SandboxAction) bool {
	return actionsHaveAct(actions, "Block")
}

func actionsHaveSignal(actions []v1alpha1.SandboxAction) bool {
	return actionsHaveAct(actions, "Signal")
}

// NB: there can only be a single enforcer spec in a policy
func (b *tpBuilder) enforcers() []v1alpha1.EnforcerSpec {

	if len(b.enforcerLists) == 0 {
		return nil
	}

	ret := v1alpha1.EnforcerSpec{}
	for l := range b.enforcerLists {
		ret.Calls = append(ret.Calls, l)
	}
	return []v1alpha1.EnforcerSpec{ret}
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

	listName := fmt.Sprintf("list:%s", name)

	var matchActions []v1alpha1.ActionSelector
	if !actionsHavePost(spec.Actions) {
		matchActions = append(matchActions, v1alpha1.ActionSelector{
			Action: "NoPost",
		})
	}

	haveBlock := actionsHaveBlock(spec.Actions)
	haveSignal := actionsHaveSignal(spec.Actions)
	if haveBlock || haveSignal {
		if spec.Op == "NotIn" {
			return fmt.Errorf("NotIn operator is currently not supported with enforcement")
		}
		notifyEnforcer := v1alpha1.ActionSelector{
			Action: "NotifyEnforcer",
		}
		if haveBlock {
			notifyEnforcer.ArgError = -int32(syscall.EPERM)
		}
		if haveSignal {
			notifyEnforcer.ArgSig = uint32(syscall.SIGKILL)
		}

		matchActions = append(matchActions, notifyEnforcer)
		b.enforcerLists[listName] = struct{}{}
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
					Values:   []string{listName},
				}},
				MatchActions: matchActions,
			}},
		},
	)
	b.tpSpec.Enforcers = b.enforcers()

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
	// NB(kkourt): The multi-kprobe enforcer fails to load. Will have to investigate in OSS side.
	// One thing to note is that if multi-kprobes and bpf_override_return() is supported, we do
	// not really need to use the enforcer. We can translate into tracing policies that hook
	// directly into kprobes rather than the generic syscall tracepoint.
	b.tpSpec.Options = []v1alpha1.OptionSpec{
		{Name: "disable-kprobe-multi", Value: "1"},
	}
	return &SandboxTracingPolicy{
		tracingpolicy.GenericTracingPolicy{
			TypeMeta: k8sv1.TypeMeta{
				Kind:       "TracingPolicy",
				APIVersion: "cilium.io/v1alpha1",
			},
			Metadata: k8sv1.ObjectMeta{
				Name: b.name,
			},
			Spec: b.tpSpec,
		},
		nil,
		rawSyscallTracepointTranslate,
	}, nil
}

func (b *tpBuilder) NamespacedPolicy(namespace string) (*SandboxTracingPolicyNamespaced, error) {
	// NB(kkourt): The multi-kprobe enforcer fails to load. Will have to investigate in OSS side.
	// One thing to note is that if multi-kprobes and bpf_override_return() is supported, we do
	// not really need to use the enforcer. We can translate into tracing policies that hook
	// directly into kprobes rather than the generic syscall tracepoint.
	b.tpSpec.Options = []v1alpha1.OptionSpec{
		{Name: "disable-kprobe-multi", Value: "1"},
	}
	return &SandboxTracingPolicyNamespaced{
		tracingpolicy.GenericTracingPolicyNamespaced{
			TypeMeta: k8sv1.TypeMeta{
				Kind:       "TracingPolicyNamespaced",
				APIVersion: "cilium.io/v1alpha1",
			},
			Metadata: k8sv1.ObjectMeta{
				Name:      b.name,
				Namespace: namespace,
			},
			Spec: b.tpSpec,
		},
		nil,
		rawSyscallTracepointTranslate,
	}, nil
}
