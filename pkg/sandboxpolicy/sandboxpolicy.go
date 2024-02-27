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
	"github.com/cilium/tetragon/pkg/eventhandler"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	sandboxGRPC "github.com/isovalent/hubble-fgs/pkg/grpc/sandbox"
)

type SandboxTracingPolicy struct {
	// GenericTracingPolicy is the translated tracing policy that implements the sandbox policy
	tracingpolicy.GenericTracingPolicy
	// sp is the original sandbox policy
	sp *v1alpha1.SandboxPolicy

	// xlateTPEvent translates a tracepoint event (orig) to a ProcessSandboxSyscall event
	xlateTPEvent func(orig *tracing.MsgGenericTracepointUnix, ev *tetragon.ProcessSandboxSyscall) error
}

func (p *SandboxTracingPolicy) spName() string {
	return p.sp.ObjectMeta.Name
}

func (p *SandboxTracingPolicy) Handler() eventhandler.Handler {
	return func(evs []observer.Event, err error) ([]observer.Event, error) {
		if err != nil {
			return nil, fmt.Errorf("error in handling sandbox policy '%s' event: %w", p.spName(), err)
		}

		out := make([]observer.Event, 0, len(evs))
		for i := range evs {
			ev := evs[i]
			switch xev := ev.(type) {
			case *tracing.MsgGenericTracepointUnix:
				spev := sandboxGRPC.NewMsgRawSyscall(xev, p.xlateTPEvent)
				out = append(out, spev)
			default:
				logger.GetLogger().Warn("unexpected event type (%T) in sandbox policy handler", ev)
				out = append(out, ev)
			}
		}

		return out, nil
	}
}

func TracingPolicyName(spName string) string {
	return fmt.Sprintf("tpsp-%s", spName)
}

// sandbox policies are translated into low-level tracing policies

func toTracingPolicy(name string, spec *v1alpha1.SandboxSpec) (*SandboxTracingPolicy, error) {

	if spec == nil {
		return nil, fmt.Errorf("sandboxpolicy spec is empty")
	}

	tpBuilder := newTpBuilder(name, spec.PodSelector)
	for i, s := range spec.Syscalls {
		listName := fmt.Sprintf("%s-syscalls-%d", name, i)
		if err := tpBuilder.addSyscallSpec(listName, &s); err != nil {
			return nil, err
		}
	}

	return tpBuilder.Policy()

}

func ToTracingPolicy(p *v1alpha1.SandboxPolicy) (*SandboxTracingPolicy, error) {
	if p == nil {
		return nil, fmt.Errorf("sandboxpolicy is empty")
	}

	name := TracingPolicyName(p.ObjectMeta.Name)
	pol, err := toTracingPolicy(name, &p.Spec)
	if err != nil {
		return nil, err
	}
	pol.sp = p
	return pol, nil
}
