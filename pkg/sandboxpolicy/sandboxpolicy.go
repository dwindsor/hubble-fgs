// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package sandboxpolicy

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/eventhandler"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	sandboxGRPC "github.com/isovalent/hubble-fgs/pkg/grpc/sandbox"
)

const (
	tpNamePrefix  = "tpsp+"
	SandboxDomain = "sandbox"
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
	if p == nil || p.sp == nil {
		return "unknown-sp-name"
	}
	return p.sp.Name
}

func (p *SandboxTracingPolicy) TpDomain() string {
	return SandboxDomain
}

func sandboxHandler(
	spName string,
	xlateFn func(orig *tracing.MsgGenericTracepointUnix, ev *tetragon.ProcessSandboxSyscall) error,
) eventhandler.Handler {
	return func(evs []observer.Event, err error) ([]observer.Event, error) {
		if err != nil {
			return nil, fmt.Errorf("error in handling sandbox policy '%s' event: %w", spName, err)
		}

		out := make([]observer.Event, 0, len(evs))
		for i := range evs {
			ev := evs[i]
			switch xev := ev.(type) {
			case *tracing.MsgGenericTracepointUnix:
				spev := sandboxGRPC.NewMsgRawSyscall(xev, xlateFn, spName)
				out = append(out, spev)
			default:
				logger.GetLogger().Warn(fmt.Sprintf("unexpected event type (%T) in sandbox policy handler", ev))
				out = append(out, ev)
			}
		}

		return out, nil
	}
}

func (p *SandboxTracingPolicy) Handler() eventhandler.Handler {
	return sandboxHandler(p.spName(), p.xlateTPEvent)
}

func TracingPolicyName(spName string) string {
	return fmt.Sprintf("%s%s", tpNamePrefix, spName)
}

// NameFromTPName returns the sandbox policy name from the tracing policy name.
// Returns "" if the tracing policy name does not correspond to a tracing policy
func NameFromTPName(tpName string) string {
	if strings.HasPrefix(tpName, tpNamePrefix) {
		return tpName[len(tpNamePrefix):]
	}
	return ""
}

// sandbox policies are translated into low-level tracing policies

func toTracingPolicy(name string, spec *v1alpha1.SandboxSpec) (*SandboxTracingPolicy, error) {

	if spec == nil {
		return nil, fmt.Errorf("sandboxpolicy spec is empty")
	}

	tpBuilder := newTpBuilder(name, spec.PodSelector)
	for _, s := range spec.Syscalls {
		if err := tpBuilder.addSyscallSpec(&s); err != nil {
			return nil, err
		}
	}

	return tpBuilder.Policy()

}

func ToTracingPolicy(p *v1alpha1.SandboxPolicy) (*SandboxTracingPolicy, error) {
	if p == nil {
		return nil, fmt.Errorf("sandboxpolicy is empty")
	}

	name := TracingPolicyName(p.Name)
	pol, err := toTracingPolicy(name, &p.Spec)
	if err != nil {
		return nil, err
	}
	pol.sp = p
	return pol, nil
}
