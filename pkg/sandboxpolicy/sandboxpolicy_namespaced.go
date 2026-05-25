// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !nok8s

package sandboxpolicy

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/eventhandler"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

type SandboxTracingPolicyNamespaced struct {
	// GenericTracingPolicy is the translated tracing policy that implements the sandbox policy
	tracingpolicy.GenericTracingPolicyNamespaced
	// sp is the original sandbox policy
	sp *v1alpha1.SandboxPolicyNamespaced

	// xlateTPEvent translates a tracepoint event (orig) to a ProcessSandboxSyscall event
	xlateTPEvent func(orig *tracing.MsgGenericTracepointUnix, ev *tetragon.ProcessSandboxSyscall) error
}

func (p *SandboxTracingPolicyNamespaced) spName() string {
	if p == nil || p.sp == nil {
		return "unknown-nssp-name"
	}
	return p.sp.Name
}

func (p *SandboxTracingPolicyNamespaced) TpDomain() string {
	return SandboxDomain
}

func toTracingPolicyNamespaced(namespace string, name string, spec *v1alpha1.SandboxSpec) (*SandboxTracingPolicyNamespaced, error) {

	if spec == nil {
		return nil, fmt.Errorf("sandboxpolicy spec is empty")
	}

	tpBuilder := newTpBuilder(name, spec.PodSelector)
	for _, s := range spec.Syscalls {
		if err := tpBuilder.addSyscallSpec(&s); err != nil {
			return nil, err
		}
	}

	return tpBuilder.NamespacedPolicy(namespace)
}

func ToTracingPolicyNamespaced(p *v1alpha1.SandboxPolicyNamespaced) (*SandboxTracingPolicyNamespaced, error) {
	if p == nil {
		return nil, fmt.Errorf("sandboxpolicy is empty")
	}

	pol, err := toTracingPolicyNamespaced(p.Namespace, p.Name, &p.Spec)
	if err != nil {
		return nil, err
	}
	pol.sp = p
	return pol, nil
}

func (p *SandboxTracingPolicyNamespaced) Handler() eventhandler.Handler {
	return sandboxHandler(p.spName(), p.xlateTPEvent)
}
