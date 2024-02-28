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
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

type SandboxTracingPolicyNamespaced struct {
	// GenericTracingPolicy is the translated tracing policy that implements the sandbox policy
	tracingpolicy.GenericTracingPolicyNamespaced
	// sp is the original sandbox policy
	sp *v1alpha1.SandboxPolicyNamespaced

	// xlateTPEvent translates a tracepoint event (orig) to a ProcessSandboxSyscall event
	xlateTPEvent func(orig *tracing.MsgGenericTracepointUnix, ev *tetragon.ProcessSandboxSyscall) error
}

func toTracingPolicyNamespaced(namespace string, name string, spec *v1alpha1.SandboxSpec) (*SandboxTracingPolicyNamespaced, error) {

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

	return tpBuilder.NamespacedPolicy(namespace)
}

func ToTracingPolicyNamespaced(p *v1alpha1.SandboxPolicyNamespaced) (*SandboxTracingPolicyNamespaced, error) {
	if p == nil {
		return nil, fmt.Errorf("sandboxpolicy is empty")
	}

	name := TracingPolicyName(p.ObjectMeta.Name)
	pol, err := toTracingPolicyNamespaced(p.ObjectMeta.Namespace, name, &p.Spec)
	if err != nil {
		return nil, err
	}
	pol.sp = p
	return pol, nil
}
