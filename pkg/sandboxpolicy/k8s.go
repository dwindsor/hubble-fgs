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
	"sync"

	"github.com/cilium/tetragon/pkg/crdutils"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	k8sv1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

var (
	spContext  *crdutils.CRDContext[*v1alpha1.SandboxPolicy]
	spOnce     sync.Once
	spnContext *crdutils.CRDContext[*v1alpha1.SandboxPolicyNamespaced]
	spnOnce    sync.Once
)

// FromYAML inspects the YAML input to determine the kind, then dispatches to
// the generic FromYAML function.
func FromYAML(data string) (crdutils.CRDObject, error) {
	var unstr unstructured.Unstructured
	if err := yaml.UnmarshalStrict([]byte(data), &unstr); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	switch unstr.GetKind() {
	case "SandboxPolicy":
		crdCtx, err := getSPContext()
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve CRD context for SandboxPolicy: %w", err)
		}
		obj, err := crdCtx.FromYAML(data)
		if err != nil {
			return nil, err
		}
		return obj, nil
	case "SandboxPolicyNamespaced":
		crdCtx, err := getSPNContext()
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve CRD context for SandboxPolicyNamespaced: %w", err)
		}
		obj, err := crdCtx.FromYAML(data)
		if err != nil {
			return nil, err
		}
		return obj, nil
	default:
		return nil, fmt.Errorf("unknown CRD kind: %s", unstr.GetKind())
	}
}

func getSPContext() (*crdutils.CRDContext[*v1alpha1.SandboxPolicy], error) {
	var err error
	spOnce.Do(func() {
		spContext, err = crdutils.NewCRDContext[*v1alpha1.SandboxPolicy](&client.SandboxPolicyCRD.Definition)
	})
	return spContext, err
}

func getSPNContext() (*crdutils.CRDContext[*v1alpha1.SandboxPolicyNamespaced], error) {
	var err error
	spnOnce.Do(func() {
		spnContext, err = crdutils.NewCRDContext[*v1alpha1.SandboxPolicyNamespaced](&client.SandboxPolicyNamespacedCRD.Definition)
	})
	return spnContext, err
}

func (b *tpBuilder) NamespacedPolicy(namespace string) (*SandboxTracingPolicyNamespaced, error) {
	b.finalizeSpec()
	return &SandboxTracingPolicyNamespaced{
		tracingpolicy.GenericTracingPolicyNamespaced{
			Kind:       "TracingPolicyNamespaced",
			APIVersion: "cilium.io/v1alpha1",
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
