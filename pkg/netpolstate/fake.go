// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package netpolstate

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/isovalent/hubble-fgs/pkg/model/datapath"
	"github.com/isovalent/hubble-fgs/pkg/workloadid"
)

// fakeK8sReader is a mock implementation of client.Reader for testing
type fakeK8sReader struct{}

func (f *fakeK8sReader) Get(_ context.Context, key client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
	// For namespace lookups, return a basic namespace object
	if ns, ok := obj.(*corev1.Namespace); ok {
		ns.Name = key.Name
		ns.Labels = map[string]string{
			"kubernetes.io/metadata.name": key.Name,
		}
		return nil
	}
	return nil
}

func (f *fakeK8sReader) List(_ context.Context, _ client.ObjectList, _ ...client.ListOption) error {
	return nil
}

func newFakeExternalDeps(t *testing.T) externalDeps {
	t.Helper()
	return externalDeps{
		prog:       &datapath.DummyBpfProgrammer{},
		workloadID: workloadid.NewFakeState(t),
		k8sReader:  &fakeK8sReader{},
	}
}

func NewFakePolicyState(t *testing.T) *PolicyState {
	t.Helper()
	s := NewPolicyState()
	s.deps = newFakeExternalDeps(t)
	return s
}
