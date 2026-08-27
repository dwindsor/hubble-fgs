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

package netpol

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	enterpriseClient "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/isovalent/ipa/k8s/apis/cilium.io/v1alpha1"
)

func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(v1alpha1.AddToScheme(s))
	return s
}

func TestNamespacedReconcile_TakesNoAction(t *testing.T) {
	req := ctrl.Request{Name: "np", Namespace: "team-a"}

	t.Run("present object is ignored", func(t *testing.T) {
		np := &v1alpha1.TetragonNetworkPolicyNamespaced{
			Name: "np", Namespace: "team-a",
		}
		cli := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(np).Build()
		r := &TetragonNetworkPolicyNamespacedReconciler{Client: cli}

		res, err := r.Reconcile(context.Background(), req)
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, res)
	})

	t.Run("missing object is a no-op", func(t *testing.T) {
		cli := fake.NewClientBuilder().WithScheme(newTestScheme(t)).Build()
		r := &TetragonNetworkPolicyNamespacedReconciler{Client: cli}

		res, err := r.Reconcile(context.Background(), req)
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, res)
	})
}

func TestRegisterTetragonNetworkPolicyNamespacedReconciler_GatesOnCorrectCRD(t *testing.T) {
	cm := &fakeControllerManager{}
	require.NoError(t, RegisterTetragonNetworkPolicyNamespacedReconciler(cm))
	require.Equal(t, enterpriseClient.TetragonNetworkPolicyNamespacedCRD.ResName, cm.gotCRD)
	require.NotNil(t, cm.setup, "setup callback must be wired")
}
