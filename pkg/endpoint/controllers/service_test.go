// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package controllers

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/isovalent/hubble-fgs/pkg/endpoint"
)

func TestReconcile(t *testing.T) {
	svc := &corev1.Service{
		Name:      "my-svc",
		Namespace: "default",
		Spec: corev1.ServiceSpec{
			ClusterIPs: []string{"1.1.1.1", "2.2.2.2"},
		},
	}
	client := getClientBuilder().WithObjects(svc).Build()
	cache := new(endpoint.FakeCache)
	call := cache.On("AddIpServiceMap", svc).Return(nil)
	reconciler := ServiceReconciler{client, cache}
	namespacedName := types.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}

	// If the service is created, the reconciler should call AddIpServiceMap.
	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: namespacedName})
	assert.NoError(t, err)
	cache.AssertCalled(t, "AddIpServiceMap", svc)
	assert.Len(t, call.Arguments, 1)
	assert.Equal(t, []string{"1.1.1.1", "2.2.2.2"}, call.Arguments[0].(*corev1.Service).Spec.ClusterIPs)

	// If the service is updated, the reconciler should call AddIpServiceMap again.
	svc.Spec.ClusterIPs = []string{"3.3.3.3", "4.4.4.4"}
	err = client.Update(context.Background(), svc)
	assert.NoError(t, err)
	_, err = reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: namespacedName})
	assert.NoError(t, err)
	cache.AssertCalled(t, "AddIpServiceMap", svc)
	assert.Len(t, call.Arguments, 1)
	assert.Equal(t, []string{"3.3.3.3", "4.4.4.4"}, call.Arguments[0].(*corev1.Service).Spec.ClusterIPs)

	// If AddIpServiceMap fails, Reconcile should return an error so that the
	// controller retries reconciliation.
	call.Unset()
	cache.On("AddIpServiceMap", svc).Return(fmt.Errorf("error"))
	_, err = reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: namespacedName})
	assert.Error(t, err)
}

func getClientBuilder() *fake.ClientBuilder {
	scheme := runtime.NewScheme()
	utilruntime.Must(corev1.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme)
}
