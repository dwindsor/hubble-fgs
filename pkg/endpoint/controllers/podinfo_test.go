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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/netpolstate"
)

func getTestClientBuilder() *fake.ClientBuilder {
	scheme := runtime.NewScheme()
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme)
}

func TestPodInfoReconcile_Add(t *testing.T) {
	podInfo := &v1alpha1.PodInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			Labels: map[string]string{
				"app": "test",
			},
		},
		WorkloadType: metav1.TypeMeta{
			Kind: "Deployment",
		},
		WorkloadObject: v1alpha1.WorkloadObjectMeta{
			Name:      "test-deployment",
			Namespace: "default",
		},
		Status: v1alpha1.PodInfoStatus{
			PodIPs: []v1alpha1.PodIP{
				{IP: "10.0.0.1"},
			},
		},
	}

	client := getTestClientBuilder().WithObjects(podInfo).Build()
	cache := new(endpoint.FakeCache)
	netpolState := netpolstate.NewFakePolicyState(t)
	reconciler := NewPodInfoReconciler(client, cache, netpolState)

	namespacedName := types.NamespacedName{Namespace: podInfo.Namespace, Name: podInfo.Name}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: namespacedName})
	require.NoError(t, err)

	err = client.Get(context.Background(), namespacedName, podInfo)
	require.NoError(t, err)
	assert.Contains(t, podInfo.Finalizers, finalizer, "Finalizer should be added")
}

func TestPodInfoReconcile_Update(t *testing.T) {
	podInfo := &v1alpha1.PodInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			Labels: map[string]string{
				"app": "test",
			},
		},
		WorkloadType: metav1.TypeMeta{
			Kind: "Deployment",
		},
		WorkloadObject: v1alpha1.WorkloadObjectMeta{
			Name:      "test-deployment",
			Namespace: "default",
		},
		Status: v1alpha1.PodInfoStatus{
			PodIPs: []v1alpha1.PodIP{
				{IP: "10.0.0.1"},
			},
		},
	}

	client := getTestClientBuilder().WithObjects(podInfo).Build()
	cache := new(endpoint.FakeCache)
	netpolState := netpolstate.NewFakePolicyState(t)
	reconciler := NewPodInfoReconciler(client, cache, netpolState)

	namespacedName := types.NamespacedName{Namespace: podInfo.Namespace, Name: podInfo.Name}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: namespacedName})
	require.NoError(t, err)

	err = client.Get(context.Background(), namespacedName, podInfo)
	require.NoError(t, err)

	podInfo.Status.PodIPs = []v1alpha1.PodIP{
		{IP: "10.0.0.1"},
		{IP: "10.0.0.2"},
	}
	err = client.Update(context.Background(), podInfo)
	require.NoError(t, err)

	_, err = reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: namespacedName})
	require.NoError(t, err)

	err = client.Get(context.Background(), namespacedName, podInfo)
	require.NoError(t, err)
	assert.Contains(t, podInfo.Finalizers, finalizer, "Finalizer should still be present after update")
}

func TestPodInfoReconcile_Remove(t *testing.T) {
	podInfo := &v1alpha1.PodInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-pod",
			Namespace:         "default",
			DeletionTimestamp: new(metav1.Now()),
			Finalizers:        []string{finalizer},
			Labels: map[string]string{
				"app": "test",
			},
		},
		WorkloadType: metav1.TypeMeta{
			Kind: "Deployment",
		},
		WorkloadObject: v1alpha1.WorkloadObjectMeta{
			Name:      "test-deployment",
			Namespace: "default",
		},
		Status: v1alpha1.PodInfoStatus{
			PodIPs: []v1alpha1.PodIP{
				{IP: "10.0.0.1"},
			},
		},
	}

	client := getTestClientBuilder().WithObjects(podInfo).Build()
	cache := new(endpoint.FakeCache)
	netpolState := netpolstate.NewFakePolicyState(t)
	reconciler := NewPodInfoReconciler(client, cache, netpolState)

	namespacedName := types.NamespacedName{Namespace: podInfo.Namespace, Name: podInfo.Name}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: namespacedName})
	require.NoError(t, err)

	err = client.Get(context.Background(), namespacedName, podInfo)
	require.Error(t, err, "Object should be deleted after finalizer removal")
	require.True(t, apierrors.IsNotFound(err), "Should get NotFound error")
}
