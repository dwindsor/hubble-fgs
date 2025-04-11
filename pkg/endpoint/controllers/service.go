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

	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ServiceReconciler is responsible for keeping service entries in the endpoint
// cache in sync with the Kubernetes cluster Tetragon is running in.
type ServiceReconciler struct {
	client.Client
	endpointCache endpoint.EndpointCache
}

func NewServiceReconciler(client client.Client, endpointCache endpoint.EndpointCache) *ServiceReconciler {
	return &ServiceReconciler{client, endpointCache}
}

func (r *ServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	svc := corev1.Service{}
	if err := r.Get(ctx, req.NamespacedName, &svc); err != nil {
		if errors.IsNotFound(err) {
			// TODO: Handle delete.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, r.endpointCache.AddIpServiceMap(&svc)
}

func (r *ServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Service{}).
		Complete(r)
}
