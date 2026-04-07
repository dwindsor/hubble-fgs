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

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/netpolstate"
)

const finalizer = "cilium.io/tetragon-podinfo-reconciler"

type PodInfoReconciler struct {
	client.Client
	endpointCache endpoint.EndpointCache
	netpolstate   *netpolstate.PolicyState
}

func NewPodInfoReconciler(client client.Client, endpointCache endpoint.EndpointCache, netpolstate *netpolstate.PolicyState) *PodInfoReconciler {
	return &PodInfoReconciler{client, endpointCache, netpolstate}
}

func (r *PodInfoReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	podInfo := v1alpha1.PodInfo{}
	if err := r.Get(ctx, req.NamespacedName, &podInfo); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if podInfo.DeletionTimestamp.IsZero() {
		// The object is not being deleted, should we add the finalizer?
		if !controllerutil.ContainsFinalizer(&podInfo, finalizer) {
			controllerutil.AddFinalizer(&podInfo, finalizer)
			if err := r.Update(ctx, &podInfo); err != nil {
				return ctrl.Result{}, err
			}
		}
	} else {
		// The object is being deleted, remove from state and remove finalizer
		if controllerutil.ContainsFinalizer(&podInfo, finalizer) {
			logger.GetLogger().Debug("PodInfo reconciler delete", "podinfo", req.NamespacedName)
			err := r.netpolstate.PodRemove(&podInfo)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("PodInfo netpolstate remove error: %w", err)
			}
			controllerutil.RemoveFinalizer(&podInfo, finalizer)
			if err := r.Update(ctx, &podInfo); err != nil {
				return ctrl.Result{}, err
			}

			return ctrl.Result{}, nil
		}
	}

	logger.GetLogger().Debug("PodInfo reconciler add or update", "podInfo", req.NamespacedName)
	r.endpointCache.AddIpPodMap(&podInfo)
	if err := r.netpolstate.PodAdd(&podInfo); err != nil {
		// This should not fail, except maybe at startup when the sensor
		// is not loaded yet, in this case the reconciler will retry.
		return ctrl.Result{}, fmt.Errorf("PodInfo netpolstate add error: %w", err)
	}

	return ctrl.Result{}, nil
}

func (r *PodInfoReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.PodInfo{}).
		Complete(r)
}
