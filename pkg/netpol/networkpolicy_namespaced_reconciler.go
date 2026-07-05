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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	enterpriseClient "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/isovalent/ipa/k8s/apis/cilium.io/v1alpha1"
)

// TetragonNetworkPolicyNamespacedReconciler is a placeholder for the not-yet-
// implemented namespaced TetragonNetworkPolicy: it watches the kind, logs
// observed objects as unsupported, and takes no action.
type TetragonNetworkPolicyNamespacedReconciler struct {
	Client client.Client
}

// Reconcile logs the observed object; namespaced TNP is not yet supported.
func (r *TetragonNetworkPolicyNamespacedReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logger.GetLogger().With("name", req.Name, "namespace", req.Namespace)

	np := &v1alpha1.TetragonNetworkPolicyNamespaced{}
	if err := r.Client.Get(ctx, req.NamespacedName, np); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		log.Warn("failed to get namespaced network policy", logfields.Error, err)
		return ctrl.Result{}, err
	}

	log.Warn("namespaced TetragonNetworkPolicy is not supported yet; ignoring")
	return ctrl.Result{}, nil
}

// SetupWithManager registers the reconciler; GenerationChangedPredicate limits
// the warning to spec changes.
func (r *TetragonNetworkPolicyNamespacedReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.TetragonNetworkPolicyNamespaced{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

// RegisterTetragonNetworkPolicyNamespacedReconciler installs the placeholder
// namespaced reconciler, gated on its CRD being present.
func RegisterTetragonNetworkPolicyNamespacedReconciler(cm controllerManager) error {
	return cm.RegisterControllerWhenCRDReady(enterpriseClient.TetragonNetworkPolicyNamespacedCRD.ResName, func(mgr ctrl.Manager) error {
		return (&TetragonNetworkPolicyNamespacedReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr)
	})
}
