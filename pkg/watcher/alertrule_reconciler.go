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

package watcher

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	enterpriseClient "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/isovalent/hubble-fgs/pkg/alerts"
)

// AlertRuleReconciler reconciles cluster-scoped AlertRule resources: Add on Get
// (rules are name-indexed, so Add overwrites), Delete on NotFound.
type AlertRuleReconciler struct {
	Client client.Client
	Rules  alerts.RuleManager
}

// Reconcile drives Add/Delete on the rule manager from the live AlertRule state.
func (r *AlertRuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logger.GetLogger().With("name", req.Name)

	ar := &v1alpha1.AlertRule{}
	err := r.Client.Get(ctx, req.NamespacedName, ar)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("deleting alert rule")
			r.Rules.DeleteAlertRule(req.Name, v1alpha1.K8sDomain)
			return ctrl.Result{}, nil
		}
		log.Warn("failed to get alert rule", logfields.Error, err)
		return ctrl.Result{}, err
	}

	// K8s-sourced rules carry the k8s domain so they are managed separately
	// from gRPC/file rules.
	ar.Domain = v1alpha1.K8sDomain
	if addErr := r.Rules.AddAlertRule(ar); addErr != nil {
		// A bad rule (invalid CEL/filename) will not become valid on retry.
		log.Warn("failed to add alert rule", logfields.Error, addErr)
		return ctrl.Result{}, reconcile.TerminalError(addErr)
	}
	log.Info("added alert rule")
	return ctrl.Result{}, nil
}

// SetupWithManager registers the reconciler. It reconciles on spec and label
// changes: the "isovalent/rule_version" label drives ListRules filtering, so a
// label-only update must re-add the rule rather than be filtered out.
func (r *AlertRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.AlertRule{},
			builder.WithPredicates(predicate.Or(
				predicate.GenerationChangedPredicate{},
				predicate.LabelChangedPredicate{},
			))).
		Complete(r)
}

// RegisterAlertRuleReconciler installs the AlertRule reconciler, gated on its
// CRD being present (registered as soon as it appears).
func RegisterAlertRuleReconciler(cm controllerManager, rm alerts.RuleManager) error {
	return cm.RegisterControllerWhenCRDReady(enterpriseClient.AlertRuleCRD.ResName, func(mgr ctrl.Manager) error {
		r := &AlertRuleReconciler{
			Client: mgr.GetClient(),
			Rules:  rm,
		}
		return r.SetupWithManager(mgr)
	})
}
