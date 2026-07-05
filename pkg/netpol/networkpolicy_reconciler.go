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
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	enterpriseClient "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/isovalent/ipa/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/netpol/library"
	"github.com/isovalent/hubble-fgs/pkg/option"
)

// controllerManager is the subset of *manager.ControllerManager needed to
// install a CRD-gated reconciler.
type controllerManager interface {
	RegisterControllerWhenCRDReady(crdName string, setup func(ctrl.Manager) error) error
}

// npAction is the reconcile action decided for a TetragonNetworkPolicy key.
type npAction int

const (
	npNoop   npAction = iota // nothing to do
	npAdd                    // load under the canonical name
	npSwap                   // load under target, then unload victim (gap-free update)
	npDelete                 // unload victim
)

// npPlan is the outcome of the toggle decision: which repository slot to load
// into and/or unload. The alt-name double-buffer (name <-> __name) gives
// gap-free updates under level-based reconciliation.
type npPlan struct {
	action npAction
	target string // slot to load into (npAdd, npSwap)
	victim string // slot to unload (npSwap, npDelete)
}

// planUpsert decides the action when the CR np is present. It compares UID as
// well as generation, so a delete+recreate of a same-name CR (both at
// generation 1) is swapped in rather than skipped, and a non-Kubernetes story
// (empty UID) is always displaced.
func planUpsert(np *v1alpha1.TetragonNetworkPolicy) npPlan {
	oldName, story, altName := getCurrentSlot(np.Name)
	if story == nil {
		return npPlan{action: npAdd, target: np.Name}
	}
	if story.CRDPolicy != nil && story.CRDPolicy.UID == np.UID && story.CRDPolicy.Generation == np.Generation {
		if library.GetRepository().Get(altName) != nil {
			return npPlan{action: npDelete, victim: altName}
		}
		return npPlan{action: npNoop}
	}
	return npPlan{action: npSwap, target: altName, victim: oldName}
}

// planDelete decides what to do when the CR named name is gone: unload whichever
// slot currently holds it, if any.
func planDelete(name string) npPlan {
	currentName, story, _ := getCurrentSlot(name)
	if story == nil {
		return npPlan{action: npNoop}
	}
	return npPlan{action: npDelete, victim: currentName}
}

// TetragonNetworkPolicyReconciler reconciles cluster-scoped
// TetragonNetworkPolicy resources into the in-memory policy repository and the
// datapath state.
type TetragonNetworkPolicyReconciler struct {
	Client client.Client
}

// Reconcile drives load/unload of the network policy from the live CR state.
func (r *TetragonNetworkPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logger.GetLogger().With("name", req.Name)

	np := &v1alpha1.TetragonNetworkPolicy{}
	err := r.Client.Get(ctx, req.NamespacedName, np)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Clear every slot holding this policy; both can be populated after
			// a failed swap. A failed unload requeues until the datapath clears.
			for plan := planDelete(req.Name); plan.action == npDelete; plan = planDelete(req.Name) {
				log.Info("deleting network policy", "slot", plan.victim)
				if delErr := deleteNetworkPolicy(plan.victim); delErr != nil {
					log.Warn("delete network policy failed", logfields.Error, delErr)
					return ctrl.Result{}, delErr
				}
			}
			return ctrl.Result{}, nil
		}
		log.Warn("failed to get network policy", logfields.Error, err)
		return ctrl.Result{}, err
	}

	if !option.Config.EnableTCP {
		log.Warn("network policies require --" + option.KeyEnableTCP)
	}

	plan := planUpsert(np)
	if plan.action == npNoop {
		return ctrl.Result{}, nil
	}

	policies, err := ToTetragonNetworkPolicies(np)
	if err != nil {
		// An invalid spec will not become valid on retry, so do not requeue.
		// Any previously-loaded instance is left in place.
		log.Warn("failed to convert network policy", logfields.Error, err, "namespace", np.Namespace)
		return ctrl.Result{}, reconcile.TerminalError(err)
	}

	switch plan.action {
	case npDelete:
		// The loaded slot is current; clear the leftover from a prior swap
		// whose victim-unload failed, requeueing on failure.
		log.Info("clearing leftover network policy slot", "slot", plan.victim)
		if err := deleteNetworkPolicy(plan.victim); err != nil {
			log.Warn("clearing leftover network policy slot failed", logfields.Error, err)
			return ctrl.Result{}, err
		}

	case npAdd:
		// A load failure is plausibly transient, so requeue; loadPolicy rolls
		// its repository entry back, leaving a clean slate for the retry.
		if err := loadPolicy(&library.PolicyStory{Title: plan.target, CRDPolicy: np, IrPolicy: policies}); err != nil {
			log.Warn("add network policy aborted", logfields.Error, err)
			return ctrl.Result{}, err
		}
		log.Info("network policy added", "rules", len(policies))

	case npSwap:
		// Gap-free update: stage and program the new policy under the alternate
		// slot before unloading the old one. On a failed apply the staged entry
		// is rolled back so the old policy stays enforced, and the error requeues.
		target := library.GetRepository().Get(plan.target)
		if target != nil && target.CRDPolicy != nil &&
			target.CRDPolicy.UID == np.UID && target.CRDPolicy.Generation == np.Generation {
			// The target already holds this version (a prior swap only failed to
			// unload the victim); re-applying it would briefly drop enforcement.
			if err := deleteNetworkPolicy(plan.victim); err != nil {
				log.Warn("remove old network policy failed", logfields.Error, err)
				return ctrl.Result{}, err
			}
			log.Info("network policy updated", "rules", len(policies))
			return ctrl.Result{}, nil
		}
		if target != nil {
			// The target slot holds a leftover from a prior failed swap;
			// unload it first so its datapath records do not leak.
			if err := deleteNetworkPolicy(plan.target); err != nil {
				log.Warn("clearing stale network policy slot failed", logfields.Error, err)
				return ctrl.Result{}, err
			}
		}
		library.GetRepository().Add(&library.PolicyStory{Title: plan.target, CRDPolicy: np, IrPolicy: policies})
		if err := applyPolicies(policies); err != nil {
			library.GetRepository().Delete(plan.target)
			log.Warn("add network policy state failed", logfields.Error, err)
			return ctrl.Result{}, err
		}
		if err := deleteNetworkPolicy(plan.victim); err != nil {
			// Both versions stay loaded until a retry clears the old slot;
			// requeue rather than leave the stale version enforced forever.
			log.Warn("remove old network policy failed", logfields.Error, err)
			return ctrl.Result{}, err
		}
		log.Info("network policy updated", "rules", len(policies))
	}

	return ctrl.Result{}, nil
}

// SetupWithManager registers the reconciler. GenerationChangedPredicate filters
// out status/metadata-only updates so they do not trigger policy reloads.
func (r *TetragonNetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.TetragonNetworkPolicy{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

// RegisterTetragonNetworkPolicyReconciler installs the cluster-scoped
// TetragonNetworkPolicy reconciler, gated on its CRD being present (registered
// as soon as it appears).
func RegisterTetragonNetworkPolicyReconciler(cm controllerManager) error {
	return cm.RegisterControllerWhenCRDReady(enterpriseClient.TetragonNetworkPolicyCRD.ResName, func(mgr ctrl.Manager) error {
		return (&TetragonNetworkPolicyReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr)
	})
}
