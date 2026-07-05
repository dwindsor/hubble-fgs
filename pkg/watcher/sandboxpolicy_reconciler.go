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

	enterpriseClient "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/isovalent/hubble-fgs/pkg/sandboxpolicy"
)

// sensorManager is the subset of sensors.Manager the reconcilers use, defined
// here so tests can supply a fake.
type sensorManager interface {
	AddTracingPolicy(ctx context.Context, tp tracingpolicy.TracingPolicy) error
	DeleteTracingPolicy(ctx context.Context, name string, namespace string, domain string) error
}

// controllerManager is the subset of *manager.ControllerManager needed to
// install a CRD-gated reconciler.
type controllerManager interface {
	RegisterControllerWhenCRDReady(crdName string, setup func(ctrl.Manager) error) error
}

// SandboxPolicyReconciler reconciles cluster-scoped SandboxPolicy resources:
// Delete+Add against sensors.Manager on Get, Delete on NotFound.
type SandboxPolicyReconciler struct {
	Client  client.Client
	Sensors sensorManager
	// convert is a field so tests can stub the ftrace-dependent syscall
	// translation; production uses defaultSandboxConvert.
	convert func(*v1alpha1.SandboxPolicy) (tracingpolicy.TracingPolicy, error)
}

func defaultSandboxConvert(sp *v1alpha1.SandboxPolicy) (tracingpolicy.TracingPolicy, error) {
	return sandboxpolicy.ToTracingPolicy(sp)
}

// Reconcile drives Add/Delete on sensors.Manager from the live SandboxPolicy state.
func (r *SandboxPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logger.GetLogger().With("name", req.Name)

	sp := &v1alpha1.SandboxPolicy{}
	err := r.Client.Get(ctx, req.NamespacedName, sp)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("deleting sandbox policy")
			if delErr := r.Sensors.DeleteTracingPolicy(ctx, req.Name, "", sandboxpolicy.SandboxDomain); delErr != nil {
				log.Warn("delete sandbox policy failed", logfields.Error, delErr)
			}
			return ctrl.Result{}, nil
		}
		log.Warn("failed to get sandbox policy", logfields.Error, err)
		return ctrl.Result{}, err
	}

	// Delete-before-add: unload any prior instance first, so an update that
	// turns the spec invalid still unloads it. Best-effort; the Add is the
	// real outcome.
	if delErr := r.Sensors.DeleteTracingPolicy(ctx, req.Name, "", sandboxpolicy.SandboxDomain); delErr != nil {
		log.Debug("delete-before-add returned an error", logfields.Error, delErr)
	}

	tp, err := r.convert(sp)
	if err != nil {
		// An invalid spec will not become valid on retry, so do not requeue.
		log.Warn("failed to convert sandbox policy to tracing policy", logfields.Error, err)
		return ctrl.Result{}, reconcile.TerminalError(err)
	}

	log.Info("adding sandbox policy", "tp-name", tp.TpName(), "tp-info", tp.TpInfo())
	if addErr := r.Sensors.AddTracingPolicy(ctx, tp); addErr != nil {
		log.Error("adding sandbox policy failed", logfields.Error, addErr)
		return ctrl.Result{}, reconcile.TerminalError(addErr)
	}
	return ctrl.Result{}, nil
}

// SetupWithManager registers the reconciler. GenerationChangedPredicate filters
// out status/metadata-only updates so they do not trigger BPF reloads.
func (r *SandboxPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.SandboxPolicy{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

// RegisterSandboxPolicyReconciler installs the cluster-scoped SandboxPolicy
// reconciler, gated on its CRD being present (registered as soon as it appears).
func RegisterSandboxPolicyReconciler(cm controllerManager, s sensorManager) error {
	return cm.RegisterControllerWhenCRDReady(enterpriseClient.SandboxPolicyCRD.ResName, func(mgr ctrl.Manager) error {
		r := &SandboxPolicyReconciler{
			Client:  mgr.GetClient(),
			Sensors: s,
			convert: defaultSandboxConvert,
		}
		return r.SetupWithManager(mgr)
	})
}
