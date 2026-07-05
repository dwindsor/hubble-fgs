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

// SandboxPolicyNamespacedReconciler reconciles namespaced SandboxPolicy
// resources, like SandboxPolicyReconciler but with the namespace propagated
// into sensors.Manager.
type SandboxPolicyNamespacedReconciler struct {
	Client  client.Client
	Sensors sensorManager
	// convert is a field so tests can stub the ftrace-dependent syscall
	// translation; production uses defaultSandboxConvertNamespaced.
	convert func(*v1alpha1.SandboxPolicyNamespaced) (tracingpolicy.TracingPolicy, error)
}

func defaultSandboxConvertNamespaced(sp *v1alpha1.SandboxPolicyNamespaced) (tracingpolicy.TracingPolicy, error) {
	return sandboxpolicy.ToTracingPolicyNamespaced(sp)
}

// Reconcile drives Add/Delete on sensors.Manager from the live SandboxPolicyNamespaced state.
func (r *SandboxPolicyNamespacedReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logger.GetLogger().With("name", req.Name, "namespace", req.Namespace)

	sp := &v1alpha1.SandboxPolicyNamespaced{}
	err := r.Client.Get(ctx, req.NamespacedName, sp)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("deleting namespaced sandbox policy")
			if delErr := r.Sensors.DeleteTracingPolicy(ctx, req.Name, req.Namespace, sandboxpolicy.SandboxDomain); delErr != nil {
				log.Warn("delete namespaced sandbox policy failed", logfields.Error, delErr)
			}
			return ctrl.Result{}, nil
		}
		log.Warn("failed to get namespaced sandbox policy", logfields.Error, err)
		return ctrl.Result{}, err
	}

	// Delete-before-add: unload any prior instance first, so an update that
	// turns the spec invalid still unloads it. Best-effort; the Add is the
	// real outcome.
	if delErr := r.Sensors.DeleteTracingPolicy(ctx, req.Name, req.Namespace, sandboxpolicy.SandboxDomain); delErr != nil {
		log.Debug("delete-before-add returned an error", logfields.Error, delErr)
	}

	tp, err := r.convert(sp)
	if err != nil {
		// An invalid spec will not become valid on retry, so do not requeue.
		log.Warn("failed to convert namespaced sandbox policy to tracing policy", logfields.Error, err)
		return ctrl.Result{}, reconcile.TerminalError(err)
	}

	log.Info("adding namespaced sandbox policy", "tp-name", tp.TpName(), "tp-info", tp.TpInfo())
	if addErr := r.Sensors.AddTracingPolicy(ctx, tp); addErr != nil {
		log.Error("adding namespaced sandbox policy failed", logfields.Error, addErr)
		return ctrl.Result{}, reconcile.TerminalError(addErr)
	}
	return ctrl.Result{}, nil
}

// SetupWithManager registers the reconciler. GenerationChangedPredicate filters
// out status/metadata-only updates so they do not trigger BPF reloads.
func (r *SandboxPolicyNamespacedReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.SandboxPolicyNamespaced{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

// RegisterSandboxPolicyNamespacedReconciler installs the namespaced SandboxPolicy
// reconciler, gated on its own CRD being present independently of the
// cluster-scoped SandboxPolicy CRD.
func RegisterSandboxPolicyNamespacedReconciler(cm controllerManager, s sensorManager) error {
	return cm.RegisterControllerWhenCRDReady(enterpriseClient.SandboxPolicyNamespacedCRD.ResName, func(mgr ctrl.Manager) error {
		r := &SandboxPolicyNamespacedReconciler{
			Client:  mgr.GetClient(),
			Sensors: s,
			convert: defaultSandboxConvertNamespaced,
		}
		return r.SetupWithManager(mgr)
	})
}
