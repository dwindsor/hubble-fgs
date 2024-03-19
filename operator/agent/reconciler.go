package agent

import (
	"context"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logr "sigs.k8s.io/controller-runtime/pkg/log"
)

// Reconciler reconciles the Tetragon agent.
type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

const (
	agentConfigMapName    = "tetragon-config"
	operatorConfigMapName = "tetragon-operator-config"
)

// Reconcile gets notified and reconciles the Tetragon operator configuration.
// Intent is captured in the Operator ConfigMap.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if req.Name != operatorConfigMapName && req.Name != agentConfigMapName {
		// Skip reconcile request if it's not related to the management of the Tetragon agent.
		return ctrl.Result{}, nil
	}
	log := logr.FromContext(ctx).WithName("agent").WithValues("name-namespace", req.NamespacedName)
	log.Info("starting the reconciliation")

	// Retrieve the intent.
	opCMNamespacedName := types.NamespacedName{
		Namespace: req.NamespacedName.Namespace,
		Name:      operatorConfigMapName,
	}
	opCM := &corev1.ConfigMap{}
	if err := r.Get(ctx, opCMNamespacedName, opCM); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "unable to fetch operator configuration")
			return ctrl.Result{}, err
		}
		log.Info("operator ConfigMap not found, creating")
		// The operator ConfigMap created, contains only default settings and instructions.
		err = r.Create(ctx, defaultOperatorConfigMap(req.NamespacedName.Namespace, operatorConfigMapName))
		if err == nil {
			log.Info("operator ConfigMap created")
			return ctrl.Result{}, nil
		}
		if apierrors.IsAlreadyExists(err) {
			return ctrl.Result{}, nil
		}
		log.Error(err, "unable to create daemon set")
		return ctrl.Result{}, err
	}

	// Reconcile the agent DaemonSet.
	desiredDS, err := daemonSet(log, req.NamespacedName.Namespace, DaemonSetName, opCM)
	if err != nil {
		log.Error(err, "unable to generate the desired DaemonSet")
		return ctrl.Result{}, err
	}
	if err := ctrl.SetControllerReference(opCM, desiredDS, r.Scheme); err != nil {
		log.Error(err, "unable to set the owner reference to the DaemonSet")
		return ctrl.Result{}, err
	}
	ds := &appsv1.DaemonSet{}
	dsNamespacedName := types.NamespacedName{
		Namespace: req.NamespacedName.Namespace,
		Name:      DaemonSetName,
	}
	if err := r.Get(ctx, dsNamespacedName, ds); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "unable to fetch daemon set")
			return ctrl.Result{}, err
		}
		log.Info("daemon set not found, creating")
		if err := r.Create(ctx, desiredDS); err != nil {
			log.Error(err, "unable to create daemon set")
			return ctrl.Result{}, err
		}
		log.Info("daemon set created")
		return ctrl.Result{}, nil
	}
	if !equality.Semantic.DeepEqual(ds.Labels, desiredDS.Labels) ||
		!equality.Semantic.DeepEqual(ds.Spec, desiredDS.Spec) {
		log.Info("updating daemon set")
		if err := r.Update(ctx, desiredDS); err != nil {
			log.Error(err, "unable to update daemon set")
			return ctrl.Result{}, err
		}
		log.Info("daemon set updated")
	}

	// Reconcile the agent ConfigMap.
	desiredCM := agentConfigMap(log, req.NamespacedName.Namespace, agentConfigMapName, opCM)
	if err := ctrl.SetControllerReference(opCM, desiredCM, r.Scheme); err != nil {
		log.Error(err, "unable to set the owner reference to the ConfigMap")
		return ctrl.Result{}, err
	}
	agentCM := &corev1.ConfigMap{}
	agentCMNamespacedName := types.NamespacedName{
		Namespace: req.NamespacedName.Namespace,
		Name:      agentConfigMapName,
	}
	if err := r.Get(ctx, agentCMNamespacedName, agentCM); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "unable to fetch the agent ConfigMap")
			return ctrl.Result{}, err
		}
		log.Info("agent ConfigMap not found, creating")
		if err := r.Create(ctx, desiredCM); err != nil {
			log.Error(err, "unable to create the agent ConfigMap")
			return ctrl.Result{}, err
		}
		log.Info("daemon set created")
		return ctrl.Result{}, nil
	}
	if !equality.Semantic.DeepEqual(agentCM.Labels, desiredCM.Labels) || !equality.Semantic.DeepEqual(agentCM.Data, desiredCM.Data) {
		log.Info("updating agent ConfigMap")
		if err := r.Update(ctx, desiredCM); err != nil {
			log.Error(err, "unable to update the agent ConfigMap")
			return ctrl.Result{}, err
		}
		log.Info("agent ConfigMap updated")
	}
	log.Info("reconciliation completed")
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
// This is an unconventional setup.
// Idiomatic would be to define a custom resource, where the intent is captured
// and to reconcile it by creating and updating the agent DaemonSet and ConfigMap accordingly.
// As part of the PoC to keep things closely aligned to the helm deployment approach
// the intent is captured in the operator ConfigMap and the agent DaemonSet and ConfigMap
// are reconciled accordingly.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{}).Owns(&appsv1.DaemonSet{}).
		Complete(r)
}
