// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

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
	"sigs.k8s.io/yaml"
)

// Reconciler reconciles the Tetragon agent.
type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

const (
	AgentConfigMapName       = "tetragon-config"
	OperatorConfigMapName    = "tetragon-operator-config"
	DaemonSetName            = "tetragon"
	RTDaemonSetName          = "tetragon-rthooks"
	AggregatorDeploymentName = "tetragon-aggregator"
)

// Reconcile gets notified and reconciles the Tetragon operator configuration.
// Intent is captured in the Operator ConfigMap.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if req.Name != OperatorConfigMapName && req.Name != AgentConfigMapName {
		// Skip reconcile request if it's not related to the management of the Tetragon agent.
		return ctrl.Result{}, nil
	}
	log := logr.FromContext(ctx).WithName("agent").WithValues("name-namespace", req.NamespacedName)
	log.Info("starting the reconciliation")

	// Retrieve the intent.
	opCMNamespacedName := types.NamespacedName{
		Namespace: req.Namespace,
		Name:      OperatorConfigMapName,
	}
	opCM := &corev1.ConfigMap{}
	if err := r.Get(ctx, opCMNamespacedName, opCM); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "unable to fetch operator configuration")
			return ctrl.Result{}, err
		}
		log.Info("operator ConfigMap not found, creating")
		// The operator ConfigMap created, contains only default settings and instructions.
		err = r.Create(ctx, DefaultOperatorConfigMap(log, req.Namespace, OperatorConfigMapName))
		if err == nil {
			log.Info("operator ConfigMap created")
			return ctrl.Result{Requeue: true}, nil
		}
		if apierrors.IsAlreadyExists(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		log.Error(err, "unable to create operator ConfigMap")
		return ctrl.Result{}, err
	}

	// Reconcile the agent ConfigMap.
	desiredCM := ExtractAgentConfigMap(log, req.Namespace, AgentConfigMapName, opCM)
	if err := ctrl.SetControllerReference(opCM, desiredCM, r.Scheme); err != nil {
		log.Error(err, "unable to set the owner reference to the ConfigMap")
		return ctrl.Result{}, err
	}
	agentCM := &corev1.ConfigMap{}
	agentCMNamespacedName := types.NamespacedName{
		Namespace: req.Namespace,
		Name:      AgentConfigMapName,
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
		log.Info("agent ConfigMap created")
		return ctrl.Result{Requeue: true}, nil
	}
	if !equality.Semantic.DeepEqual(agentCM.Labels, desiredCM.Labels) || !equality.Semantic.DeepEqual(agentCM.Data, desiredCM.Data) {
		log.Info("updating agent ConfigMap")
		if err := r.Update(ctx, desiredCM); err != nil {
			log.Error(err, "unable to update the agent ConfigMap")
			return ctrl.Result{}, err
		}
		log.Info("agent ConfigMap updated")
	}

	// Reconcile the agent DaemonSet.
	desiredDS, err := DaemonSet(log, req.Namespace, DaemonSetName, opCM)
	if err != nil {
		log.Error(err, "unable to generate the desired daemon set")
		return ctrl.Result{}, nil
	}
	if err := ctrl.SetControllerReference(opCM, desiredDS, r.Scheme); err != nil {
		log.Error(err, "unable to set the owner reference to the DaemonSet")
		return ctrl.Result{}, err
	}
	ds := &appsv1.DaemonSet{}
	dsNamespacedName := types.NamespacedName{
		Namespace: req.Namespace,
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
		return ctrl.Result{Requeue: true}, nil
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

	// Reconcile the runtime hooks DaemonSet
	desiredRTDS, err := RTDaemonSet(log, req.Namespace, RTDaemonSetName, opCM)
	if err != nil {
		log.Error(err, "unable to generate the desired runtime hooks daemon set")
		// no need to requeue as it is not recoverable without a config change
		// that would trigger an event anyway.
		return ctrl.Result{}, nil
	}
	if desiredRTDS != nil {
		if err := ctrl.SetControllerReference(opCM, desiredRTDS, r.Scheme); err != nil {
			log.Error(err, "unable to set the owner reference to the runtime hooks DaemonSet")
			return ctrl.Result{}, err
		}
	}
	rtDS := &appsv1.DaemonSet{}
	rtDSNamespacedName := types.NamespacedName{
		Namespace: req.Namespace,
		Name:      RTDaemonSetName,
	}
	if err := r.Get(ctx, rtDSNamespacedName, rtDS); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "unable to fetch the runtime hooks daemon set")
			return ctrl.Result{}, err
		}
		if desiredRTDS != nil {
			log.Info("runtime hooks daemon set not found, creating")
			if err := r.Create(ctx, desiredRTDS); err != nil {
				log.Error(err, "unable to create the runtime hooks daemon set")
				return ctrl.Result{}, err
			}
			log.Info("runtime hooks daemon set created")
			return ctrl.Result{Requeue: true}, nil
		}
	} else {
		if desiredRTDS == nil {
			if err := r.Delete(ctx, desiredRTDS); err != nil {
				log.Error(err, "unable to delete the runtime hooks daemon set")
				return ctrl.Result{}, err
			}
			log.Info("runtime hooks daemon set deleted")
			return ctrl.Result{Requeue: true}, nil
		}
	}
	if desiredRTDS != nil && (!equality.Semantic.DeepEqual(rtDS.Labels, desiredRTDS.Labels) ||
		!equality.Semantic.DeepEqual(ds.Spec, desiredRTDS.Spec)) {
		log.Info("updating runtime hooks daemon set")
		if err := r.Update(ctx, desiredRTDS); err != nil {
			log.Error(err, "unable to update the runtime hooks daemon set")
			return ctrl.Result{}, err
		}
		log.Info("runtime hooks daemon set updated")
	}

	aggregatorConfigYaml := opCM.Data[OperatorConfigMapAggregatorKey]
	aggregatorCMFields := make(map[string]any)
	if err := yaml.Unmarshal([]byte(aggregatorConfigYaml), &aggregatorCMFields); err != nil {
		log.WithValues("value", aggregatorConfigYaml).Error(err, "could not unmarshal the aggregator configuration")
		return ctrl.Result{}, err
	}

	// Reconcile the Tetragon Aggregator Deployment.
	desiredAggregatorDeploy, err := AggregatorDeployment(log, req.Namespace, AggregatorDeploymentName, aggregatorCMFields)
	if err != nil {
		log.Error(err, "unable to generate the desired aggregator deployment")
		return ctrl.Result{}, nil
	}
	if desiredAggregatorDeploy != nil {
		if err := ctrl.SetControllerReference(opCM, desiredAggregatorDeploy, r.Scheme); err != nil {
			log.Error(err, "unable to set the owner reference to the aggregator deployment")
			return ctrl.Result{}, err
		}
	}
	aggregatorDeploy := &appsv1.Deployment{}
	aggregatorDeployNamespacedName := types.NamespacedName{
		Namespace: req.Namespace,
		Name:      AggregatorDeploymentName,
	}
	if err := r.Get(ctx, aggregatorDeployNamespacedName, aggregatorDeploy); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "unable to fetch aggregator deployment")
			return ctrl.Result{}, err
		}
		if desiredAggregatorDeploy != nil {
			log.Info("aggregator deployment not found, creating")
			if err := r.Create(ctx, desiredAggregatorDeploy); err != nil {
				log.Error(err, "unable to create aggregator deployment")
				return ctrl.Result{}, err
			}
			log.Info("aggregator deployment created")
			return ctrl.Result{Requeue: true}, nil
		}
	} else {
		if desiredAggregatorDeploy == nil {
			if err := r.Delete(ctx, desiredAggregatorDeploy); err != nil {
				log.Error(err, "unable to delete the aggregator deployment")
				return ctrl.Result{}, err
			}
			log.Info("aggregator deployment deleted")
			return ctrl.Result{Requeue: true}, nil
		}
	}
	if desiredAggregatorDeploy != nil && (!equality.Semantic.DeepEqual(aggregatorDeploy.Labels, desiredAggregatorDeploy.Labels) ||
		!equality.Semantic.DeepEqual(aggregatorDeploy.Spec, desiredAggregatorDeploy.Spec)) {
		log.Info("updating aggregator deployment")
		if err := r.Update(ctx, desiredAggregatorDeploy); err != nil {
			log.Error(err, "unable to update aggregator deployment")
			return ctrl.Result{}, err
		}
		log.Info("aggregator deployment updated")
	}

	// Reconcile the Tetragon Aggregator Service.
	desiredAggregatorService, err := AggregatorService(log, req.Namespace, AggregatorDeploymentName, aggregatorCMFields)
	if err != nil {
		log.Error(err, "unable to generate the desired aggregator service")
		return ctrl.Result{}, nil
	}
	if desiredAggregatorService != nil {
		if err := ctrl.SetControllerReference(opCM, desiredAggregatorService, r.Scheme); err != nil {
			log.Error(err, "unable to set the owner reference to the aggregator service")
			return ctrl.Result{}, err
		}
	}
	aggregatorService := &corev1.Service{}
	aggregatorServiceNamespacedName := types.NamespacedName{
		Namespace: req.Namespace,
		Name:      AggregatorDeploymentName,
	}
	if err := r.Get(ctx, aggregatorServiceNamespacedName, aggregatorService); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "unable to fetch aggregator service")
			return ctrl.Result{}, err
		}
		if desiredAggregatorService != nil {
			log.Info("aggregator service not found, creating")
			if err := r.Create(ctx, desiredAggregatorService); err != nil {
				log.Error(err, "unable to create aggregator service")
				return ctrl.Result{}, err
			}
			log.Info("aggregator service created")
			return ctrl.Result{Requeue: true}, nil
		}
	} else {
		if desiredAggregatorService == nil {
			if err := r.Delete(ctx, desiredAggregatorService); err != nil {
				log.Error(err, "unable to delete the aggregator service")
				return ctrl.Result{}, err
			}
			log.Info("aggregator service deleted")
			return ctrl.Result{Requeue: true}, nil
		}
	}
	if desiredAggregatorService != nil && (!equality.Semantic.DeepEqual(aggregatorService.Labels, desiredAggregatorService.Labels) ||
		!equality.Semantic.DeepEqual(aggregatorService.Spec, desiredAggregatorService.Spec)) {
		log.Info("updating aggregator service")
		if err := r.Update(ctx, desiredAggregatorService); err != nil {
			log.Error(err, "unable to update aggregator service")
			return ctrl.Result{}, err
		}
		log.Info("aggregator service updated")
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
