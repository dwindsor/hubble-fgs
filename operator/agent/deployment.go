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
	"os"

	"github.com/go-logr/logr"
	appv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8sv1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// AggregatorDeployment instantiates a Tetragon Aggregator Deployment.
func AggregatorDeployment(log logr.Logger, namespace string, name string, config map[string]interface{}) (*appv1.Deployment, error) {
	// the aggregator deployment gets only created if it is enabled
	if !configValue(log, config, "enabled", false) {
		return nil, nil
	}

	labels := labelsForManaged(name)
	for k, v := range configMapOfString(log, config, "extraLabels") {
		labels[k] = v
	}

	podLabels := labelsForManaged(name)
	for k, v := range configMapOfString(log, config, "extraPodLabels") {
		podLabels[k] = v
	}

	imagePullSecrets := make([]corev1.LocalObjectReference, 0)
	imagePullSecretsValue := configValue(log, config, "imagePullSecrets", "")
	if imagePullSecretsValue != "" {
		if err := yaml.Unmarshal([]byte(imagePullSecretsValue), &imagePullSecrets); err != nil {
			log.WithValues("value", imagePullSecretsValue).Error(err, "could not unmarshal the imagePullSecrets, skipped")
		}
	}

	podSecurityContext := corev1.PodSecurityContext{}
	podSecurityContextValue := configValue(log, config, "podSecurityContext", "")
	if podSecurityContextValue != "" {
		if err := yaml.Unmarshal([]byte(podSecurityContextValue), &podSecurityContext); err != nil {
			log.WithValues("value", podSecurityContextValue).Error(err, "could not unmarshal the podSecurityContext, default value used instead")
		}
	}

	var affinity corev1.Affinity
	affinityValue := configValue(log, config, "affinity", "")
	if affinityValue != "" {
		if err := yaml.Unmarshal([]byte(affinityValue), &affinity); err != nil {
			log.WithValues("value", affinityValue).Error(err, "could not unmarshal the affinity, affinity not applied")
		}
	}

	tolerations := make([]corev1.Toleration, 0)
	tolerationValues := configValue(log, config, "tolerations", "")
	if tolerationValues != "" {
		if err := yaml.Unmarshal([]byte(tolerationValues), &tolerations); err != nil {
			log.WithValues("value", tolerationValues).Error(err, "could not unmarshal the toleration, toleration not applied")
		}
	}

	resources := corev1.ResourceRequirements{}
	resourcesValue := configValue(log, config, "resources", "")
	if resourcesValue != "" {
		if err := yaml.Unmarshal([]byte(resourcesValue), &resources); err != nil {
			log.WithValues("value", resourcesValue).Error(err, "could not unmarshal the resources, default value used instead")
		}
	}

	var deploymentStrategy appv1.DeploymentStrategy
	deploymentStrategyValue := configValue(log, config, "strategy", "")
	if deploymentStrategyValue != "" {
		if err := yaml.Unmarshal([]byte(deploymentStrategyValue), &deploymentStrategy); err != nil {
			log.WithValues("value", deploymentStrategyValue).Error(err, "could not unmarshal the deployment strategy, deployment strategy not applied")
		}
	}

	deployment := &appv1.Deployment{
		TypeMeta: k8sv1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: k8sv1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: configMapOfString(log, config, "annotations"),
			Labels:      labels,
		},
		Spec: appv1.DeploymentSpec{
			Selector: &k8sv1.LabelSelector{
				MatchLabels: labelsForManaged(name),
			},
			Replicas: new(int32(1)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: k8sv1.ObjectMeta{
					Labels:      podLabels,
					Annotations: configMapOfString(log, config, "podAnnotations"),
				},
				Spec: corev1.PodSpec{
					PriorityClassName:             configValue(log, config, "priorityClassName", ""),
					ImagePullSecrets:              imagePullSecrets,
					AutomountServiceAccountToken:  new(false),
					SecurityContext:               &podSecurityContext,
					Containers:                    aggregatorDeploymentContainers(log, name, config),
					NodeSelector:                  configMapOfString(log, config, "nodeSelector"),
					Affinity:                      &affinity,
					Tolerations:                   tolerations,
					Volumes:                       volumesFromConfigMap(log, config, "extraVolumes"),
					TerminationGracePeriodSeconds: new(int64(10)),
					Resources:                     &resources,
				},
			},
			Strategy: deploymentStrategy,
		},
	}
	return deployment, nil
}

func aggregatorDeploymentContainers(log logr.Logger, name string, config map[string]any) []corev1.Container {
	securityContext := corev1.SecurityContext{}
	securityContextValue := configValue(log, config, "securityContext", "")
	if securityContextValue != "" {
		if err := yaml.Unmarshal([]byte(securityContextValue), &securityContext); err != nil {
			log.WithValues("value", securityContextValue).Error(err, "could not unmarshal the aggregator container security context, default value used instead")
		}
	}

	return []corev1.Container{{
		Name:            name,
		Command:         []string{"/usr/bin/tetragon-aggregator", "aggregate"},
		Image:           os.Getenv("TETRAGON_AGGREGATOR_IMAGE"),
		ImagePullPolicy: imagePullPolicy(log, config, "imagePullPolicy"),
		SecurityContext: &securityContext,
		VolumeMounts:    volumeMountsFromConfigMap(log, config, "extraVolumeMounts"),
	}}
}
