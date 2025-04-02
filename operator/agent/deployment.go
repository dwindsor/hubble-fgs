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
func AggregatorDeployment(log logr.Logger, namespace string, name string, cm *corev1.ConfigMap) (*appv1.Deployment, error) {
	aggregatorConfigYaml := cm.Data[OperatorConfigMapAggregatorKey]
	aggregatorCMFields := make(map[string]interface{})
	if err := yaml.Unmarshal([]byte(aggregatorConfigYaml), &aggregatorCMFields); err != nil {
		log.WithValues("value", aggregatorConfigYaml).Error(err, "could not unmarshal the aggregator configuration")
		return nil, err
	}
	// the aggregator deployment gets only created if it is enabled
	if !configValue(log, aggregatorCMFields, "enabled", false) {
		return nil, nil
	}

	labels := labelsForManaged(name)
	for k, v := range configMapOfString(log, aggregatorCMFields, "extraLabels") {
		labels[k] = v
	}

	podLabels := labelsForManaged(name)
	for k, v := range configMapOfString(log, aggregatorCMFields, "extraPodLabels") {
		podLabels[k] = v
	}

	imagePullSecrets := make([]corev1.LocalObjectReference, 0)
	imagePullSecretsValue := configValue(log, aggregatorCMFields, "imagePullSecrets", "")
	if imagePullSecretsValue != "" {
		if err := yaml.Unmarshal([]byte(imagePullSecretsValue), &imagePullSecrets); err != nil {
			log.WithValues("value", imagePullSecretsValue).Error(err, "could not unmarshal the imagePullSecrets, skipped")
		}
	}

	podSecurityContext := corev1.PodSecurityContext{}
	podSecurityContextValue := configValue(log, aggregatorCMFields, "podSecurityContext", "")
	if podSecurityContextValue != "" {
		if err := yaml.Unmarshal([]byte(podSecurityContextValue), &podSecurityContext); err != nil {
			log.WithValues("value", podSecurityContextValue).Error(err, "could not unmarshal the podSecurityContext, default value used instead")
		}
	}

	var affinity corev1.Affinity
	affinityValue := configValue(log, aggregatorCMFields, "affinity", "")
	if affinityValue != "" {
		if err := yaml.Unmarshal([]byte(affinityValue), &affinity); err != nil {
			log.WithValues("value", affinityValue).Error(err, "could not unmarshal the affinity, affinity not applied")
		}
	}

	tolerations := make([]corev1.Toleration, 0)
	tolerationValues := configValue(log, aggregatorCMFields, "tolerations", "")
	if tolerationValues != "" {
		if err := yaml.Unmarshal([]byte(tolerationValues), &tolerations); err != nil {
			log.WithValues("value", tolerationValues).Error(err, "could not unmarshal the toleration, toleration not applied")
		}
	}

	resources := corev1.ResourceRequirements{}
	resourcesValue := configValue(log, aggregatorCMFields, "resources", "")
	if resourcesValue != "" {
		if err := yaml.Unmarshal([]byte(resourcesValue), &resources); err != nil {
			log.WithValues("value", resourcesValue).Error(err, "could not unmarshal the resources, default value used instead")
		}
	}

	var deploymentStrategy appv1.DeploymentStrategy
	deploymentStrategyValue := configValue(log, aggregatorCMFields, "strategy", "")
	if deploymentStrategyValue != "" {
		if err := yaml.Unmarshal([]byte(deploymentStrategyValue), &deploymentStrategy); err != nil {
			log.WithValues("value", deploymentStrategyValue).Error(err, "could not unmarshal the deployment strategy, deployment strategy not applied")
		}
	}

	replicas := int32(1)
	boolFalse := false
	terminationGracePeriodSeconds := int64(10)
	deployment := &appv1.Deployment{
		TypeMeta: k8sv1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: k8sv1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: configMapOfString(log, aggregatorCMFields, "annotations"),
			Labels:      labels,
		},
		Spec: appv1.DeploymentSpec{
			Selector: &k8sv1.LabelSelector{
				MatchLabels: labelsForManaged(name),
			},
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: k8sv1.ObjectMeta{
					Labels:      podLabels,
					Annotations: configMapOfString(log, aggregatorCMFields, "podAnnotations"),
				},
				Spec: corev1.PodSpec{
					PriorityClassName:             configValue(log, aggregatorCMFields, "priorityClassName", ""),
					ImagePullSecrets:              imagePullSecrets,
					AutomountServiceAccountToken:  &boolFalse,
					SecurityContext:               &podSecurityContext,
					Containers:                    aggregatorDeploymentContainers(log, name, aggregatorCMFields),
					NodeSelector:                  configMapOfString(log, aggregatorCMFields, "nodeSelector"),
					Affinity:                      &affinity,
					Tolerations:                   tolerations,
					Volumes:                       volumesFromConfigMap(log, aggregatorCMFields, "extraVolumes"),
					TerminationGracePeriodSeconds: &terminationGracePeriodSeconds,
					Resources:                     &resources,
				},
			},
			Strategy: deploymentStrategy,
		},
	}
	return deployment, nil
}

func aggregatorDeploymentContainers(log logr.Logger, name string, cmFields map[string]any) []corev1.Container {
	securityContext := corev1.SecurityContext{}
	securityContextValue := configValue(log, cmFields, "securityContext", "")
	if securityContextValue != "" {
		if err := yaml.Unmarshal([]byte(securityContextValue), &securityContext); err != nil {
			log.WithValues("value", securityContextValue).Error(err, "could not unmarshal the aggregator container security context, default value used instead")
		}
	}

	return []corev1.Container{{
		Name:            name,
		Command:         []string{"/usr/bin/tetragon-aggregator", "aggregate"},
		Image:           os.Getenv("TETRAGON_AGGREGATOR_IMAGE"),
		ImagePullPolicy: imagePullPolicy(log, cmFields, "imagePullPolicy"),
		SecurityContext: &securityContext,
		VolumeMounts:    volumeMountsFromConfigMap(log, cmFields, "extraVolumeMounts"),
	}}
}
