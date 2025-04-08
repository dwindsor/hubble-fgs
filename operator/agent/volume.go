package agent

import (
	"fmt"

	"github.com/go-logr/logr"

	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/yaml"
)

func volumesFromConfigMap(log logr.Logger, cmFields map[string]any, key string) []corev1.Volume {
	value := configValue(log, cmFields, key, "")
	if value == "" {
		return []corev1.Volume{}
	}
	volumes := make([]corev1.Volume, 0)
	if err := yaml.Unmarshal([]byte(value), &volumes); err != nil {
		log.WithValues("value", value).Error(err, fmt.Sprintf("could not unmarshal the %s volume, skipped", key))
	}
	return volumes
}

func volumeMountsFromConfigMap(log logr.Logger, cmFields map[string]any, key string) []corev1.VolumeMount {
	value := configValue(log, cmFields, key, "")
	if value == "" {
		return []corev1.VolumeMount{}
	}
	mounts := make([]corev1.VolumeMount, 0)
	if err := yaml.Unmarshal([]byte(value), &mounts); err != nil {
		log.WithValues("value", value).Error(err, fmt.Sprintf("could not unmarshal the %s volume mount, skipped", key))
	}
	return mounts
}
