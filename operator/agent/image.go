package agent

import (
	"errors"

	"github.com/go-logr/logr"

	corev1 "k8s.io/api/core/v1"
)

func imagePullPolicy(log logr.Logger, config map[string]any, key string) corev1.PullPolicy {
	policy := corev1.PullPolicy(configValue(log, config, key, ""))
	switch policy {
	case corev1.PullAlways, corev1.PullNever, corev1.PullIfNotPresent:
		return policy
	}
	log.WithValues("key", key, "value", policy).Error(errors.New("could not resolve image pull policy"), "default value used instead")
	return corev1.PullIfNotPresent
}
