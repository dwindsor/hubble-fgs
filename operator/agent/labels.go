package agent

import (
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

// aggregatedLabels returns the labels configured by the user in the operator
// ConfigMap in addition to the ones that always get applied.
func aggregatedLabels(log logr.Logger, cm *corev1.ConfigMap, key string) map[string]string {
	labelsCfg := cm.Data[key]
	labels := labelsForManaged()
	if err := yaml.Unmarshal([]byte(labelsCfg), &labels); err != nil {
		log.WithValues("key", key, "value", labelsCfg).Error(err, "could not unmarshal the labels configuration, labels not applied")
	}
	return labels
}

// labelsForManaged returns the generic Tetragon labels plus ManagedBy label.
func labelsForManaged() map[string]string {
	return map[string]string{
		"app.kubernetes.io/instance":   daemonSetName,
		"app.kubernetes.io/name":       daemonSetName,
		"app.kubernetes.io/managed-by": "tetragon-operator",
	}
}
