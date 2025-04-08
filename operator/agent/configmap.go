package agent

import (
	_ "embed"
	"errors"

	"github.com/go-logr/logr"

	corev1 "k8s.io/api/core/v1"
	k8sv1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/yaml"
)

const (
	OperatorConfigMapAgentConfigMapKey   = "agentConfigMap"
	OperatorConfigMapAgentDaemonSetKey   = "agentDaemonSet"
	OperatorConfigMapRTHooksDaemonSetKey = "rtHooks"
	OperatorConfigMapAggregatorKey       = "aggregator"
)

var (
	//go:embed manifests/operator-config.yaml
	defaultOperatorConfig string

	//go:embed manifests/tetragon-config.yaml
	defaultAgentConfig string

	//go:embed manifests/agent-daemonset-config.yaml
	defaultDSConfig string

	//go:embed manifests/rthooks-daemonset-config.yaml
	defaultRTDSConfig string

	//go:embed manifests/aggregator-config.yaml
	defaultAggregatorConfig string
)

// DefaultOperatorConfigMap creates a ConfigMap.
// It matches the mount configuration of the operator.
// Note: this ConfigMap is not managed by the operator. It is actually driving the operator.
// A ConfigMap is only created for convenience. Users are free
// to create it themselves and to update it as they wish.
func DefaultOperatorConfigMap(log logr.Logger, namespace string, name string) *corev1.ConfigMap {
	data := ValuesAsMap(log, defaultOperatorConfig)
	data[OperatorConfigMapAgentConfigMapKey] = defaultAgentConfig
	data[OperatorConfigMapAgentDaemonSetKey] = defaultDSConfig
	data[OperatorConfigMapRTHooksDaemonSetKey] = defaultRTDSConfig
	data[OperatorConfigMapAggregatorKey] = defaultAggregatorConfig
	cm := &corev1.ConfigMap{
		TypeMeta: k8sv1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: k8sv1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			// No label here. This ConfigMap is not managed by the operator.
			Labels: map[string]string{},
		},
		Data: data,
	}
	return cm
}

// ExtractAgentConfigMap instantiates a ConfigMap based on the operator configuration.
func ExtractAgentConfigMap(log logr.Logger, namespace string, name string, opCM *corev1.ConfigMap) *corev1.ConfigMap {
	agentCM := &corev1.ConfigMap{
		TypeMeta: k8sv1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: k8sv1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    opCM.Labels,
		},
		Data: ValuesAsMap(log, opCM.Data[OperatorConfigMapAgentConfigMapKey]),
	}
	return agentCM
}

func ValuesAsMap(log logr.Logger, yamlValues string) map[string]string {
	values := map[string]string{}
	if err := yaml.Unmarshal([]byte(yamlValues), &values); err != nil {
		log.WithValues("value", yamlValues).Error(err, "could not unmarshal the agent ConfigMap, left empty")
	}
	return values
}

func configValue[V string | bool](log logr.Logger, config map[string]any, key string, defaultValue V) V {
	if value, ok := config[key]; ok {
		if typedValue, ok := value.(V); ok {
			return typedValue
		}
		log.WithValues("key", key, "value", value).Error(errors.New("could not unmarshal"), "default value used instead")
	}
	return defaultValue
}

func configMapOfString(log logr.Logger, m map[string]any, key string) map[string]string {
	stringValues := map[string]string{}
	if values, ok := m[key]; ok {
		typedValues, ok := values.(map[string]interface{})
		if !ok {
			log.WithValues("key", key, "value", values).Error(errors.New("could not unmarshal"), "not applied")
		} else {
			for k, v := range typedValues {
				stringValues[k] = v.(string)
			}
		}
	}
	return stringValues
}
