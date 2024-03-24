package agent

import (
	_ "embed"

	"github.com/go-logr/logr"

	corev1 "k8s.io/api/core/v1"
	k8sv1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/yaml"
)

const operatorConfigMapAgentConfigMapKey = "agentConfigMap"

//go:embed tetragon-config.yaml
var defaultAgentConfig string

// defaultOperatorConfigMap creates an empty ConfigMap.
// It matches the mount configuration of the operator.
// Note: this ConfigMap is not managed by the operator. It is actually driving the operator.
// An empty ConfigMap is only created for convenience. Users are free
// to create it themselves and to update it as they wish.
func defaultOperatorConfigMap(namespace string, name string) *corev1.ConfigMap {
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
		Data: map[string]string{
			operatorConfigMapAgentConfigMapKey: defaultAgentConfig,
			operatorConfigMapAgentDaemonSetKey: `# Configuration of the agent DaemonSet
#   labels:
#     key1: value1
#   dnsPolicy: Default
#   serviceAccountName: tetragon
#   hostNetwork: true
#   exportMode: stdout
#   exportFileNames:
#   - file1.log
#   exportDirectory: /var/run/cilium/tetragon
#   imagePullPolicy: IfNotPresent
#   argsOverride:
#   - --arg1=value1
#   grpcEnabled: true
#   grpcAddress: localhost:64321`,
		},
	}
	return cm
}

// agentConfigMap instantiates a ConfigMap based on the operator configuration.
func agentConfigMap(log logr.Logger, namespace string, name string, opCM *corev1.ConfigMap) *corev1.ConfigMap {
	agentCM := &corev1.ConfigMap{
		TypeMeta: k8sv1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: k8sv1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    aggregatedLabels(log, opCM, "labels"),
		},
		Data: valuesAsMap(log, opCM.Data[operatorConfigMapAgentConfigMapKey]),
	}
	return agentCM
}

func valuesAsMap(log logr.Logger, yamlValues string) map[string]string {
	values := map[string]string{}
	if err := yaml.Unmarshal([]byte(yamlValues), &values); err != nil {
		log.WithValues("value", yamlValues).Error(err, "could not unmarshal the agent ConfigMap, left empy")
	}
	return values
}
