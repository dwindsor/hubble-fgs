// TODO(FGI) rename to agent
package daemon

import (
	corev1 "k8s.io/api/core/v1"
	k8sv1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

const (
	OperatorConfigMapName              = "tetragon-operator-config"
	AgentConfigMapName                 = "tetragon-config"
	OperatorConfigMapAgentConfigMapKey = "agentConfigMap"
)

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
			OperatorConfigMapAgentConfigMapKey: `# Configuration of the agent ConfigMap
# The content specified here will be copied into it.
# Refer to Tetragon documentation for the options.`,
			OperatorConfigMapAgentDaemonSetKey: `# Configuration of the agent DaemonSet
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
func agentConfigMap(namespace string, name string, opCM *corev1.ConfigMap) *corev1.ConfigMap {
	agentCM := &corev1.ConfigMap{
		TypeMeta: k8sv1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: k8sv1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			// .
			Labels: map[string]string{ //TODO: make configurable
				"app.kubernetes.io/instance": DaemonSetName,
				"app.kubernetes.io/name":     DaemonSetName,
				ManagedByLabel:               TetragonOperatorName,
			},
		},
		Data: valuesAsMap(opCM.Data[OperatorConfigMapAgentConfigMapKey]),
	}
	return agentCM
}

func valuesAsMap(yamlValues string) map[string]string {
	values := map[string]string{}
	err := yaml.Unmarshal([]byte(yamlValues), &values)
	if err != nil {
		log.WithField("value", yamlValues).WithError(err).Error("could not unmarshal the agent ConfigMap, left empty")
	}
	return values
}
