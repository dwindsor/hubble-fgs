package agent

import (
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	k8sv1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"
)

// AggregatorService instantiates a Tetragon Aggregator Service.
func AggregatorService(log logr.Logger, namespace string, name string, cm *corev1.ConfigMap) (*corev1.Service, error) {
	aggregatorConfigYaml := cm.Data[OperatorConfigMapAggregatorKey]
	aggregatorCMFields := make(map[string]interface{})
	if err := yaml.Unmarshal([]byte(aggregatorConfigYaml), &aggregatorCMFields); err != nil {
		log.WithValues("value", aggregatorConfigYaml).Error(err, "could not unmarshal the aggregator configuration")
		return nil, err
	}
	// the aggregator service gets only created if it is enabled
	if !configValue(log, aggregatorCMFields, "enabled", false) {
		return nil, nil
	}

	labels := labelsForManaged(name)
	service := &corev1.Service{
		TypeMeta: k8sv1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: k8sv1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Type:     corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       int32(8080),
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(8080),
				},
			},
		},
	}
	return service, nil
}
