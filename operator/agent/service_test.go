package agent

import (
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	logr "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/yaml"
)

func TestAggregatorService(t *testing.T) {
	testCases := []struct {
		name        string
		namespace   string
		serviceName string
		cm          *corev1.ConfigMap
		expected    *corev1.Service
	}{
		{
			name:        "default values [aggregator disabled]",
			namespace:   "kube-system",
			serviceName: "tetragon-aggregator",
			cm:          &corev1.ConfigMap{},
		},
		{
			name:        "default values [aggregator enabled]",
			namespace:   "kube-system",
			serviceName: "tetragon-aggregator",
			cm: &corev1.ConfigMap{
				Data: map[string]string{
					OperatorConfigMapAggregatorKey: "enabled: true",
				},
			},
			expected: &corev1.Service{
				TypeMeta: v1.TypeMeta{
					Kind:       "Service",
					APIVersion: "v1",
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      "tetragon-aggregator",
					Namespace: "kube-system",
					Labels: map[string]string{
						"app.kubernetes.io/instance":   "tetragon-aggregator",
						"app.kubernetes.io/name":       "tetragon-aggregator",
						"app.kubernetes.io/managed-by": "tetragon-operator",
					},
				},
				Spec: corev1.ServiceSpec{
					Selector: map[string]string{
						"app.kubernetes.io/instance":   "tetragon-aggregator",
						"app.kubernetes.io/name":       "tetragon-aggregator",
						"app.kubernetes.io/managed-by": "tetragon-operator",
					},
					Type: corev1.ServiceTypeClusterIP,
					Ports: []corev1.ServicePort{
						{
							Name:       "http",
							Port:       int32(8080),
							Protocol:   corev1.ProtocolTCP,
							TargetPort: intstr.FromInt(8080),
						},
					}},
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// get the config
			config := make(map[string]interface{})
			err := yaml.Unmarshal([]byte(tt.cm.Data[OperatorConfigMapAggregatorKey]), &config)
			require.NoError(t, err)

			// function to test
			actual, err := AggregatorService(logr.Log, tt.namespace, tt.serviceName, config)
			require.NoError(t, err)
			require.Equal(t, tt.expected, actual)
		})
	}
}
