package agent

import (
	"testing"

	"github.com/stretchr/testify/require"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	logr "sigs.k8s.io/controller-runtime/pkg/log"
)

func TestAgentMonitorCfg(t *testing.T) {
	testCases := []struct {
		name     string
		cm       *corev1.ConfigMap
		expected monitorServiceCfg
	}{
		{
			name: "default values",
			cm:   DefaultOperatorConfigMap(logr.Log, "kube-system", "test"),
			expected: monitorServiceCfg{
				enabled:                    false,
				monitorYAML:                serviceMonitorAgentYAML,
				serviceYAML:                serviceAgentYAML,
				monitorLabels:              map[string]string{},
				monitorEndpointsInterval:   "10s",
				serviceLabels:              map[string]string{},
				serviceTargetPort:          intstr.Parse("2112"),
				serviceLabelSelectorLabels: map[string]string{},
			},
		},
		{
			name: "custom values",
			cm: &corev1.ConfigMap{
				Data: map[string]string{
					OperatorConfigMapAgentDaemonSetKey: `labelsOverride:
  sel-label1: value1
  sel-label2: value2
serviceMonitorEnabled: true
serviceMonitorLabelsOverride:
  mon-label1: value1
  mon-label2: value2
serviceMonitorScrapeInterval: 123s
serviceMonitorPrometheusPort: "1234"
serviceLabelsOverride:
  srv-label1: value1
  srv-label2: value2`,
				},
			},
			expected: monitorServiceCfg{
				enabled:     true,
				monitorYAML: serviceMonitorAgentYAML,
				serviceYAML: serviceAgentYAML,
				monitorLabels: map[string]string{
					"mon-label1": "value1",
					"mon-label2": "value2",
				},
				monitorEndpointsInterval: "123s",
				serviceLabels: map[string]string{
					"srv-label1": "value1",
					"srv-label2": "value2",
				},
				serviceTargetPort: intstr.Parse("1234"),
				serviceLabelSelectorLabels: map[string]string{
					"sel-label1": "value1",
					"sel-label2": "value2",
				},
			},
		},
	}

	for _, tt := range testCases {
		//function to test
		actual, err := agentMonitorCfg(logr.Log, tt.cm)

		require.NoError(t, err)
		require.Equal(t, tt.expected, actual)
	}
}

func TestOperatorMonitorCfg(t *testing.T) {
	testCases := []struct {
		name     string
		cm       *corev1.ConfigMap
		expected monitorServiceCfg
	}{
		{
			name: "default values",
			cm:   DefaultOperatorConfigMap(logr.Log, "kube-system", "test"),
			expected: monitorServiceCfg{
				enabled:                    false,
				monitorYAML:                serviceMonitorOperatorYAML,
				serviceYAML:                serviceOperatorYAML,
				monitorLabels:              map[string]string{},
				monitorEndpointsInterval:   "10s",
				serviceLabels:              map[string]string{},
				serviceTargetPort:          intstr.Parse("2113"),
				serviceLabelSelectorLabels: map[string]string{},
			},
		},
		{
			name: "custom values",
			cm: &corev1.ConfigMap{
				Data: map[string]string{
					"serviceMonitorEnabled": "true",
					"serviceMonitorLabelsOverride": `
  mon-label1: value1
  mon-label2: value2`,
					"serviceMonitorScrapeInterval": "123s",
					"serviceMonitorPrometheusPort": "1234",
					"serviceLabelsOverride": `
  srv-label1: value1
  srv-label2: value2`,
				},
			},
			expected: monitorServiceCfg{
				enabled:     true,
				monitorYAML: serviceMonitorOperatorYAML,
				serviceYAML: serviceOperatorYAML,
				monitorLabels: map[string]string{
					"mon-label1": "value1",
					"mon-label2": "value2",
				},
				monitorEndpointsInterval: "123s",
				serviceLabels: map[string]string{
					"srv-label1": "value1",
					"srv-label2": "value2",
				},
				serviceTargetPort:          intstr.Parse("1234"),
				serviceLabelSelectorLabels: map[string]string{},
			},
		},
	}

	for _, tt := range testCases {
		//function to test
		actual, err := operatorMonitorCfg(logr.Log, tt.cm)

		require.NoError(t, err)
		require.Equal(t, tt.expected, actual)
	}
}

func TestServiceMonitor(t *testing.T) {
	testCases := []struct {
		name      string
		namespace string
		cfg       monitorServiceCfg
		expected  *monitoringv1.ServiceMonitor
	}{
		{
			name:      "agent monitor default values",
			namespace: "kube-system",
			cfg: monitorServiceCfg{
				monitorYAML:              serviceMonitorAgentYAML,
				monitorEndpointsInterval: "10s",
			},
			expected: &monitoringv1.ServiceMonitor{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ServiceMonitor",
					APIVersion: "monitoring.coreos.com/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tetragon",
					Namespace: "kube-system",
					Labels: map[string]string{
						"app.kubernetes.io/instance": "tetragon",
						"app.kubernetes.io/name":     "tetragon",
					},
				},
				Spec: monitoringv1.ServiceMonitorSpec{
					Endpoints: []monitoringv1.Endpoint{
						{
							HonorLabels: true,
							Port:        "metrics",
							Path:        "/metrics",
							Interval:    monitoringv1.Duration("10s"),
							RelabelConfigs: []*monitoringv1.RelabelConfig{
								{
									SourceLabels: []monitoringv1.LabelName{"__meta_kubernetes_pod_node_name"},
									TargetLabel:  "node",
									Replacement:  "${1}",
								},
							},
						},
					},
					Selector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app.kubernetes.io/instance": "tetragon",
							"app.kubernetes.io/name":     "tetragon",
						},
					},
					NamespaceSelector: monitoringv1.NamespaceSelector{
						MatchNames: []string{"kube-system"},
					},
				},
			},
		},
		{
			name:      "agent monitor custom values",
			namespace: "kube-system",
			cfg: monitorServiceCfg{
				monitorYAML: serviceMonitorAgentYAML,
				monitorLabels: map[string]string{
					"label1": "value1",
					"label2": "value2",
				},
				monitorEndpointsInterval: "123s",
				serviceLabels: map[string]string{
					"srv-label1": "value1",
					"srv-label2": "value2",
				},
			},
			expected: &monitoringv1.ServiceMonitor{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ServiceMonitor",
					APIVersion: "monitoring.coreos.com/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tetragon",
					Namespace: "kube-system",
					Labels: map[string]string{
						"label1": "value1",
						"label2": "value2",
					},
				},
				Spec: monitoringv1.ServiceMonitorSpec{
					Endpoints: []monitoringv1.Endpoint{
						{
							HonorLabels: true,
							Port:        "metrics",
							Path:        "/metrics",
							Interval:    monitoringv1.Duration("123s"),
							RelabelConfigs: []*monitoringv1.RelabelConfig{
								{
									SourceLabels: []monitoringv1.LabelName{"__meta_kubernetes_pod_node_name"},
									TargetLabel:  "node",
									Replacement:  "${1}",
								},
							},
						},
					},
					Selector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"srv-label1": "value1",
							"srv-label2": "value2",
						},
					},
					NamespaceSelector: monitoringv1.NamespaceSelector{
						MatchNames: []string{"kube-system"},
					},
				},
			},
		},
		{
			name:      "operator monitor default values",
			namespace: "kube-system",
			cfg: monitorServiceCfg{
				monitorYAML:              serviceMonitorOperatorYAML,
				monitorEndpointsInterval: "10s",
			},
			expected: &monitoringv1.ServiceMonitor{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ServiceMonitor",
					APIVersion: "monitoring.coreos.com/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tetragon-operator",
					Namespace: "kube-system",
					Labels: map[string]string{
						"app.kubernetes.io/instance": "tetragon",
						"app.kubernetes.io/name":     "tetragon-operator",
					},
				},
				Spec: monitoringv1.ServiceMonitorSpec{
					Endpoints: []monitoringv1.Endpoint{
						{
							HonorLabels: true,
							Port:        "metrics",
							Path:        "/metrics",
							Interval:    monitoringv1.Duration("10s"),
							RelabelConfigs: []*monitoringv1.RelabelConfig{
								{
									SourceLabels: []monitoringv1.LabelName{"__meta_kubernetes_pod_node_name"},
									TargetLabel:  "node",
									Replacement:  "${1}",
								},
							},
						},
					},
					Selector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app.kubernetes.io/instance": "tetragon",
							"app.kubernetes.io/name":     "tetragon-operator",
						},
					},
					NamespaceSelector: monitoringv1.NamespaceSelector{
						MatchNames: []string{"kube-system"},
					},
				},
			},
		},
		{
			name:      "operator monitor custom values",
			namespace: "kube-system",
			cfg: monitorServiceCfg{
				monitorYAML: serviceMonitorOperatorYAML,
				monitorLabels: map[string]string{
					"label1": "value1",
					"label2": "value2",
				},
				monitorEndpointsInterval: "123s",
				serviceLabels: map[string]string{
					"srv-label1": "value1",
					"srv-label2": "value2",
				},
			},
			expected: &monitoringv1.ServiceMonitor{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ServiceMonitor",
					APIVersion: "monitoring.coreos.com/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tetragon-operator",
					Namespace: "kube-system",
					Labels: map[string]string{
						"label1": "value1",
						"label2": "value2",
					},
				},
				Spec: monitoringv1.ServiceMonitorSpec{
					Endpoints: []monitoringv1.Endpoint{
						{
							HonorLabels: true,
							Port:        "metrics",
							Path:        "/metrics",
							Interval:    monitoringv1.Duration("123s"),
							RelabelConfigs: []*monitoringv1.RelabelConfig{
								{
									SourceLabels: []monitoringv1.LabelName{"__meta_kubernetes_pod_node_name"},
									TargetLabel:  "node",
									Replacement:  "${1}",
								},
							},
						},
					},
					Selector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"srv-label1": "value1",
							"srv-label2": "value2",
						},
					},
					NamespaceSelector: monitoringv1.NamespaceSelector{
						MatchNames: []string{"kube-system"},
					},
				},
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// function to test
			actual, err := serviceMonitor(logr.Log, tt.namespace, tt.cfg)

			require.NoError(t, err)
			require.Equal(t, tt.expected, actual)
		})
	}
}

func TestServiceMonitorService(t *testing.T) {
	testCases := []struct {
		name      string
		namespace string
		cfg       monitorServiceCfg
		expected  *corev1.Service
	}{
		{
			name:      "agent service default values",
			namespace: "kube-system",
			cfg: monitorServiceCfg{
				serviceYAML:       serviceAgentYAML,
				serviceTargetPort: intstr.Parse("2112"),
			},
			expected: &corev1.Service{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Service",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tetragon",
					Namespace: "kube-system",
					Labels: map[string]string{
						"app.kubernetes.io/instance": "tetragon",
						"app.kubernetes.io/name":     "tetragon",
					},
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{
						{
							Name:       "metrics",
							Protocol:   "TCP",
							Port:       2112,
							TargetPort: intstr.Parse("2112"),
						},
					},
					Selector: map[string]string{
						"app.kubernetes.io/instance": "tetragon",
						"app.kubernetes.io/name":     "tetragon",
					},
					Type: "ClusterIP",
				},
			},
		},
		{
			name:      "agent service custom values",
			namespace: "kube-system",
			cfg: monitorServiceCfg{
				serviceYAML: serviceAgentYAML,
				serviceLabels: map[string]string{
					"srv-label1": "value1",
					"srv-label2": "value2",
				},
				serviceTargetPort: intstr.Parse("1234"),
				serviceLabelSelectorLabels: map[string]string{
					"label1": "value1",
					"label2": "value2",
				},
			},
			expected: &corev1.Service{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Service",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tetragon",
					Namespace: "kube-system",
					Labels: map[string]string{
						"srv-label1": "value1",
						"srv-label2": "value2",
					},
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{
						{
							Name:       "metrics",
							Protocol:   "TCP",
							Port:       2112,
							TargetPort: intstr.Parse("1234"),
						},
					},
					Selector: map[string]string{
						"label1": "value1",
						"label2": "value2",
					},
					Type: "ClusterIP",
				},
			},
		},
		{
			name:      "operator service default values",
			namespace: "kube-system",
			cfg: monitorServiceCfg{
				serviceYAML:       serviceOperatorYAML,
				serviceTargetPort: intstr.Parse("2113"),
			},
			expected: &corev1.Service{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Service",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tetragon-operator",
					Namespace: "kube-system",
					Labels: map[string]string{
						"app.kubernetes.io/instance": "tetragon",
						"app.kubernetes.io/name":     "tetragon-operator",
					},
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{
						{
							Name:       "metrics",
							Protocol:   "TCP",
							Port:       2113,
							TargetPort: intstr.Parse("2113"),
						},
					},
					Selector: map[string]string{
						"app.kubernetes.io/instance": "tetragon",
						"app.kubernetes.io/name":     "tetragon-operator",
					},
					Type: "ClusterIP",
				},
			},
		},
		{
			name:      "operator service custom values",
			namespace: "kube-system",
			cfg: monitorServiceCfg{
				serviceYAML: serviceOperatorYAML,
				serviceLabels: map[string]string{
					"srv-label1": "value1",
					"srv-label2": "value2",
				},
				serviceTargetPort: intstr.Parse("1234"),
				serviceLabelSelectorLabels: map[string]string{
					"label1": "value1",
					"label2": "value2",
				},
			},
			expected: &corev1.Service{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Service",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tetragon-operator",
					Namespace: "kube-system",
					Labels: map[string]string{
						"srv-label1": "value1",
						"srv-label2": "value2",
					},
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{
						{
							Name:       "metrics",
							Protocol:   "TCP",
							Port:       2113,
							TargetPort: intstr.Parse("1234"),
						},
					},
					Selector: map[string]string{
						"label1": "value1",
						"label2": "value2",
					},
					Type: "ClusterIP",
				},
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// function to test
			actual, err := serviceMonitorService(logr.Log, tt.namespace, tt.cfg)

			require.NoError(t, err)
			require.Equal(t, tt.expected, actual)
		})
	}
}

func TestIntervalDuration(t *testing.T) {
	testCases := []struct {
		value    string
		expected monitoringv1.Duration
	}{
		{
			value:    "",
			expected: monitoringv1.Duration("10s"),
		},
		{
			value:    "bla-bla-bla",
			expected: monitoringv1.Duration("10s"),
		},
		{
			value:    "123s",
			expected: monitoringv1.Duration("123s"),
		},
	}

	for _, tt := range testCases {
		//function to test
		actual := intervalDuration(logr.Log, tt.value)

		require.Equal(t, tt.expected, actual)
	}
}
