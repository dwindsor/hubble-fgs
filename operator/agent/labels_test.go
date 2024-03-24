package agent

import (
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	logr "sigs.k8s.io/controller-runtime/pkg/log"
)

func TestAggregatedLabels(t *testing.T) {
	testCases := []struct {
		configMap *corev1.ConfigMap
		expected  map[string]string
	}{
		{
			configMap: &corev1.ConfigMap{
				Data: map[string]string{},
			},
			expected: map[string]string{
				"app.kubernetes.io/instance":   daemonSetName,
				"app.kubernetes.io/name":       daemonSetName,
				"app.kubernetes.io/managed-by": "tetragon-operator",
			},
		},
		{
			configMap: &corev1.ConfigMap{
				Data: map[string]string{
					"labels": `
label1: true
label2: 123
label3: text
app.kubernetes.io/managed-by: user`,
				},
			},
			expected: map[string]string{
				"label1":                       "true",
				"label2":                       "123",
				"label3":                       "text",
				"app.kubernetes.io/instance":   daemonSetName,
				"app.kubernetes.io/name":       daemonSetName,
				"app.kubernetes.io/managed-by": "user",
			},
		},
	}

	for _, tt := range testCases {
		// function to test
		actual := aggregatedLabels(logr.Log, tt.configMap, "labels")

		require.Equal(t, tt.expected, actual)
	}
}
