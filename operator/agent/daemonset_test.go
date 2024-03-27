package agent

import (
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	logr "sigs.k8s.io/controller-runtime/pkg/log"
)

func Test_dnsPolicy(t *testing.T) {
	testCases := []struct {
		configMap map[string]any
		expected  corev1.DNSPolicy
	}{
		{
			configMap: nil,
			expected:  corev1.DNSDefault,
		},
		{
			configMap: map[string]any{"dnsPolicy": "bla-bla-bla"},
			expected:  corev1.DNSDefault,
		},
		{
			configMap: map[string]any{"dnsPolicy": "ClusterFirst"},
			expected:  corev1.DNSClusterFirst,
		},
	}

	for _, tt := range testCases {
		// function to test
		actual := dnsPolicy(logr.Log, tt.configMap)

		require.Equal(t, tt.expected, actual)
	}
}

func Test_imagePullPolicy(t *testing.T) {
	testCases := []struct {
		configMap map[string]any
		expected  corev1.PullPolicy
	}{
		{
			configMap: nil,
			expected:  corev1.PullIfNotPresent,
		},
		{
			configMap: map[string]any{"imagePullPolicy": "bla-bla-bla"},
			expected:  corev1.PullIfNotPresent,
		},
		{
			configMap: map[string]any{"imagePullPolicy": "Always"},
			expected:  corev1.PullAlways,
		},
	}

	for _, tt := range testCases {
		// function to test
		actual := imagePullPolicy(logr.Log, tt.configMap)

		require.Equal(t, tt.expected, actual)
	}
}
