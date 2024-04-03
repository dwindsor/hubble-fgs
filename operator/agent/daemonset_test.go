package agent

import (
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	logr "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/yaml"
)

func TestDnsPolicy(t *testing.T) {
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

func TestImagePullPolicy(t *testing.T) {
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

func TestConfigValue_bool(t *testing.T) {
	key := "test"
	testCases := []struct {
		configMap    map[string]any
		defaultValue bool
		expected     bool
	}{
		{
			configMap:    map[string]any{},
			defaultValue: false,
			expected:     false,
		},
		{
			configMap: map[string]any{
				key: true,
			},
			defaultValue: false,
			expected:     true,
		},
		{
			configMap: map[string]any{
				key: "true",
			},
			defaultValue: false,
			expected:     false,
		},
	}

	for _, tt := range testCases {
		// function to test
		actual := configValue(logr.Log, tt.configMap, key, tt.defaultValue)

		require.Equal(t, tt.expected, actual)
	}
}

func TestConfigValue_string(t *testing.T) {
	key := "test"
	testCases := []struct {
		configMap    map[string]any
		defaultValue string
		expected     string
	}{
		{
			configMap:    map[string]any{},
			defaultValue: "default",
			expected:     "default",
		},
		{
			configMap: map[string]any{
				key: "123",
			},
			defaultValue: "default",
			expected:     "123",
		},
		{
			configMap: map[string]any{
				key: true,
			},
			defaultValue: "default",
			expected:     "default",
		},
	}

	for _, tt := range testCases {
		// function to test
		actual := configValue(logr.Log, tt.configMap, key, tt.defaultValue)

		require.Equal(t, tt.expected, actual)
	}
}

func TestConfigMapOfString(t *testing.T) {
	key := "test"
	testCases := []struct {
		configMap map[string]any
		expected  map[string]string
	}{
		{
			configMap: map[string]any{},
			expected:  map[string]string{},
		},
		{
			configMap: map[string]any{
				key: "not map",
			},
			expected: map[string]string{},
		},
		{
			configMap: map[string]any{
				key: map[string]interface{}{
					"key1": "value1",
					"key2": "true",
					"key3": "-1",
				},
			},
			expected: map[string]string{
				"key1": "value1",
				"key2": "true",
				"key3": "-1",
			},
		},
	}

	for _, tt := range testCases {
		// function to test
		actual := configMapOfString(logr.Log, tt.configMap, key)

		require.Equal(t, tt.expected, actual)
	}
}

func TestConfigArray(t *testing.T) {
	key := "test"
	testCases := []struct {
		yamlString   string
		defaultValue []string
		expected     []string
	}{
		{
			yamlString:   "",
			defaultValue: []string{"default"},
			expected:     []string{"default"},
		},
		{
			yamlString: key + `:
- tetragon-1.log
- tetragon-2.log`,
			defaultValue: []string{"default"},
			expected:     []string{"tetragon-1.log", "tetragon-2.log"},
		},
	}

	for _, tt := range testCases {
		cfgMap := make(map[string]any)
		require.NoError(t, yaml.Unmarshal([]byte(tt.yamlString), &cfgMap))
		// function to test
		actual := configArray(logr.Log, cfgMap, key, tt.defaultValue)

		require.Equal(t, tt.expected, actual)
	}
}
