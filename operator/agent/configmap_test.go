package agent

import (
	"testing"

	"github.com/stretchr/testify/require"

	logr "sigs.k8s.io/controller-runtime/pkg/log"
)

func TestValuesAsMap(t *testing.T) {
	testCases := []struct {
		yamlString string
		expected   map[string]string
	}{
		{
			yamlString: "",
			expected:   map[string]string{},
		},
		{
			yamlString: "invalid yaml string",
			expected:   map[string]string{},
		},
		{
			yamlString: `# Configuration of the agent ConfigMap.
# The content specified here will be copied into it.
enable-k8s-api: "true"
enable-process-cred: "false"
export-allowlist: '{"event_set":["PROCESS_CONNECT", "PROCESS_EXEC", "PROCESS_HTTP", "PROCESS_KPROBE", "PROCESS_LISTEN", "PROCESS_TLS"]}'
export-denylist: |-
  {"health_check":true}
  {"namespace":["", "cilium", "kube-system"]}
export-file-max-backups: "5"
export-filename: /var/run/cilium/tetragon/tetragon.log
export-rate-limit: "-1"
field-filters: '{}'
fim-runtime-endpoint: ""
gops-address: localhost:8118
metrics-server: :2112`,
			expected: map[string]string{
				"enable-k8s-api":          "true",
				"enable-process-cred":     "false",
				"export-allowlist":        "{\"event_set\":[\"PROCESS_CONNECT\", \"PROCESS_EXEC\", \"PROCESS_HTTP\", \"PROCESS_KPROBE\", \"PROCESS_LISTEN\", \"PROCESS_TLS\"]}",
				"export-denylist":         "{\"health_check\":true}\n{\"namespace\":[\"\", \"cilium\", \"kube-system\"]}",
				"export-file-max-backups": "5",
				"export-filename":         "/var/run/cilium/tetragon/tetragon.log",
				"export-rate-limit":       "-1",
				"fim-runtime-endpoint":    "",
				"gops-address":            "localhost:8118",
				"field-filters":           "{}",
				"metrics-server":          ":2112",
			},
		},
	}

	for _, tt := range testCases {
		// function to test
		actual := ValuesAsMap(logr.Log, tt.yamlString)

		require.Equal(t, tt.expected, actual)
	}
}
