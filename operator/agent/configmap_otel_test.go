// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package agent

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logr "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/stretchr/testify/require"
)

func TestOtelConfigMap(t *testing.T) {
	oName := "otel"
	oNs := "test"
	expectedOtelCM := &corev1.ConfigMap{
		TypeMeta: v1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      oName,
			Namespace: oNs,
			Labels: map[string]string{"app.kubernetes.io/instance": "otel",
				"app.kubernetes.io/managed-by": "tetragon-operator",
				"app.kubernetes.io/name":       "otel",
				"label1":                       "value1",
			},
		},
		Data: map[string]string{
			"otel-agent-config": `exporters:
  splunk_hec:
    endpoint: "${env:SPLUNK_HEC_ENDPOINT}"
    token: "${env:SPLUNK_HEC_TOKEN}"
    sourcetype: "cisco:isovalent"
    sending_queue:
      enabled: true
      num_consumers: 2
      queue_size: 512
    retry_on_failure:
      enabled: true
      initial_interval: 2s
      max_interval: 30s
      max_elapsed_time: 300s
    index: ~
    disable_compression: false
    timeout: 10s
    tls:
      ca_file: /tls/ca.crt
      cert_file: /tls/tls.crt
      key_file: /tls/tls.key
      insecure_skip_verify: false
extensions:
  file_storage:
    directory: /var/lib/otelcol/file-storage
processors:
  attributes:
    actions:
      - action: upsert
        key: com.splunk.source
        from_attribute: log.file.path # use log.file.name for just the basename
      - action: upsert
        key: com.splunk.sourcetype
        value: cisco:isovalent
  resource:
    attributes:
      - action: upsert
        key: host.name
        value: "${env:K8S_NODE}"
  memory_limiter:
    check_interval: 5s
    limit_mib: 512
  batch:
    #timeout: 60s
    timeout: 3600
    send_batch_max_size: 10240
    send_batch_size: 2560
receivers:
  filelog:
    include:
      - /var/log/tetragon/**/*.log
    multiline:
      line_start_pattern: "^{"
    start_at: end
    poll_interval: 1s
    max_concurrent_files: 20
    include_file_path: true
    include_file_name: true
    storage: file_storage
    operators:
      - type: json_parser
        on_error: send
      - type: time_parser
        parse_from: body.time
        layout_type: gotime
        layout: "2006-01-02T15:04:05.999999999Z07:00"
        on_error: send
service:
  extensions: [file_storage]
  pipelines:
    logs:
      receivers: [filelog]
      processors: [attributes, resource, memory_limiter, batch]
      exporters: [splunk_hec]
`,
		},
	}
	opCM := &corev1.ConfigMap{
		Data: map[string]string{
			splunkKey: `
enabled: true
extraLabels:
  label1: value1
index: ~
# Disables gzip compression over HTTP.
disable_compression: false
timeout: 10s
tls:
  secret:
    name: "splunk-tls-user"
    keys:
      ca_cert: ca.crt
      client_cert: tls.crt
      client_key: tls.key
  # Whether to skip checking the certificate of the HEC endpoint when sending data over HTTPS. Defaults to false.
  insecureSkipVerify: false`,
		},
	}
	otelCM, err := OtelConfigMap(logr.Log, oNs, oName, opCM)
	require.NoError(t, err, "Not able to generate the OTel configMap.")
	require.Equal(t, expectedOtelCM, otelCM)
	opCM2 := &corev1.ConfigMap{
		Data: map[string]string{
			splunkKey: `
enabled: true
extraLabels:
  label1: value1
index: ~
# Disables gzip compression over HTTP.
disable_compression: false
timeout: 10s
tls:
  ca: |
    -----BEGIN CERTIFICATE-----
    xxxxxxxxxxxxxxxxxxxxxxxxxxx
    -----END CERTIFICATE-------
  crt: |
    -----BEGIN CERTIFICATE-----
    xxxxxxxxxxxxxxxxxxxxxxxxxxx
    -----END CERTIFICATE-------
  key: |
    -----BEGIN CERTIFICATE-----
    xxxxxxxxxxxxxxxxxxxxxxxxxxx
    -----END CERTIFICATE-------
  # Whether to skip checking the certificate of the HEC endpoint when sending data over HTTPS. Defaults to false.
  insecureSkipVerify: false`,
		},
	}
	otelCM, err = OtelConfigMap(logr.Log, oNs, oName, opCM2)
	require.NoError(t, err, "Not able to generate the OTel configMap with inline certificates.")
	require.Equal(t, expectedOtelCM, otelCM)
}
