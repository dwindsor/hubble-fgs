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

func TestOtelSecret(t *testing.T) {
	oName := "tetragon-splunk-tls"
	oNs := "test"
	opCM := &corev1.ConfigMap{
		Data: map[string]string{
			splunkKey: `
enabled: true
extraLabels:
  label1: value1
index: ~
tls:
  secret:
    name: "splunk-tls-user"
    keys:
      ca_cert: ca.crt
      client_cert: tls.crt
      client_key: tls.key`,
		},
	}
	otelSecret, err := OtelSecret(logr.Log, oNs, oName, opCM)
	require.NoError(t, err, "Not able to generate the OTel secret.")
	require.Nil(t, otelSecret)
	opCM = &corev1.ConfigMap{
		Data: map[string]string{
			splunkKey: `
enabled: true
extraLabels:
  label1: value1
index: ~
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
    -----END CERTIFICATE-------`,
		},
	}
	expectedOtelSecret := &corev1.Secret{
		TypeMeta: v1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      oName,
			Namespace: oNs,
			Labels: map[string]string{"app.kubernetes.io/instance": oName,
				"app.kubernetes.io/managed-by": "tetragon-operator",
				"app.kubernetes.io/name":       oName,
				"label1":                       "value1",
			},
		},
		Data: map[string][]byte{
			"ca.crt": []byte(`-----BEGIN CERTIFICATE-----
xxxxxxxxxxxxxxxxxxxxxxxxxxx
-----END CERTIFICATE-------`),
			"tls.crt": []byte(`-----BEGIN CERTIFICATE-----
xxxxxxxxxxxxxxxxxxxxxxxxxxx
-----END CERTIFICATE-------`),
			"tls.key": []byte(`-----BEGIN CERTIFICATE-----
xxxxxxxxxxxxxxxxxxxxxxxxxxx
-----END CERTIFICATE-------`),
		},
	}
	otelSecret, err = OtelSecret(logr.Log, oNs, oName, opCM)
	require.NoError(t, err, "Not able to generate the OTel secret.")
	require.Equal(t, expectedOtelSecret, otelSecret)
}
