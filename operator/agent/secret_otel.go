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
	"strings"

	"github.com/go-logr/logr"
	// Using gopkg.in/yaml.v3 as it preserves quotes
	"gopkg.in/yaml.v3"

	corev1 "k8s.io/api/core/v1"
)

// OtelSecret creates the Secret with the otel TLS certificates.
func OtelSecret(log logr.Logger, namespace string, name string, opCM *corev1.ConfigMap) (*corev1.Secret, error) {
	data := map[string][]byte{}
	var opSplunk yaml.Node
	if err := yaml.Unmarshal([]byte(opCM.Data[splunkKey]), &opSplunk); err != nil {
		log.WithValues("value", opCM.Data[splunkKey]).Error(err, "could not unmarshal the splunk_hec configuration")
		return nil, err
	}
	toCreate := false
	if tlsCAValue, err := yamlNodeFind(&opSplunk, []string{tlsKey, tlsCAKey}); err == nil {
		data["ca.crt"] = []byte(strings.TrimRight(tlsCAValue.Value, "\n"))
		toCreate = true
	} else {
		data["ca.crt"] = []byte{}
	}
	if tlsCertValue, err := yamlNodeFind(&opSplunk, []string{tlsKey, tlsCertKey}); err == nil {
		data["tls.crt"] = []byte(strings.TrimRight(tlsCertValue.Value, "\n"))
		toCreate = true
	} else {
		data["tls.crt"] = []byte{}
	}
	if tlsKeyValue, err := yamlNodeFind(&opSplunk, []string{tlsKey, tlsKeyKey}); err == nil {
		data["tls.key"] = []byte(strings.TrimRight(tlsKeyValue.Value, "\n"))
		toCreate = true
	} else {
		data["tls.key"] = []byte{}
	}
	if !toCreate {
		return nil, nil
	}
	labels := labelsForManaged(name)
	if extraLabelsNode, err := yamlNodeFind(&opSplunk, []string{"extraLabels"}); err == nil {
		if extraLabelsNode.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(extraLabelsNode.Content); i += 2 {
				labels[extraLabelsNode.Content[i].Value] = extraLabelsNode.Content[i+1].Value
			}
		}
	}
	return &corev1.Secret{
		Kind:       "Secret",
		APIVersion: "v1",
		Name:       name,
		Namespace:  namespace,
		Labels:     labels,
		Data:       data,
	}, nil
}
