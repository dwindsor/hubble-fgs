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
	"bytes"
	_ "embed"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	// Using gopkg.in/yaml.v3 as it preserves quotes
	"gopkg.in/yaml.v3"

	corev1 "k8s.io/api/core/v1"
)

const (
	exportersKey               = "exporters"
	splunkKey                  = "splunk_hec"
	indexKey                   = "index"
	disableCompressionKey      = "disable_compression"
	timeoutKey                 = "timeout"
	tlsKey                     = "tls"
	tlsCAKey                   = "ca"
	tlsCertKey                 = "crt"
	tlsKeyKey                  = "key"
	tlsSecretKey               = "secret"
	tlsSecretNameKey           = "name"
	tlsSecretKeysKey           = "keys"
	tlsSecretCACertKey         = "ca_cert"
	tlsSecretClientCertKey     = "client_cert"
	tlsSecretClientKeyKey      = "client_key"
	tlsCAFileKey               = "ca_file"
	tlsCertFileKey             = "cert_file"
	tlsKeyFileKey              = "key_file"
	insecureSkipVerifyInputKey = "insecureSkipVerify"
	insecureSkipVerifyKey      = "insecure_skip_verify"
)

// yamlNodeFind returns the value node for the given path in a YAML node tree.
func yamlNodeFind(node *yaml.Node, path []string) (*yaml.Node, error) {
	if node.Kind == yaml.DocumentNode {
		return yamlNodeFind(node.Content[0], path)
	}
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected mapping node, got %v", node.Kind)
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == path[0] {
			if len(path) == 1 {
				return node.Content[i+1], nil
			}
			return yamlNodeFind(node.Content[i+1], path[1:])
		}
	}
	return nil, fmt.Errorf("key %q not found", path[0])
}

var (
	//go:embed manifests/otel-config.yaml
	OtelConfig string
)

// OtelConfigMap creates the ConfigMap with the agent otel configuration.
func OtelConfigMap(log logr.Logger, namespace string, name string, opCM *corev1.ConfigMap) (*corev1.ConfigMap, error) {
	data := ValuesAsMap(log, OtelConfig)

	var exporters yaml.Node
	if err := yaml.Unmarshal([]byte(data[exportersKey]), &exporters); err != nil {
		log.WithValues("value", data[exportersKey]).Error(err, "could not unmarshal the exporters configuration")
		return nil, err
	}
	splunkNode, err := yamlNodeFind(&exporters, []string{splunkKey})
	if err != nil {
		log.Error(err, "could not find splunk_hec in exporters configuration")
		return nil, err
	}
	var opSplunk yaml.Node
	if err := yaml.Unmarshal([]byte(opCM.Data[splunkKey]), &opSplunk); err != nil {
		log.WithValues("value", opCM.Data[splunkKey]).Error(err, "could not unmarshal the splunk_hec configuration")
		return nil, err
	}

	if indexNode, err := yamlNodeFind(&opSplunk, []string{indexKey}); err == nil {
		splunkNode.Content = append(splunkNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: indexKey},
			indexNode,
		)
	}

	disableCompressionNode, err := yamlNodeFind(&opSplunk, []string{disableCompressionKey})
	if err != nil {
		disableCompressionNode = &yaml.Node{Kind: yaml.ScalarNode, Value: ""}
	}
	splunkNode.Content = append(splunkNode.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: disableCompressionKey},
		disableCompressionNode,
	)

	timeoutNode, err := yamlNodeFind(&opSplunk, []string{timeoutKey})
	if err != nil {
		timeoutNode = &yaml.Node{Kind: yaml.ScalarNode, Value: ""}
	}
	splunkNode.Content = append(splunkNode.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: timeoutKey},
		timeoutNode,
	)
	var tlsContent []*yaml.Node
	var tlsCAFileNode *yaml.Node
	_, err = yamlNodeFind(&opSplunk, []string{tlsKey, tlsCAKey})
	if err == nil {
		tlsCAFileNode = &yaml.Node{Kind: yaml.ScalarNode, Value: "/tls/ca.crt"}
	} else {
		tlsCAFileNode, err = yamlNodeFind(&opSplunk, []string{tlsKey, tlsSecretKey, tlsSecretKeysKey, tlsSecretCACertKey})
		if err == nil {
			tlsCAFileNode = &yaml.Node{Kind: yaml.ScalarNode, Value: fmt.Sprintf("/tls/%s", tlsCAFileNode.Value)}
		} else {
			tlsCAFileNode = nil
		}
	}
	if tlsCAFileNode != nil {
		tlsContent = append(tlsContent,
			&yaml.Node{Kind: yaml.ScalarNode, Value: tlsCAFileKey},
			&yaml.Node{Kind: yaml.ScalarNode, Value: tlsCAFileNode.Value},
		)
	}
	var tlsCertFileNode *yaml.Node
	_, err = yamlNodeFind(&opSplunk, []string{tlsKey, tlsCertKey})
	if err == nil {
		tlsCertFileNode = &yaml.Node{Kind: yaml.ScalarNode, Value: "/tls/tls.crt"}
	} else {
		tlsCertFileNode, err = yamlNodeFind(&opSplunk, []string{tlsKey, tlsSecretKey, tlsSecretKeysKey, tlsSecretClientCertKey})
		if err == nil {
			tlsCertFileNode = &yaml.Node{Kind: yaml.ScalarNode, Value: fmt.Sprintf("/tls/%s", tlsCertFileNode.Value)}
		} else {
			tlsCertFileNode = nil
		}
	}
	if tlsCertFileNode != nil {
		tlsContent = append(tlsContent,
			&yaml.Node{Kind: yaml.ScalarNode, Value: tlsCertFileKey},
			&yaml.Node{Kind: yaml.ScalarNode, Value: tlsCertFileNode.Value},
		)
	}
	var tlsKeyFileNode *yaml.Node
	_, err = yamlNodeFind(&opSplunk, []string{tlsKey, tlsKeyKey})
	if err == nil {
		tlsKeyFileNode = &yaml.Node{Kind: yaml.ScalarNode, Value: "/tls/tls.key"}
	} else {
		tlsKeyFileNode, err = yamlNodeFind(&opSplunk, []string{tlsKey, tlsSecretKey, tlsSecretKeysKey, tlsSecretClientKeyKey})
		if err == nil {
			tlsKeyFileNode = &yaml.Node{Kind: yaml.ScalarNode, Value: fmt.Sprintf("/tls/%s", tlsKeyFileNode.Value)}
		} else {
			tlsCAFileNode = nil
		}
	}
	if tlsKeyFileNode != nil {
		tlsContent = append(tlsContent,
			&yaml.Node{Kind: yaml.ScalarNode, Value: tlsKeyFileKey},
			&yaml.Node{Kind: yaml.ScalarNode, Value: tlsKeyFileNode.Value},
		)
	}
	insecureSkipVerifyNode, err := yamlNodeFind(&opSplunk, []string{tlsKey, insecureSkipVerifyInputKey})
	if err != nil {
		insecureSkipVerifyNode = &yaml.Node{Kind: yaml.ScalarNode, Value: ""}
	}
	tlsContent = append(tlsContent,
		&yaml.Node{Kind: yaml.ScalarNode, Value: insecureSkipVerifyKey},
		insecureSkipVerifyNode,
	)
	splunkNode.Content = append(splunkNode.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: tlsKey},
		&yaml.Node{Kind: yaml.MappingNode, Content: tlsContent},
	)
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&exporters); err != nil {
		log.WithValues("value", data[exportersKey]).Error(err, "could not marshal the exporters configuration")
		return nil, err
	}
	data[exportersKey] = buf.String()

	var otelConfig strings.Builder
	for _, section := range []string{exportersKey, "extensions", "processors", "receivers", "service"} {
		otelConfig.WriteString(section)
		otelConfig.WriteString(":\n")
		for line := range strings.SplitSeq(strings.TrimRight(data[section], "\n"), "\n") {
			otelConfig.WriteString("  ")
			otelConfig.WriteString(line)
			otelConfig.WriteString("\n")
		}
	}
	data = map[string]string{"otel-agent-config": otelConfig.String()}

	labels := labelsForManaged(name)
	if extraLabelsNode, err := yamlNodeFind(&opSplunk, []string{"extraLabels"}); err == nil {
		if extraLabelsNode.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(extraLabelsNode.Content); i += 2 {
				labels[extraLabelsNode.Content[i].Value] = extraLabelsNode.Content[i+1].Value
			}
		}
	}

	return &corev1.ConfigMap{
		Kind:       "ConfigMap",
		APIVersion: "v1",
		Name:       name,
		Namespace:  namespace,
		Labels:     labels,
		Data:       data,
	}, nil
}
