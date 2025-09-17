// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package conf

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/option"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	certutil "k8s.io/client-go/util/cert"

	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
)

const separator = "|"

// K8sConfig returns Kubernetes client configuration. If running in-cluster, the
// second return value is true, otherwise false.
func K8sConfig() (*rest.Config, bool, error) {
	if option.Config.K8sKubeConfigPath != "" {
		cfg, err := clientcmd.BuildConfigFromFlags("", option.Config.K8sKubeConfigPath)
		return cfg, false, err
	}

	if enterpriseOption.Config.K8sServiceAccountAuth != "" {
		cfg, err := externalClusterSAConfig(enterpriseOption.Config.K8sServiceAccountAuth)
		return cfg, false, err
	}

	cfg, err := rest.InClusterConfig()
	return cfg, true, err
}

func externalClusterSAConfig(details string) (*rest.Config, error) {
	host, token, ca, err := parseServiceAccountAuth(details)
	if err != nil {
		return nil, fmt.Errorf("failed to parse service account auth details: %w", err)
	}
	if len(host) == 0 {
		return nil, fmt.Errorf("api server cannot be empty")
	}
	if len(token) == 0 {
		return nil, fmt.Errorf("service account token cannot be empty")
	}

	tlsClientConfig := rest.TLSClientConfig{}
	if _, err := certutil.NewPoolFromBytes([]byte(ca)); err == nil {
		tlsClientConfig.CAData = []byte(ca)
	}

	return &rest.Config{
		Host:            host,
		TLSClientConfig: tlsClientConfig,
		BearerToken:     token,
	}, nil
}

func parseServiceAccountAuth(details string) (string, string, string, error) {
	decode := func(s string) (string, error) {
		data, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}

	temp, err := decode(details)
	if err != nil {
		return "", "", "", err
	}

	parts := strings.Split(temp, separator)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("service account auth details must be in the format <api-server>|<token>|<ca-cert>")
	}

	return parts[0], parts[1], parts[2], nil
}
