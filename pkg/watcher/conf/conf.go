// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !nok8s

package conf

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/golang-jwt/jwt/v5"
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
		cfg, err := ExternalClusterSAConfig(enterpriseOption.Config.K8sServiceAccountAuth)
		return cfg, false, err
	}
	cfg, err := rest.InClusterConfig()
	return cfg, true, err
}

func ExternalClusterSAConfig(details string) (*rest.Config, error) {
	host, token, ca, err := ParseServiceAccountAuth(details)
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
	if _, err := certutil.NewPoolFromBytes([]byte(ca)); err != nil {
		return nil, fmt.Errorf("CA certificate parsing failure")
	}
	tlsClientConfig.CAData = []byte(ca)

	return &rest.Config{
		Host:            host,
		TLSClientConfig: tlsClientConfig,
		BearerToken:     token,
	}, nil
}

func ParseServiceAccountAuth(details string) (string, string, string, error) {
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

// K8sConfigRetry returns the number of retry attempts for establishing a connection
// to the Kubernetes control plane. A return value of -1 indicates that retries
// should continue indefinitely until a successful connection is made.
func K8sConfigRetry() int {
	return -1
}

// ExtractNamespaceAndServiceAccount extracts the Kubernetes namespace and service account name
// from a given JWT token string.
//
// Parameters:
//
//	tokenString - the JWT token string to extract claims from.
//
// Returns:
//
//	namespace      - the extracted Kubernetes namespace, or an empty string if not found.
//	serviceAccount - the extracted service account name, or an empty string if not found.
func ExtractNamespaceAndServiceAccount(tokenString string) (string, string) {
	// Validating input.
	if tokenString == "" {
		logger.GetLogger().Debug("token is empty")
		return "", ""
	}

	// Get the service account token from the full token string.
	_, serviceAccountToken, _, err := ParseServiceAccountAuth(tokenString)
	if err != nil || serviceAccountToken == "" {
		logger.GetLogger().Error("failed to parse service account auth", logfields.Error, err)
		return "", ""
	}

	// Extracting namespace and service account from the token.
	parser := jwt.Parser{}
	tokenObj, _, err := parser.ParseUnverified(serviceAccountToken, jwt.MapClaims{})
	if err != nil {
		logger.GetLogger().Error("failed to parse token to get namespace and service account")
		return "", ""
	}
	if tokenObj == nil {
		logger.GetLogger().Error("jwt claims not found in token")
		return "", ""
	}
	claims, ok := tokenObj.Claims.(jwt.MapClaims)
	if !ok {
		logger.GetLogger().Error("invalid jwt claims")
		return "", ""
	}

	// The JWT token structure may use nested objects under "kubernetes.io" as per Kubernetes service account token projection,
	// see: https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#service-account-token-volume-projection
	// Extract namespace and service account from the nested structure.
	var namespace, serviceAccount string

	// Try the nested structure first (modern format: claims["kubernetes.io"] is a map with "namespace" and "serviceaccount" keys)
	if k8sInfo, ok := claims["kubernetes.io"].(map[string]any); ok {
		if ns, ok := k8sInfo["namespace"].(string); ok {
			namespace = ns
		}
		if saInfo, ok := k8sInfo["serviceaccount"].(map[string]any); ok {
			if saName, ok := saInfo["name"].(string); ok {
				serviceAccount = saName
			}
		}
	}

	// Fall back to flat structure (legacy format) if needed.
	// Some Kubernetes clusters or custom token issuers may use a flat claim structure
	// instead of the nested "kubernetes.io" object. This legacy format is supported
	// for backward compatibility with older clusters or non-standard token generators.
	if namespace == "" {
		if ns, ok := claims["kubernetes.io/serviceaccount/namespace"].(string); ok {
			namespace = ns
		} else {
			logger.GetLogger().Error("namespace not found in jwt claims")
		}
	}
	if serviceAccount == "" {
		if sa, ok := claims["kubernetes.io/serviceaccount/service-account.name"].(string); ok {
			serviceAccount = sa
		} else {
			logger.GetLogger().Error("service-account name not found in jwt claims")
		}
	}
	return namespace, serviceAccount
}
