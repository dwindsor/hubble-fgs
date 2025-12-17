// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// Package token provides interfaces and implementations for managing authentication tokens,
// such as Kubernetes service account tokens or JWTs. The main responsibility of this package
// is to manage, validate, persist, and load authentication tokens required for secure
// communication with external systems like on-prem Kubernetes clusters.
package token

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/spf13/viper"

	enterpriseConfig "github.com/isovalent/hubble-fgs/pkg/watcher/conf"
)

const (
	EnvToken = "HYPERSHIELD_TOKEN"
)

type AgentToken struct {
	lock              sync.RWMutex
	k8sAuthToken      string
	k8sAuthPath       string
	k8sNamespace      string
	k8sServiceAccount string
	k8sControllerURL  string
}

var (
	agentTokenInstance *AgentToken
	once               sync.Once
)

// GetAgentToken returns the singleton instance of AgentToken.
func GetAgentToken() *AgentToken {
	once.Do(func() {
		agentTokenInstance = &AgentToken{}
	})
	return agentTokenInstance
}

// K8sAuthToken returns the Kubernetes authentication token associated with the AgentToken.
// It acquires a read lock to ensure thread-safe access to the token.
func (a *AgentToken) K8sAuthToken() string {
	a.lock.RLock()
	defer a.lock.RUnlock()
	return a.k8sAuthToken
}

// SetK8sAuthToken sets the Kubernetes authentication token for the AgentToken instance.
// It also updates the namespace and service account based on the provided token.
// It acquires a lock to ensure thread-safe access when updating the token.
//
// Parameters:
//   - token: The Kubernetes authentication token to be set.
func (a *AgentToken) SetK8sAuthToken(token string) {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.k8sAuthToken = token
	a.setNamespaceAndServiceAccount(token)
	a.SetK8sControllerURL(token)
}

// K8sAuthPath returns the Kubernetes authentication path associated with the AgentToken.
// It acquires a read lock to ensure thread-safe access to the k8sAuthPath field.
func (a *AgentToken) K8sAuthPath() string {
	a.lock.RLock()
	defer a.lock.RUnlock()
	return a.k8sAuthPath
}

// SetK8sAuthPath sets the Kubernetes authentication file path for the AgentToken.
// It acquires a lock to ensure thread-safe access when updating the k8sAuthPath field.
//
// Parameters:
//   - path: The new Kubernetes authentication file path to be set.
func (a *AgentToken) SetK8sAuthPath(path string) {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.k8sAuthPath = path
}

// SetNamespaceAndServiceAccount extracts and sets the namespace and service account from the token.
func (a *AgentToken) setNamespaceAndServiceAccount(tokenString string) {
	namespace, serviceAccount := a.extractNamespaceAndServiceAccount(tokenString)
	a.k8sNamespace = namespace
	a.k8sServiceAccount = serviceAccount
}

// K8sNamespace returns the Kubernetes namespace associated with the AgentToken.
func (a *AgentToken) K8sNamespace() string {
	a.lock.RLock()
	defer a.lock.RUnlock()
	return a.k8sNamespace
}

// K8sServiceAccount returns the Kubernetes service account associated with the AgentToken.
func (a *AgentToken) K8sServiceAccount() string {
	a.lock.RLock()
	defer a.lock.RUnlock()
	return a.k8sServiceAccount
}

// Persist saves the Kubernetes authentication token to a file in JSON format.
// The file is created or overwritten at the path returned by K8sAuthPath(), and contains
// the token under the "k8s_auth" key. After writing, the file permissions are set to 0600
// (read and write for the owner only) to ensure the token's security. Returns an error if
// writing the file or setting permissions fails.
func (a *AgentToken) Persist() error {
	at := a.K8sAuthToken()
	path := a.K8sAuthPath()

	if path == "" {
		return fmt.Errorf("k8s auth path is not set")
	}

	// Writing tokens to file
	v := viper.New()
	v.SetConfigType("json")
	v.Set("k8s_auth", at)

	// If the file exists, it will be overwritten.
	err := v.WriteConfigAs(path)
	if err != nil {
		logger.GetLogger().Error("failed to write token to file",
			logfields.Error, err, "path", path)
		return fmt.Errorf("failed to write token to file: %w", err)
	}

	// Setting permissions on token file.
	// The file should only be readable and writable by the owner.
	// This is important for security reasons, as the token is sensitive information.
	// 0600 means read and write permissions for the owner, and no permissions for others.
	err = os.Chmod(path, 0600)
	if err != nil {
		return fmt.Errorf("failed to set permissions on token file: %w", err)
	}
	return nil
}

// Delete removes the Kubernetes authentication token file associated with the AgentToken.
// It first checks if the token file path is valid and whether the file exists.
// If the file exists, it truncates its contents, closes the file, and then deletes it from path.
// Returns an error if any operation fails, or nil if the file does not exist or is successfully deleted.
func (a *AgentToken) Delete() error {
	path := a.K8sAuthPath()
	if path == "" {
		logger.GetLogger().Error("token path is empty", "path", path)
		return errors.New("token path is empty")
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		logger.GetLogger().Warn("token file does not exist, nothing to delete", "path", path)
		return nil
	} else if err != nil {
		logger.GetLogger().Error("error stating token file", logfields.Error, err, "path", path)
		return err
	}
	// Truncating the file to remove its contents.
	file, err := os.OpenFile(path, os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		logger.GetLogger().Error("failed to truncate token file",
			logfields.Error, err, "path", path)
		return fmt.Errorf("failed to truncate token file: %w", err)
	}
	// Closing the file before deleting it.
	if cerr := file.Close(); cerr != nil {
		logger.GetLogger().Error("error closing token file", logfields.Error, cerr, "path", path)
		return fmt.Errorf("failed to close token file: %w", cerr)
	}
	err = os.Remove(path)
	if err != nil {
		logger.GetLogger().Error("error removing token file", logfields.Error, err, "path", path)
		return fmt.Errorf("failed to remove token file: %w", err)
	}
	return nil
}

// Load reads the Kubernetes authentication token from the file specified by K8sAuthPath,
// validates it, and sets it in the AgentToken instance. Returns true if the token is loaded
// and valid, false if the file does not exist, or an error if loading or validation fails.
func (a *AgentToken) Load() (bool, error) {
	logger.GetLogger().Debug("loading k8s auth token from file")
	path := a.K8sAuthPath()

	// Check if file exists
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		logger.GetLogger().Error("token file does not exist", "path", path)
		return false, nil
	} else if err != nil {
		logger.GetLogger().Error("error stating token file in load", logfields.Error, err, "path", path)
		return false, err
	}

	// Reading tokens from file.
	logger.GetLogger().Debug("reading token from file ", "path", path)
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("json")
	err = v.ReadInConfig()
	if err != nil {
		logger.GetLogger().Error("error reading token file", logfields.Error, err, "path", path)
		return false, err
	}
	at := v.GetString("k8s_auth")
	if at == "" {
		return false, fmt.Errorf("agent token is empty %s", path)
	}

	// Checking if tokens are valid.
	if err = a.ValidK8sAuth(at); err != nil {
		return false, fmt.Errorf("invalid k8s auth token: %w", err)
	}
	// Setting tokens in AgentToken object.
	a.SetK8sAuthToken(at)
	return true, nil
}

// LoadK8sAuthFromEnv attempts to load the Kubernetes authentication token from the environment variable specified by EnvToken.
// If the token is not found in the environment, it tries to load it from two possible .env files:
// "/opt/cisco/hypershield/etc/.k8s_auth" and "/opt/cisco/daf/etc/.k8s_auth".
// If the token is still not found after these attempts, it returns an error.
// On success, it sets the token in the AgentToken instance.
func (a *AgentToken) LoadK8sAuthFromEnv() error {
	logger.GetLogger().Debug("setting k8s auth token from environment")
	// Checking if the token is set in the environment.
	token := os.Getenv(EnvToken)
	if token == "" {
		// Checking if the token could be stored in an .env file
		fileName := "/opt/cisco/hypershield/etc/.k8s_auth"
		if err := godotenv.Load(fileName); err != nil {
			logger.GetLogger().Info("load k8s_auth", logfields.Error, err, "file", fileName)
		}
		token = os.Getenv(EnvToken)
		if token == "" {
			// Checking alternative path for .env file.
			fileName = "/opt/cisco/daf/etc/.k8s_auth"
			if err := godotenv.Load(fileName); err != nil {
				logger.GetLogger().Info("load k8s_auth", logfields.Error, err, "file", fileName)
			}
			token = os.Getenv(EnvToken)
			if token == "" {
				return errors.New("K8s auth token not found in environment or .k8s_auth files")
			}
		}
		// Checking if token is valid.
		if err := a.ValidK8sAuth(token); err != nil {
			return fmt.Errorf("invalid k8s auth token format in environment: %w", err)
		}
	}

	// Setting token in AgentToken object.
	a.SetK8sAuthToken(token)
	return nil
}

// ValidK8sAuth validates a Kubernetes service account authentication token string.
// It parses the token to extract the API server URL, service account token, and CA certificate.
// Returns an error if parsing fails or if any of the required fields are empty.
func (a *AgentToken) ValidK8sAuth(tknStr string) error {
	logger.GetLogger().Debug("Validating token")
	_, err := enterpriseConfig.ExternalClusterSAConfig(tknStr)
	if err != nil {
		return err
	}
	logger.GetLogger().Debug("Validated token successfully")
	return nil
}

// SetAndPersistK8sAuthToken sets the Kubernetes authentication token in the AgentToken instance
// and persists it to the configured file path.
// Parameters:
//   - token: The Kubernetes authentication token to be set and persisted.
//
// Returns an error if persisting the token fails, otherwise returns nil.
func (a *AgentToken) SetAndPersistK8sAuthToken(token string) error {
	if token == "" {
		return fmt.Errorf("token is empty")
	}
	a.SetK8sAuthToken(token)
	err := a.Persist()
	if err != nil {
		logger.GetLogger().Debug("failed to persist k8s token", logfields.Error, err)
		return err
	}
	return nil
}

// extractNamespaceAndServiceAccount extracts the Kubernetes namespace and service account name
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
func (a *AgentToken) extractNamespaceAndServiceAccount(tokenString string) (string, string) {
	// Validating input.
	if tokenString == "" {
		logger.GetLogger().Debug("token is empty")
		return "", ""
	}

	// Get the service account token from the full token string.
	_, serviceAccountToken, _, err := enterpriseConfig.ParseServiceAccountAuth(tokenString)
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
	if k8sInfo, ok := claims["kubernetes.io"].(map[string]interface{}); ok {
		if ns, ok := k8sInfo["namespace"].(string); ok {
			namespace = ns
		}
		if saInfo, ok := k8sInfo["serviceaccount"].(map[string]interface{}); ok {
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

func (a *AgentToken) K8sControllerURL() string {
	a.lock.RLock()
	defer a.lock.RUnlock()
	return a.k8sControllerURL
}

func (a *AgentToken) SetK8sControllerURL(tokenStr string) {
	apiServer, _, _, err := enterpriseConfig.ParseServiceAccountAuth(tokenStr)
	if err != nil {
		a.k8sControllerURL = ""
		return
	}
	a.k8sControllerURL = apiServer
}

// K8sControllerEndpoint parses a controller endpoint URL and extracts the hostname and port.
// It supports both HTTP and HTTPS URLs with IPv4, IPv6, and DNS hostnames.
// The controller endpoint URL in the format http(s)://<ipv4/6-or-dns>:<port>
//
// Returns:
//   - string: The extracted hostname/IP address
//   - uint32: The extracted port number (0 if no port specified)
//   - error: Any parsing error encountered
//
// The function returns empty values with no error if the input URL is empty.
// If the URL doesn't start with http:// or https://, or if parsing fails,
// an error is returned.
func (a *AgentToken) K8sControllerEndpoint() (string, uint32, error) {
	endpointUrl := a.K8sControllerURL()
	if endpointUrl == "" {
		logger.GetLogger().Info("Controller endpoint is empty")
		return "", 0, fmt.Errorf("controller endpoint URL is empty")
	}

	controllerEndpoint := ""
	controllerPort := uint32(0)

	// parse endpointUrl and split into endpoint and port
	// expected format: http(s)://<ipv4/6-or-dns>:<port>
	if strings.HasPrefix(endpointUrl, "http://") || strings.HasPrefix(endpointUrl, "https://") {
		// Use net/url package for proper URL parsing including IPv6 support
		parsedUrl, err := url.Parse(endpointUrl)
		if err != nil {
			logger.GetLogger().Error("failed to parse controller URL", "endpointUrl", endpointUrl, logfields.Error, err)
			return "", 0, fmt.Errorf("invalid controller URL: %v", err)
		}

		// Extract hostname and port
		host, portStr, err := net.SplitHostPort(parsedUrl.Host)
		if err != nil {
			// No port specified, use hostname as-is
			controllerEndpoint = parsedUrl.Host
			controllerPort = 0 // Default port
		} else {
			controllerEndpoint = host
			port, err := strconv.ParseUint(portStr, 10, 32)
			if err != nil {
				logger.GetLogger().Error("failed to parse controller port", "port", portStr, logfields.Error, err)
				return "", 0, fmt.Errorf("invalid controller port: %v", err)
			}
			controllerPort = uint32(port)
		}
	}
	// If still no controllerEndpoint, return error
	if controllerEndpoint == "" {
		logger.GetLogger().Error("invalid controller endpoint URL", "endpointUrl", endpointUrl)
		return "", 0, fmt.Errorf("invalid controller endpoint URL: %s", endpointUrl)
	}
	return controllerEndpoint, controllerPort, nil
}
