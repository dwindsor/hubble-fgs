// Package token provides interfaces and implementations for managing authentication tokens,
// such as Kubernetes service account tokens or JWTs. The main responsibility of this package
// is to manage, validate, persist, and load authentication tokens required for secure
// communication with external systems like on-prem Kubernetes clusters.
package token

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/joho/godotenv"
	"github.com/spf13/viper"

	enterpriseConfig "github.com/isovalent/hubble-fgs/pkg/watcher/conf"
)

const (
	EnvToken = "HYPERSHIELD_TOKEN"
)

type AgentToken struct {
	lock         sync.RWMutex
	k8sAuthToken string
	k8sAuthPath  string
}

// K8sAuthToken returns the Kubernetes authentication token associated with the AgentToken.
// It acquires a read lock to ensure thread-safe access to the token.
func (a *AgentToken) K8sAuthToken() string {
	a.lock.RLock()
	defer a.lock.RUnlock()
	return a.k8sAuthToken
}

// SetK8sAuthToken sets the Kubernetes authentication token for the AgentToken instance.
// It acquires a lock to ensure thread-safe access when updating the token.
//
// Parameters:
//   - token: The Kubernetes authentication token to be set.
func (a *AgentToken) SetK8sAuthToken(token string) {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.k8sAuthToken = token
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

// ValidK8sAuth checks whether the Kubernetes authentication token associated with the AgentToken
// is valid. It logs an error if the token is invalid.
// Returns true if the token is valid, otherwise returns false.
func (a *AgentToken) ValidK8sAuth() bool {
	err := isValidK8sAuth(a.K8sAuthToken())
	if err != nil {
		logger.GetLogger().Error("Invalid k8s auth token", logfields.Error, err)
		return false
	}
	return true
}

// Persist saves the Kubernetes authentication token to a file in JSON format.
// The file is created or overwritten at the path returned by K8sAuthPath(), and contains
// the token under the "k8s_auth" key. After writing, the file permissions are set to 0600
// (read and write for the owner only) to ensure the token's security. Returns an error if
// writing the file or setting permissions fails.
func (a *AgentToken) Persist() error {
	at := a.K8sAuthToken()
	path := a.K8sAuthPath()

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
	if err = isValidK8sAuth(at); err != nil {
		return false, fmt.Errorf("invalid k8s auth token in file: %w", err)
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
			logger.GetLogger().Info("failed to load k8s_auth", logfields.Error, err, "file", fileName)
		}
		token = os.Getenv(EnvToken)
		if token == "" {
			// Checking alternative path for .env file.
			fileName = "/opt/cisco/daf/etc/.k8s_auth"
			if err := godotenv.Load(fileName); err != nil {
				logger.GetLogger().Info("failed to load k8s_auth", logfields.Error, err, "file", fileName)
			}
			token = os.Getenv(EnvToken)
			if token == "" {
				return errors.New("K8s auth token not found in environment or .k8s_auth files")
			}
		}
		// Checking if token is valid.
		if err := isValidK8sAuth(token); err != nil {
			return fmt.Errorf("invalid k8s auth token format in environment: %w", err)
		}
	}

	// Setting token in AgentToken object.
	a.SetK8sAuthToken(token)
	return nil
}

// isValidK8sAuth validates a Kubernetes service account authentication token string.
// It parses the token to extract the API server URL, service account token, and CA certificate.
// Returns an error if parsing fails or if any of the required fields are empty.
func isValidK8sAuth(tknStr string) error {
	logger.GetLogger().Debug("Validating token")
	apiServer, serviceAccountToken, caCert, err := enterpriseConfig.ParseServiceAccountAuth(tknStr)
	if err != nil {
		return err
	}
	if len(apiServer) == 0 {
		return fmt.Errorf("field 'apiServer' cannot be empty")
	}
	if len(serviceAccountToken) == 0 {
		return fmt.Errorf("field 'serviceAccountToken' cannot be empty")
	}
	if len(caCert) == 0 {
		return fmt.Errorf("field 'caCert' cannot be empty")
	}

	return nil
}
