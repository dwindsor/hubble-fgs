// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// Package mtls provides interfaces and implementations for managing mTLS certificates,
// private keys, and CA certificates. The main responsibility of this package
// is to manage, validate, persist, and load certificates required for secure
// mTLS communication with external systems.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/spf13/viper"
)

// MTLSCertificates holds the certificate, private key, and CA certificate data
type MTLSCertificates struct {
	lock      sync.RWMutex
	certPEM   string // Client certificate in PEM format
	keyPEM    string // Private key in PEM format
	caCertPEM string // CA certificate in PEM format
	certsPath string // File path for certificate persistence
}

var (
	mtlsCertInstance *MTLSCertificates
	once             sync.Once
)

// GetMTLSCertificates returns the singleton instance of MTLSCertificates.
func GetMTLSCertificates() *MTLSCertificates {
	once.Do(func() {
		mtlsCertInstance = &MTLSCertificates{}
	})
	return mtlsCertInstance
}

// CertPEM returns the client certificate in PEM format.
// It acquires a read lock to ensure thread-safe access to the certificate.
func (m *MTLSCertificates) CertPEM() string {
	m.lock.RLock()
	defer m.lock.RUnlock()
	return m.certPEM
}

// SetCertPEM sets the client certificate in PEM format.
// It acquires a lock to ensure thread-safe access when updating the certificate.
//
// Parameters:
//   - certPEM: The client certificate in PEM format to be set.
func (m *MTLSCertificates) SetCertPEM(certPEM string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.certPEM = certPEM
}

// KeyPEM returns the private key in PEM format.
// It acquires a read lock to ensure thread-safe access to the private key.
func (m *MTLSCertificates) KeyPEM() string {
	m.lock.RLock()
	defer m.lock.RUnlock()
	return m.keyPEM
}

// SetKeyPEM sets the private key in PEM format.
// It acquires a lock to ensure thread-safe access when updating the private key.
//
// Parameters:
//   - keyPEM: The private key in PEM format to be set.
func (m *MTLSCertificates) SetKeyPEM(keyPEM string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.keyPEM = keyPEM
}

// CACertPEM returns the CA certificate in PEM format.
// It acquires a read lock to ensure thread-safe access to the CA certificate.
func (m *MTLSCertificates) CACertPEM() string {
	m.lock.RLock()
	defer m.lock.RUnlock()
	return m.caCertPEM
}

// SetCACertPEM sets the CA certificate in PEM format.
// It acquires a lock to ensure thread-safe access when updating the CA certificate.
//
// Parameters:
//   - caCertPEM: The CA certificate in PEM format to be set.
func (m *MTLSCertificates) SetCACertPEM(caCertPEM string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.caCertPEM = caCertPEM
}

// CertsPath returns the file path for certificate persistence.
// It acquires a read lock to ensure thread-safe access to the certsPath field.
func (m *MTLSCertificates) CertsPath() string {
	m.lock.RLock()
	defer m.lock.RUnlock()
	return m.certsPath
}

// SetCertsPath sets the file path for certificate persistence.
// It acquires a lock to ensure thread-safe access when updating the certsPath field.
//
// Parameters:
//   - path: The new certificate file path to be set.
func (m *MTLSCertificates) SetCertsPath(path string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.certsPath = path
}

// ConfigureCertificatePath configures the certificate storage path from AGW configuration.
// This function should be called from AGW to set up the certificate storage location.
// It validates the path and creates the directory if it doesn't exist.
//
// Parameters:
//   - mtlsPath: The path from AGW configuration (e.g., from dafconfig mtls_path)
//
// Returns an error if path configuration fails.
func (m *MTLSCertificates) ConfigureCertificatePath(mtlsPath string) error {
	if mtlsPath == "" {
		return fmt.Errorf("mTLS path cannot be empty")
	}

	// Create the certificate file path by appending a filename to the directory
	certFilePath := fmt.Sprintf("%s/mtls_certificates.json", mtlsPath)

	// Ensure the directory exists
	if err := os.MkdirAll(mtlsPath, 0700); err != nil {
		logger.GetLogger().Error("failed to create mTLS directory",
			logfields.Error, err,
			"path", mtlsPath)
		return fmt.Errorf("failed to create mTLS directory: %w", err)
	}

	// Set the certificate file path
	m.SetCertsPath(certFilePath)

	logger.GetLogger().Info("MTLS certificate path configured",
		"directory", mtlsPath,
		"certFile", certFilePath)

	return nil
}

// SetCertificates sets all three certificates at once.
// It acquires a lock to ensure thread-safe access when updating all certificates.
//
// Parameters:
//   - certPEM: The client certificate in PEM format.
//   - keyPEM: The private key in PEM format.
//   - caCertPEM: The CA certificate in PEM format.
func (m *MTLSCertificates) SetCertificates(certPEM, keyPEM, caCertPEM string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.certPEM = certPEM
	m.keyPEM = keyPEM
	m.caCertPEM = caCertPEM
}

// Persist saves the mTLS certificates to a file in JSON format.
// The file is created or overwritten at the path returned by CertsPath(), and contains
// the certificates under "client_cert", "private_key", and "ca_cert" keys.
// After writing, the file permissions are set to 0600 (read and write for the owner only)
// to ensure the certificates' security.
// Returns an error if writing the file or setting
// permissions fails.
func (m *MTLSCertificates) Persist() error {
	certPEM := m.CertPEM()
	keyPEM := m.KeyPEM()
	caCertPEM := m.CACertPEM()
	path := m.CertsPath()

	if path == "" {
		return fmt.Errorf("mTLS certificates path is not set")
	}

	if certPEM == "" || keyPEM == "" || caCertPEM == "" {
		return fmt.Errorf("one or more mTLS certificates are empty")
	}

	// Writing certificates to file
	v := viper.New()
	v.SetConfigType("json")
	v.Set("client_cert", certPEM)
	v.Set("private_key", keyPEM)
	v.Set("ca_cert", caCertPEM)

	// If the file exists, it will be overwritten.
	err := v.WriteConfigAs(path)
	if err != nil {
		logger.GetLogger().Error("failed to write certificates to file",
			logfields.Error, err, "path", path)
		return fmt.Errorf("failed to write certificates to file: %w", err)
	}

	// Setting permissions on certificate file.
	// The file should only be readable and writable by the owner.
	// This is important for security reasons, as the certificates are sensitive information.
	// 0600 means read and write permissions for the owner, and no permissions for others.
	err = os.Chmod(path, 0600)
	if err != nil {
		return fmt.Errorf("failed to set permissions on certificate file: %w", err)
	}

	logger.GetLogger().Info("successfully persisted mTLS certificates", "path", path)
	return nil
}

// Delete removes the mTLS certificate file associated with the MTLSCertificates.
// It first checks if the certificate file path is valid and whether the file exists.
// If the file exists, it truncates its contents, closes the file, and then deletes it from path.
// Returns an error if any operation fails, or nil if the file does not exist or is successfully deleted.
func (m *MTLSCertificates) Delete() error {
	path := m.CertsPath()
	if path == "" {
		logger.GetLogger().Error("mTLS certificate path is empty", "path", path)
		return fmt.Errorf("mTLS certificate path is empty")
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		logger.GetLogger().Warn("mTLS certificate file does not exist, nothing to delete", "path", path)
		return nil
	} else if err != nil {
		logger.GetLogger().Error("error stating mTLS certificate file", logfields.Error, err, "path", path)
		return err
	}

	// Truncating the file to remove its contents.
	file, err := os.OpenFile(path, os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to truncate certificate file: %w", err)
	}

	// Closing the file before deleting it.
	if cerr := file.Close(); cerr != nil {
		return fmt.Errorf("failed to close certificate file: %w", cerr)
	}

	err = os.Remove(path)
	if err != nil {
		return fmt.Errorf("failed to remove certificate file: %w", err)
	}

	logger.GetLogger().Debug("successfully deleted certificate file", "path", path)
	return nil
}

// Load reads the mTLS certificates from the file specified by CertsPath,
// validates them, and sets them in the MTLSCertificates instance.
// Returns true if the certificates are loaded and valid, false if the file does not exist,
// or an error if loading or validation fails.
func (m *MTLSCertificates) Load() (bool, error) {
	logger.GetLogger().Debug("loading mTLS certificates from file")
	path := m.CertsPath()

	// Check if file exists
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		logger.GetLogger().Debug("mTLS certificate file does not exist", "path", path)
		return false, nil
	} else if err != nil {
		logger.GetLogger().Error("error stating mTLS certificate file in load", logfields.Error, err, "path", path)
		return false, err
	}

	// Reading certificates from file.
	logger.GetLogger().Debug("reading mTLS certificates from file", "path", path)
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("json")
	err = v.ReadInConfig()
	if err != nil {
		logger.GetLogger().Error("error reading mTLS certificate file", logfields.Error, err, "path", path)
		return false, err
	}

	certPEM := v.GetString("client_cert")
	keyPEM := v.GetString("private_key")
	caCertPEM := v.GetString("ca_cert")

	if certPEM == "" || keyPEM == "" || caCertPEM == "" {
		return false, fmt.Errorf("one or more mTLS certificates are empty in file %s", path)
	}

	// Validate certificates before setting them
	if err = m.ValidateCertificates(certPEM, keyPEM, caCertPEM); err != nil {
		return false, fmt.Errorf("invalid mTLS certificates: %w", err)
	}

	// Setting certificates in MTLSCertificates object.
	m.SetCertificates(certPEM, keyPEM, caCertPEM)
	logger.GetLogger().Debug("successfully loaded and validated mTLS certificates from file")
	return true, nil
}

// ValidateCertificates validates the provided PEM-encoded certificates and private key.
// It checks that the certificates can be parsed and that the private key matches the client certificate.
// Returns an error if validation fails.
func (m *MTLSCertificates) ValidateCertificates(certPEM, keyPEM, caCertPEM string) error {
	logger.GetLogger().Debug("validating mTLS certificates")

	// Validate client certificate
	_, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return fmt.Errorf("invalid mTLS client certificate or key: %w", err)
	}

	// Validate CA certificate
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM([]byte(caCertPEM)) {
		return fmt.Errorf("invalid mTLS CA certificate")
	}

	logger.GetLogger().Debug("validated mTLS certificates successfully")
	return nil
}

// SetAndPersistCertificates sets all mTLS certificates in the MTLSCertificates instance
// and persists them to the configured file path.
//
// Parameters:
//   - certPEM: The client certificate in PEM format.
//   - keyPEM: The private key in PEM format.
//   - caCertPEM: The CA certificate in PEM format.
//
// Returns an error if validation or persisting the certificates fails, otherwise returns nil.
func (m *MTLSCertificates) SetAndPersistCertificates(certPEM, keyPEM, caCertPEM string) error {
	if certPEM == "" || keyPEM == "" || caCertPEM == "" {
		return fmt.Errorf("one or more certificates are empty")
	}

	// Validate certificates before setting them
	if err := m.ValidateCertificates(certPEM, keyPEM, caCertPEM); err != nil {
		return fmt.Errorf("certificate validation failed: %w", err)
	}

	m.SetCertificates(certPEM, keyPEM, caCertPEM)
	err := m.Persist()
	if err != nil {
		logger.GetLogger().Error("failed to persist mTLS certificates", logfields.Error, err)
		return err
	}

	logger.GetLogger().Debug("successfully set and persisted mTLS certificates")
	return nil
}

// GetTLSConfig returns a tls.Config configured with the loaded certificates.
// This can be used for establishing mTLS connections.
// Returns an error if certificates are not loaded or invalid.
func (m *MTLSCertificates) GetTLSConfig() (*tls.Config, error) {
	certPEM := m.CertPEM()
	keyPEM := m.KeyPEM()
	caCertPEM := m.CACertPEM()

	if certPEM == "" || keyPEM == "" || caCertPEM == "" {
		return nil, fmt.Errorf("certificates not loaded")
	}

	// Load client certificate
	clientCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	// Load CA certificate
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM([]byte(caCertPEM)) {
		return nil, fmt.Errorf("failed to load CA certificate")
	}

	// Create TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	return tlsConfig, nil
}

// IsLoaded returns true if all certificates (client cert, private key, and CA cert) are loaded.
func (m *MTLSCertificates) IsLoaded() bool {
	m.lock.RLock()
	defer m.lock.RUnlock()
	return m.certPEM != "" && m.keyPEM != "" && m.caCertPEM != ""
}
