// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package mtls

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/manager"

	"github.com/isovalent/hubble-fgs/pkg/shutdown"
)

// Certificate approval timeout constants
const (
	DefaultCertificateApprovalTimeout = 5 * time.Minute  // Default timeout for certificate approval
	RenewalCertificateApprovalTimeout = 10 * time.Minute // Longer timeout for renewal certificate approval
)

// Package-level singleton variables
var (
	certificateManagerInstance *CertificateManager
	certificateManagerOnce     sync.Once
	certificateManagerMutex    sync.RWMutex
)

// CertificateManager handles mTLS certificate lifecycle for external clients
type CertificateManager struct {
	controllerMgr     *manager.ControllerManager
	clientPrivateKey  *rsa.PrivateKey
	clientCertificate *x509.Certificate
	caCert            *x509.Certificate
	clientConfig      *ClientConfig
	// Renewal monitoring
	renewalStopCh  chan struct{}
	renewalRunning bool
	renewalMutex   sync.Mutex
}

// ClientConfig contains configuration for certificate generation
type ClientConfig struct {
	// Common Name for the certificate (typically hostname or service name)
	CommonName string
	// Organization for the certificate
	Organization []string
	// DNS SANs (Subject Alternative Names)
	DNSNames []string
	// IP SANs
	IPAddresses []net.IP
	// Serial Number for unique identification
	SerialNumber string
	// Key size for RSA key generation
	KeySize int
	// Kubernetes CSR name
	CSRName string
	// Kubernetes namespace for CSR
	Namespace string
	// Signer name for the CSR
	SignerName string
	// Usage for the certificate
	Usages []certificatesv1.KeyUsage
	// CA Secret configuration
	CaNamespace  string // Namespace where the CA Secret is located
	CaSecretName string // Name of the Secret containing the CA certificate
}

// buildSignerName constructs the SignerName with the kind.group/name format required by Kubernetes CSR API
// The complete Signer string format is:
//
//	<plural-kind>.<issuer_group>/<issuer_name>
//
// Examples:
//   - "clusterissuers.cert-manager.io/cluster-root-ca-issuer"
//   - "issuers.cert-manager.io/my-namespace-issuer"
//
// For built-in Kubernetes signers that are not cert-manager issuers:
//   - Set kind = "" and issuer_group = ""
//   - Put full signer string in issuer_name
//   - Example: issuer_name = "kubernetes.io/kube-apiserver-client"
func buildSignerName(kind, group, name string) string {
	// Handle built-in Kubernetes signers (no kind/group, full signer in name)
	if kind == "" && group == "" && name != "" {
		return name
	}
	// Handle cert-manager issuers with kind.group/name format
	if kind != "" && group != "" && name != "" {
		switch kind {
		case "Issuer":
			kind = "issuers"
		case "ClusterIssuer":
			kind = "clusterissuers"
		default:
			logger.GetLogger().Error("Unsupported issuer kind for signer name", "kind", kind)
			return ""
		}
		return fmt.Sprintf("%s.%s/%s", kind, group, name)
	}
	return ""
}

// setClientConfig returns a default configuration for AGW client certificates
func setClientConfig(serialNumber, namespace, serviceIP, caSecretName, caNamespace, caIssuer string) *ClientConfig {
	// Caller has ensured the required parameters are provided, but we add extra checks here for safety
	if serialNumber == "" {
		logger.GetLogger().Error("Serial number not provided for mTLS client certificate")
		return nil
	}
	if namespace == "" {
		logger.GetLogger().Error("Namespace not provided for mTLS client certificate")
		return nil
	}
	if serviceIP == "" {
		logger.GetLogger().Error("Service IP not provided for mTLS client certificate")
		return nil
	}

	// Parse service IP address
	var ipAddresses []net.IP
	if ip := net.ParseIP(serviceIP); ip != nil {
		ipAddresses = append(ipAddresses, ip)
	} else {
		logger.GetLogger().Warn("invalid service IP address provided", "serviceIP", serviceIP)
	}

	return &ClientConfig{
		CommonName:   serialNumber,
		Organization: []string{"cisco", "hypershield"},
		// DNSNames:         []string{hostname},
		IPAddresses:  ipAddresses,
		SerialNumber: serialNumber,
		KeySize:      2048,
		CSRName:      fmt.Sprintf("agw-client-%s", serialNumber),
		Namespace:    namespace,
		SignerName:   caIssuer,
		Usages: []certificatesv1.KeyUsage{
			certificatesv1.UsageDigitalSignature,
			certificatesv1.UsageKeyEncipherment,
			certificatesv1.UsageClientAuth,
		},
		CaNamespace:  caNamespace,
		CaSecretName: caSecretName,
	}
}

// NewClientConfig creates a client configuration
func NewClientConfig(serialNumber, namespace, serviceIP, caSecretName, caSecretNamespace, mtlsIssuerName, mtlsIssuerGroup, mtlsIssuerKind string) *ClientConfig {
	signerName := buildSignerName(mtlsIssuerKind, mtlsIssuerGroup, mtlsIssuerName)
	if signerName == "" {
		logger.GetLogger().Error("failed to build signer name for mTLS client configuration")
		return nil
	}

	config := setClientConfig(serialNumber, namespace, serviceIP, caSecretName, caSecretNamespace, signerName)
	if config == nil {
		return nil
	}
	return config
}

// getKubeClient returns the Kubernetes client from the ControllerManager
func (cm *CertificateManager) getKubeClient() kubernetes.Interface {
	if cm.controllerMgr == nil || cm.controllerMgr.Manager == nil {
		logger.GetLogger().Error("ControllerManager or its Manager is nil in CertificateManager")
		return nil
	}

	// Get the rest config from the controller-runtime manager
	config := cm.controllerMgr.Manager.GetConfig()
	if config == nil {
		logger.GetLogger().Error("failed to get rest config from ControllerManager")
		return nil
	}

	// Create a Kubernetes clientset from the config
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		logger.GetLogger().Error("failed to create Kubernetes clientset from config", "error", err)
		return nil
	}

	return kubeClient
}

// GetCertificateManagerInstance returns the singleton instance of CertificateManager
// If no instance exists, it creates one with the provided parameters
func GetCertificateManagerInstance(controller *manager.ControllerManager, config *ClientConfig) *CertificateManager {
	certificateManagerOnce.Do(func() {
		certificateManagerInstance = &CertificateManager{
			controllerMgr: controller,
			clientConfig:  config,
		}
		logger.GetLogger().Debug("created singleton CertificateManager instance")
	})
	return certificateManagerInstance
}

// GetExistingCertificateManager returns the existing singleton instance if it exists
// Returns nil if no instance has been created yet
func GetExistingCertificateManager() *CertificateManager {
	certificateManagerMutex.RLock()
	defer certificateManagerMutex.RUnlock()
	return certificateManagerInstance
}

// UpdateCertificateManagerConfig updates the configuration of the singleton instance
// This is thread-safe and will update the existing instance if it exists
func UpdateCertificateManagerConfig(controller *manager.ControllerManager, config *ClientConfig) {
	certificateManagerMutex.Lock()
	defer certificateManagerMutex.Unlock()

	if certificateManagerInstance != nil {
		certificateManagerInstance.controllerMgr = controller
		certificateManagerInstance.clientConfig = config
		logger.GetLogger().Debug("updated singleton CertificateManager configuration")
	}
}

// GenerateKeyPair generates a new RSA private key
func (cm *CertificateManager) GenerateKeyPair() error {
	logger.GetLogger().Info("generating RSA private key", "keySize", cm.clientConfig.KeySize)

	privateKey, err := rsa.GenerateKey(rand.Reader, cm.clientConfig.KeySize)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	cm.clientPrivateKey = privateKey
	logger.GetLogger().Debug("successfully generated private key")
	return nil
}

// CreateCSR creates a Certificate Signing Request
func (cm *CertificateManager) CreateCSR() ([]byte, error) {
	if cm.clientPrivateKey == nil {
		return nil, fmt.Errorf("private key not generated")
	}

	logger.GetLogger().Info("creating mTLS Certificate Signing Request", "commonName", cm.clientConfig.CommonName)

	logger.GetLogger().Debug("CSR configuration",
		"signerName", cm.clientConfig.SignerName,
		"csrName", cm.clientConfig.CSRName,
		"namespace", cm.clientConfig.Namespace)

	// Create certificate request template
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         cm.clientConfig.CommonName,
			Organization:       cm.clientConfig.Organization,
			OrganizationalUnit: []string{cm.clientConfig.Namespace}, // Add namespace as OU
		},
		// DNSNames:    cm.clientConfig.DNSNames,
		IPAddresses: cm.clientConfig.IPAddresses,
	}

	// Generate CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, cm.clientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	// Encode CSR to PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	logger.GetLogger().Debug("created CSR", "csrLength", len(csrPEM))
	return csrPEM, nil
}

// SubmitCSRToKubernetes submits the CSR to Kubernetes API server
func (cm *CertificateManager) SubmitCSRToKubernetes(ctx context.Context, csrPEM []byte) error {
	logger.GetLogger().Info("submitting CSR to Kubernetes", "csrName", cm.clientConfig.CSRName)

	// Get Kubernetes client and validate it's available
	kubeClient := cm.getKubeClient()
	if kubeClient == nil {
		return fmt.Errorf("kubernetes client not available")
	}

	// Create CertificateSigningRequest object
	csr := &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: cm.clientConfig.CSRName,
			Labels: map[string]string{
				"app":        "agw-client",
				"component":  "mtls",
				"managed-by": "hypershield",
				"namespace":  cm.clientConfig.Namespace,
			},
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request:    csrPEM,
			SignerName: cm.clientConfig.SignerName,
			Usages:     cm.clientConfig.Usages,
		},
	}

	logger.GetLogger().Debug("created CSR object", "signerName", cm.clientConfig.SignerName, "usages", cm.clientConfig.Usages)

	// Add timeout to prevent hanging
	submitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Submit CSR with timeout
	logger.GetLogger().Debug("calling Kubernetes API to create CSR...")
	result, err := kubeClient.CertificatesV1().CertificateSigningRequests().Create(submitCtx, csr, metav1.CreateOptions{})
	if err != nil {
		// Check if CSR already exists
		if kerrors.IsAlreadyExists(err) {
			logger.GetLogger().Info("CSR already exists, checking existing CSR status", "csrName", cm.clientConfig.CSRName)

			// Get the existing CSR to check its status
			existingCSR, getErr := kubeClient.CertificatesV1().CertificateSigningRequests().Get(submitCtx, cm.clientConfig.CSRName, metav1.GetOptions{})
			if getErr != nil {
				return fmt.Errorf("failed to create CSR: %w", err)
			}

			// Check if the existing CSR is already approved and issued
			if len(existingCSR.Status.Certificate) > 0 {
				// The existing certificate was generated with a different private key
				// We need to delete it and create a new one with our current private key
				logger.GetLogger().Info("existing CSR has different private key, deleting and recreating")

				deleteErr := kubeClient.CertificatesV1().CertificateSigningRequests().Delete(submitCtx, cm.clientConfig.CSRName, metav1.DeleteOptions{})
				if deleteErr != nil {
					return fmt.Errorf("failed to delete existing CSR: %w", deleteErr)
				}

				// Retry creating the CSR
				result, retryErr := kubeClient.CertificatesV1().CertificateSigningRequests().Create(submitCtx, csr, metav1.CreateOptions{})
				if retryErr != nil {
					return fmt.Errorf("failed to create CSR after deletion: %w", retryErr)
				}

				logger.GetLogger().Info("successfully recreated CSR to Kubernetes", "csrName", result.Name, "uid", result.UID)
				return nil
			}

			// For denied CSRs or other conflicts, return error to trigger retry at higher level
			for _, condition := range existingCSR.Status.Conditions {
				if condition.Type == certificatesv1.CertificateDenied {
					logger.GetLogger().Warn("existing CSR was denied", "reason", condition.Message)
					return fmt.Errorf("existing CSR was denied: %s", condition.Message)
				}
			}

			// CSR exists but not yet processed - we can continue with it
			logger.GetLogger().Info("existing CSR is pending, will wait for approval")
			return nil
		}

		return fmt.Errorf("failed to create CSR: %w", err)
	}

	logger.GetLogger().Info("successfully submitted CSR to Kubernetes", "csrName", result.Name, "uid", result.UID)
	return nil
}

// WaitForCertificateApproval waits for the CSR to be approved and signed
func (cm *CertificateManager) WaitForCertificateApproval(ctx context.Context, timeout time.Duration) error {
	logger.GetLogger().Info("waiting for certificate approval", "timeout", timeout)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for mTLS certificate approval: %w", ctx.Err())
		case <-ticker.C:
			// Get Kubernetes client and validate it's available
			kubeClient := cm.getKubeClient()
			if kubeClient == nil {
				logger.GetLogger().Warn("Kubernetes client not available, retrying...")
				continue
			}

			csr, err := kubeClient.CertificatesV1().CertificateSigningRequests().Get(ctx, cm.clientConfig.CSRName, metav1.GetOptions{})
			if err != nil {
				logger.GetLogger().Warn("failed to get mTLS CSR status", "error", err)
				continue
			}

			// Check if CSR is approved and certificate is available
			if len(csr.Status.Certificate) > 0 {
				logger.GetLogger().Info("mTLS certificate approved and signed")
				return cm.processCertificate(csr.Status.Certificate)
			}

			// Check for denial
			for _, condition := range csr.Status.Conditions {
				if condition.Type == certificatesv1.CertificateDenied {
					return fmt.Errorf("mTLS certificate request denied: %s", condition.Message)
				}
			}

			logger.GetLogger().Debug("mTLS certificate not yet approved, waiting...")
		}
	}
}

// processCertificate processes the signed certificate from Kubernetes
func (cm *CertificateManager) processCertificate(certPEM []byte) error {
	// Decode PEM certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode mTLS certificate PEM")
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse mTLS certificate: %w", err)
	}

	cm.clientCertificate = cert
	logger.GetLogger().Info("successfully processed signed mTLS certificate",
		"subject", cert.Subject.String(),
		"notAfter", cert.NotAfter,
		"serialNumber", cert.SerialNumber.String())

	return nil
}

// FetchCACertificateFromSecret fetches the CA certificate from a Kubernetes Secret using internal kubeClient
func (cm *CertificateManager) FetchCACertificateFromSecret(ctx context.Context) error {
	kubeClient := cm.getKubeClient()
	if kubeClient == nil {
		return fmt.Errorf("kubernetes client not available")
	}
	return cm.fetchCACertificateFromSecret(ctx, kubeClient)
}

// fetchCACertificateFromSecret is a private helper that uses the provided kubeClient
func (cm *CertificateManager) fetchCACertificateFromSecret(ctx context.Context, kubeClient kubernetes.Interface) error {
	logger.GetLogger().Info("fetching mTLS CA certificate from Secret",
		"namespace", cm.clientConfig.CaNamespace,
		"secretName", cm.clientConfig.CaSecretName)

	// Get the Timescape CA certificate from the Timescape CA k8s secret
	timescapeCaSecret, err := kubeClient.CoreV1().Secrets(cm.clientConfig.CaNamespace).Get(ctx, cm.clientConfig.CaSecretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get Timescape CA k8s secret %v/%v: %w", cm.clientConfig.CaNamespace, cm.clientConfig.CaSecretName, err)
	}

	timescapeCaCert, ok := timescapeCaSecret.Data["ca.crt"]
	if !ok {
		return fmt.Errorf("timescape CA k8s secret %v/%v does not have \"ca.crt\"", cm.clientConfig.CaNamespace, cm.clientConfig.CaSecretName)
	}

	return cm.LoadCACertificate(timescapeCaCert)
}

// LoadCACertificate loads the CA certificate for server verification
func (cm *CertificateManager) LoadCACertificate(caCertPEM []byte) error {
	logger.GetLogger().Info("loading mTLS CA certificate for server verification")

	// Decode PEM certificate
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return fmt.Errorf("failed to decode mTLS CA certificate PEM")
	}

	// Parse certificate
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse mTLS CA certificate: %w", err)
	}

	cm.caCert = caCert
	logger.GetLogger().Info("successfully loaded mTLS CA certificate",
		"subject", caCert.Subject.String(),
		"notAfter", caCert.NotAfter)

	return nil
}

// persistCertificates saves the client certificate, private key, and CA certificate to persistent storage
// using the MTLSCertificates singleton for file-based persistence
func (cm *CertificateManager) persistCertificates() error {
	if cm.clientPrivateKey == nil || cm.clientCertificate == nil {
		return fmt.Errorf("mTLS certificates not available for persistence")
	}

	// Get the MTLS persistence singleton
	mtlsCerts := GetMTLSCertificates()
	if mtlsCerts == nil {
		return fmt.Errorf("mTLS certificates persistence not available")
	}

	// Convert private key to PEM format
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(cm.clientPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal mTLS private key: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Convert client certificate to PEM format
	clientCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cm.clientCertificate.Raw,
	})

	// Convert CA certificate to PEM format (if available)
	var caCertPEM []byte
	if cm.caCert != nil {
		caCertPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cm.caCert.Raw,
		})
	} else {
		logger.GetLogger().Warn("mTLS CA certificate not available, persisting without CA cert")
		// Use empty PEM for CA cert if not available
		caCertPEM = []byte("")
	}

	// Validate the certificate-key pair before persistence
	logger.GetLogger().Debug("validating certificate-key pair before persistence")
	_, err = tls.X509KeyPair(clientCertPEM, privateKeyPEM)
	if err != nil {
		// Log additional debug information
		logger.GetLogger().Error("certificate-key pair validation failed",
			"error", err,
			"certPEMLength", len(clientCertPEM),
			"keyPEMLength", len(privateKeyPEM),
			"certSubject", cm.clientCertificate.Subject.String(),
			"certNotAfter", cm.clientCertificate.NotAfter)
		return fmt.Errorf("invalid mTLS certificate-key pair for persistence: %w", err)
	}
	logger.GetLogger().Info("certificate-key pair validation successful")

	// Persist all certificates
	err = mtlsCerts.SetAndPersistCertificates(
		string(clientCertPEM),
		string(privateKeyPEM),
		string(caCertPEM),
	)
	if err != nil {
		return fmt.Errorf("failed to persist mTLS certificates: %w", err)
	}

	return nil
}

// GetTLSConfig returns a TLS configuration for mTLS client authentication
func (cm *CertificateManager) GetTLSConfig() (*tls.Config, error) {
	if cm.clientPrivateKey == nil {
		return nil, fmt.Errorf("mTLS private key not available")
	}
	if cm.clientCertificate == nil {
		return nil, fmt.Errorf("mTLS certificate not available")
	}

	// Create mTLS certificate from private key and certificate
	tlsCert := tls.Certificate{
		Certificate: [][]byte{cm.clientCertificate.Raw},
		PrivateKey:  cm.clientPrivateKey,
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	// Add CA certificate for server verification if available
	if cm.caCert != nil {
		certPool := x509.NewCertPool()
		certPool.AddCert(cm.caCert)
		tlsConfig.RootCAs = certPool
	}

	logger.GetLogger().Debug("created mTLS config for authentication")
	return tlsConfig, nil
}

// CompleteCertificateFlow performs the complete certificate generation and approval flow
func (cm *CertificateManager) CompleteCertificateFlow(ctx context.Context) error {
	return cm.completeCertificateFlowWithRetry(ctx, false, 3) // Allow up to 3 attempts for CSR creation
}

// completeCertificateFlowWithRetry performs the complete certificate flow with retry logic for CSR conflicts
func (cm *CertificateManager) completeCertificateFlowWithRetry(ctx context.Context, isRenewal bool, maxAttempts int) error {
	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		logger.GetLogger().Debug("mTLS certificate flow attempt", "attempt", attempt, "maxAttempts", maxAttempts)

		err := cm.completeCertificateFlow(ctx, isRenewal)
		if err == nil {
			if attempt > 1 {
				logger.GetLogger().Info("mTLS certificate flow succeeded after retry", "attempt", attempt)
			}
			return nil // Success
		}

		lastErr = err

		// Check if this is a retryable error (CSR conflicts, denials)
		if kerrors.IsAlreadyExists(err) || strings.Contains(err.Error(), "denied") {
			logger.GetLogger().Warn("mTLS certificate flow failed with retryable error",
				"error", err, "attempt", attempt, "maxAttempts", maxAttempts)

			if attempt < maxAttempts {
				// Clean up existing CSR before retry to avoid conflicts
				if cleanupErr := cm.cleanupOldCSR(ctx); cleanupErr != nil {
					logger.GetLogger().Error("failed to cleanup existing mTLS CSR during retry", "error", cleanupErr)
				} else {
					logger.GetLogger().Info("cleaned up existing mTLS CSR for retry", "csrName", cm.clientConfig.CSRName)
				}

				// Wait a short time before retry to avoid rapid recreation conflicts
				select {
				case <-ctx.Done():
					return fmt.Errorf("mTLS context cancelled during retry: %w", ctx.Err())
				case <-time.After(time.Duration(attempt) * 2 * time.Second): // Exponential backoff
					continue
				}
			}
		} else {
			// Non-retryable error, fail immediately
			logger.GetLogger().Error("mTLS certificate flow failed with non-retryable error", "error", err)
			return err
		}
	}

	return fmt.Errorf("mTLS certificate flow failed after %d attempts: %w", maxAttempts, lastErr)
}

// completeCertificateFlow performs the complete certificate generation and approval flow
// The isRenewal parameter controls timeout and CSR naming behavior
func (cm *CertificateManager) completeCertificateFlow(ctx context.Context, isRenewal bool) error {
	if isRenewal {
		logger.GetLogger().Info("starting mTLS certificate renewal flow")
	} else {
		logger.GetLogger().Info("starting complete mTLS certificate flow")
	}

	// Step 1: Generate key pair (only if not already generated)
	if cm.clientPrivateKey == nil {
		if err := cm.GenerateKeyPair(); err != nil {
			return fmt.Errorf("mTLS key generation failed: %w", err)
		}
	} else {
		logger.GetLogger().Debug("using existing mTLS private key for certificate flow")
	}

	// Step 2: Create CSR
	csrPEM, err := cm.CreateCSR()
	if err != nil {
		return fmt.Errorf("mTLS CSR creation failed: %w", err)
	}

	// Step 3: Submit CSR to Kubernetes
	if err := cm.SubmitCSRToKubernetes(ctx, csrPEM); err != nil {
		return fmt.Errorf("mTLS CSR submission failed: %w", err)
	}

	// Step 4: Wait for approval (longer timeout for renewal)
	timeout := DefaultCertificateApprovalTimeout
	if isRenewal {
		timeout = RenewalCertificateApprovalTimeout
	}

	if err := cm.WaitForCertificateApproval(ctx, timeout); err != nil {
		return fmt.Errorf("mTLS certificate approval failed: %w", err)
	}

	// Step 5: Fetch CA certificate from Secret
	if err := cm.FetchCACertificateFromSecret(ctx); err != nil {
		logger.GetLogger().Warn("failed to fetch mTLS CA certificate from Secret", "error", err)
		// Continue without CA cert - mTLS will work but server verification may be limited
	}

	// Step 6: Persist the obtained certificates
	if err := cm.persistCertificates(); err != nil {
		logger.GetLogger().Error("failed to persist mTLS certificates", "error", err)
		// Don't fail the flow - certificates are still in memory and functional
	}

	// Persist the obtained certificate, private key an CA cert
	if isRenewal {
		logger.GetLogger().Info("mTLS certificate renewal flow successful")
	} else {
		logger.GetLogger().Info("Complete mTLS certificate flow successful")
		// Start renewal monitoring after successful certificate acquisition (only for initial flow)
		cm.startRenewalMonitoring(ctx)
	}

	return nil
}

// IsValid checks if the current certificate is still valid
func (cm *CertificateManager) IsValid() bool {
	if cm.clientCertificate == nil {
		return false
	}

	now := time.Now()
	return now.After(cm.clientCertificate.NotBefore) && now.Before(cm.clientCertificate.NotAfter)
}

// needsAutoRenewal checks if the certificate needs automatic renewal
func (cm *CertificateManager) needsAutoRenewal() bool {
	if cm.clientCertificate == nil {
		return true
	}

	autoRenewalThreshold := 3 * 24 * time.Hour // 3 days
	return time.Until(cm.clientCertificate.NotAfter) < autoRenewalThreshold
}

// startRenewalMonitoring starts the background certificate renewal monitoring
// It checks daily if the certificate needs renewal (within 3 days of expiry)
func (cm *CertificateManager) startRenewalMonitoring(ctx context.Context) {
	cm.renewalMutex.Lock()
	defer cm.renewalMutex.Unlock()

	if cm.renewalRunning {
		logger.GetLogger().Debug("mTLS certificate renewal monitoring already running")
		return
	}

	cm.renewalStopCh = make(chan struct{})
	cm.renewalRunning = true

	go cm.renewalMonitorLoop(ctx)
	logger.GetLogger().Info("started mTLS certificate renewal monitoring")
}

// stopRenewalMonitoring stops the background mTLS certificate renewal monitoring
func (cm *CertificateManager) stopRenewalMonitoring() {
	cm.renewalMutex.Lock()
	defer cm.renewalMutex.Unlock()

	if !cm.renewalRunning {
		return
	}

	close(cm.renewalStopCh)
	cm.renewalRunning = false
	logger.GetLogger().Info("stopped mTLS certificate renewal monitoring")
}

// renewalMonitorLoop runs the renewal monitoring in a background goroutine
func (cm *CertificateManager) renewalMonitorLoop(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour) // Check daily
	defer ticker.Stop()

	// Ensure cleanup on exit
	defer func() {
		logger.GetLogger().Debug("renewalMonitorLoop exiting, performing cleanup")
		cm.stopRenewalMonitoring()
	}()

	for {
		select {
		case <-ctx.Done():
			logger.GetLogger().Debug("mTLS certificate renewal monitoring stopped due to context cancellation")
			return
		case <-cm.renewalStopCh:
			logger.GetLogger().Debug("mTLS certificate renewal monitoring stopped")
			return
		case <-ticker.C:
			cm.checkAndRenewCertificate(ctx)
		}
	}
}

// checkAndRenewCertificate checks if renewal is needed and initiates renewal process
func (cm *CertificateManager) checkAndRenewCertificate(ctx context.Context) {
	if !cm.needsAutoRenewal() {
		return
	}

	logger.GetLogger().Info("mTLS certificate needs renewal, initiating renewal process",
		"currentExpiry", cm.clientCertificate.NotAfter,
		"daysUntilExpiry", time.Until(cm.clientCertificate.NotAfter).Hours()/24)

	// Clean up old CSR if it exists
	if err := cm.cleanupOldCSR(ctx); err != nil {
		logger.GetLogger().Warn("failed to cleanup old CSR, continuing with renewal", "error", err)
	}

	// Perform certificate renewal
	if err := cm.renewCertificate(ctx); err != nil {
		logger.GetLogger().Error("mTLS certificate renewal failed", "error", err)
		// Continue monitoring, will try again next day
		return
	}

	logger.GetLogger().Info("mTLS certificate renewal completed successfully",
		"newExpiry", cm.clientCertificate.NotAfter)

	// Trigger AGW restart after successful renewal
	cm.restartAgwAfterRenewal()
}

// renewCertificate performs the complete certificate renewal process
func (cm *CertificateManager) renewCertificate(ctx context.Context) error {
	// Use the shared certificate flow with retry and renewal-specific behavior
	return cm.completeCertificateFlowWithRetry(ctx, true, 3)
}

// cleanupOldCSR removes any existing CSR to avoid conflicts during renewal
func (cm *CertificateManager) cleanupOldCSR(ctx context.Context) error {
	kubeClient := cm.getKubeClient()
	if kubeClient == nil {
		logger.GetLogger().Warn("cannot cleanup old CSR: kubernetes client not available")
		return nil // Don't fail renewal for this
	}

	// Try to delete the old CSR (ignore if it doesn't exist)
	err := kubeClient.CertificatesV1().CertificateSigningRequests().Delete(ctx, cm.clientConfig.CSRName, metav1.DeleteOptions{})
	if err != nil {
		// Log but don't fail - CSR might not exist
		logger.GetLogger().Debug("could not delete old CSR (may not exist)", "csrName", cm.clientConfig.CSRName, "error", err)
	}

	return nil
}

// restartAgwAfterRenewal triggers an AGW restart after successful mTLS certificate renewal
func (cm *CertificateManager) restartAgwAfterRenewal() error {
	logger.GetLogger().Info("restartAgwAfterRenewal: AGW restart after mTLS certificate renewal")

	// Use the shutdown manager to trigger a restart with exit code 200
	// This will cause the init script to restart the AGW process
	shutdown.TriggerShutdown(shutdown.RestartExitCode)
	return nil
}
