// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package switchevents

import (
	"context"
	"fmt"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/manager"

	"github.com/isovalent/hubble-fgs/pkg/agw"
	"github.com/isovalent/hubble-fgs/pkg/mtls"
	"github.com/isovalent/hubble-fgs/pkg/shutdown"
	"github.com/isovalent/hubble-fgs/pkg/timescape/types"

	v1alpha "github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

// TimescapeConfigMapId is the expected ID for the Timescape ConfigMap
const TimescapeConfigMapId = "timescape-config"

// Package-level variables to store Setup parameters for ConfigMap callbacks
var (
	setupContext           context.Context
	setupAgw               *agw.AgentGateway
	setupEnableNxos        bool
	setupControllerManager *manager.ControllerManager
)

// SetTimescapeSetupParams stores the parameters needed for Setup calls from ConfigMap callbacks
func SetTimescapeSetupParams(ctx context.Context, agwGateway *agw.AgentGateway, enableNxos bool, controllerManager *manager.ControllerManager) {
	setupContext = ctx
	setupAgw = agwGateway
	setupEnableNxos = enableNxos
	setupControllerManager = controllerManager
}

// SubscribeTimescapeConfig handles ConfigMap-based Timescape configuration changes
// This callback is registered with the config repository to handle CONFIG_TYPE_TIMESCAPE changes
func SubscribeTimescapeConfig(oldConfig, newConfig *v1alpha.ConfigObject) error {
	logger.GetLogger().Debug("SubscribeTimescapeConfig callback called",
		"oldConfig", oldConfig != nil,
		"newConfig", newConfig != nil)

	if ok := checkForConfigMapName(oldConfig, newConfig); !ok {
		// Ignore configs that don't match the expected ConfigMap id
		return nil
	}

	// Handle delete operation
	if oldConfig != nil && newConfig == nil {
		logger.GetLogger().Info("Timescape ConfigMap deleted, disabling client")
		shutdown.TriggerShutdown(shutdown.RestartExitCode)
		return nil
	}

	// Handle add/update operations
	if newConfig != nil {
		timescapeConfig := newConfig.GetConfigTimescape()
		if timescapeConfig == nil {
			logger.GetLogger().Error("received non-Timescape config in SubscribeTimescapeConfig")
			return fmt.Errorf("invalid config type for Timescape subscription")
		}

		isNewConfig := oldConfig == nil
		logger.GetLogger().Debug("Processing Timescape Config",
			"id", timescapeConfig.GetId(),
			"host", timescapeConfig.GetHost(),
			"port", timescapeConfig.GetPort(),
			"isNew", isNewConfig)

		// Update request.
		// TODO: Fix restart
		if !isNewConfig {
			logger.GetLogger().Info("Restarting Timescape client from ConfigMap update")
			shutdown.TriggerShutdown(shutdown.RestartExitCode)
			return nil
		}

		// New Config Added
		// Convert protobuf config to our internal TimescapeConfig struct
		internalConfig := convertProtobufToInternalConfig(timescapeConfig, setupContext, setupAgw, setupEnableNxos)

		// Update the configuration
		configManager := GetTimescapeConfigManager()
		configManager.SetTimescapeConfig(internalConfig)

		// Call Setup to start or restart the timescape client
		if setupContext != nil && setupAgw != nil {
			logger.GetLogger().Debug("Starting Timescape client...")
			err := Setup(setupContext, setupAgw, setupEnableNxos, setupControllerManager)
			if err != nil {
				logger.GetLogger().Error("Failed to setup Timescape client from Config", "error", err)
				return fmt.Errorf("timescape client setup failed: %w", err)
			}
		} else {
			logger.GetLogger().Warn("Setup parameters not available, skipping Timescape client start")
		}
	}

	return nil
}

func checkForConfigMapName(oldConfig, newConfig *v1alpha.ConfigObject) bool {
	var config *v1alpha.ConfigObject

	if newConfig != nil {
		config = newConfig
	} else if oldConfig != nil {
		config = oldConfig
	}

	if config != nil {
		// Extract ConfigMap ID from Timescape config
		configTimescape := config.GetConfigTimescape()
		if configTimescape != nil {
			if configMapId := configTimescape.GetId(); configMapId != "" {
				if configMapId != TimescapeConfigMapId {
					logger.GetLogger().Error("Received config with unexpected ID in SubscribeTimescapeConfig",
						"expected", TimescapeConfigMapId,
						"actual", configMapId)
					return false
				}
				return true
			}
			logger.GetLogger().Error("Timescape config missing ID field in SubscribeTimescapeConfig")
		}
	}
	return false
}

// convertProtobufToInternalConfig converts a protobuf TimescapeConfig to our internal TimescapeConfig
// This function handles the complete mTLS configuration flow from ConfigMap to internal structures:
//
// ConfigMap Flow:
// 1. ConfigMap contains protobuf TimescapeConfig with mTLS.enabled = true
// 2. This function extracts mTLS configuration and populates internal TimescapeConfig
// 3. Sets UseMTLS = true and populates CA configuration from defaults
// 4. Runtime values (SerialNumber, Namespace, ServiceIP) are populated later by enhanceMTLSConfig()
// 5. The internal config flows to HTTPTransportConfig in timescape_handler.go
//
// ConfigMap Fields Extracted:
// - mTLS enabled flag from protobuf
// - Only default CA Secret configuration (not runtime-specific values)
//
// Runtime Fields (NOT from ConfigMap):
// - MTLSSerialNumber: Set from AGW context at runtime
// - MTLSNamespace: Set from runtime environment
// - MTLSServiceIP: Set by caller when needed
func convertProtobufToInternalConfig(pbConfig *v1alpha.TimescapeConfig, ctx context.Context, agw *agw.AgentGateway, enableNXOS bool) *TimescapeConfig {
	config := &TimescapeConfig{
		ClientEnabled:        true, // Enable client when ConfigMap is present
		Host:                 pbConfig.GetHost(),
		Port:                 pbConfig.GetPort(),
		Protocol:             pbConfig.GetProtocol(),
		TlsEnabled:           pbConfig.GetTlsEnabled(),
		EndpointApi:          pbConfig.GetEndpointApi(),
		MaxRetries:           pbConfig.GetMaxRetries(),
		ConnectionTimeoutSec: pbConfig.GetConnectionTimeoutSec(),
		RequestTimeoutSec:    pbConfig.GetRequestTimeoutSec(),
		MaxBatchSize:         pbConfig.GetMaxBatchSize(),
		BatchTimeoutMs:       pbConfig.GetBatchTimeoutMs(),
	}

	// Apply production defaults if values are still 0
	if config.MaxRetries <= 0 {
		config.MaxRetries = uint32(types.DefaultMaxRetries)
	}
	if config.ConnectionTimeoutSec <= 0 {
		config.ConnectionTimeoutSec = uint32(types.DefaultHTTPConnectionTimeout.Seconds())
	}
	if config.RequestTimeoutSec <= 0 {
		config.RequestTimeoutSec = uint32(types.DefaultHTTPRequestTimeout.Seconds())
	}
	if config.MaxBatchSize <= 0 {
		config.MaxBatchSize = uint32(types.DefaultMaxBatchSize)
	}
	if config.BatchTimeoutMs <= 0 {
		config.BatchTimeoutMs = uint32(types.DefaultBatchTimeout.Milliseconds())
	}

	// Build endpoint URL from host, port, protocol, and TLS settings
	if config.Host != "" && config.Port != "" {
		protocol := "http"
		if config.TlsEnabled {
			protocol = "https"
		}
		apiPath := config.EndpointApi
		if apiPath == "" {
			apiPath = "/push" // Default API path
		}
		config.Endpoint = fmt.Sprintf("%s://%s:%s%s", protocol, config.Host, config.Port, apiPath)
	}

	// Handle authentication configuration (oneOf pattern)
	if basicAuth := pbConfig.GetBasicAuth(); basicAuth != nil {
		config.UseBasicAuth = true
		config.UseMTLS = false
		config.Username = basicAuth.GetUsername()
		config.Password = basicAuth.GetPassword()
		logger.GetLogger().Debug("timescape: configured BasicAuth authentication",
			"username", config.Username,
			"hasPassword", config.Password != "")
	} else if mtls := pbConfig.GetMtls(); mtls != nil {
		config.UseBasicAuth = false
		config.UseMTLS = mtls.GetEnabled()
		config.Username = "" // mTLS doesn't use username/password
		config.Password = ""

		logger.GetLogger().Info("timescape: configuring mTLS authentication from ConfigMap",
			"mtlsEnabled", mtls.GetEnabled(),
			"useMTLS", config.UseMTLS)

		// Extract Certificate Manager configuration (MTLSCertManager)
		if cm := mtls.GetCertmanager(); cm != nil {
			if issuerRef := cm.GetIssuerRef(); issuerRef != nil {
				config.MTLSIssuerGroup = issuerRef.GetGroup()
				config.MTLSIssuerKind = issuerRef.GetKind()
				config.MTLSIssuerName = issuerRef.GetName()
				logger.GetLogger().Debug("timescape: extracted certificate manager config",
					"issuerGroup", config.MTLSIssuerGroup,
					"issuerKind", config.MTLSIssuerKind,
					"issuerName", config.MTLSIssuerName)
			}
		}

		// Extract Client CA configuration (MTLSClientCA)
		if ca := mtls.GetManagedCa(); ca != nil {
			config.MTLSCASecretName = ca.GetSecretName()
			config.MTLSCASecretNamespace = ca.GetSecretNamespace()
			logger.GetLogger().Debug("timescape: extracted client CA config",
				"caSecretName", config.MTLSCASecretName,
				"caSecretNamespace", config.MTLSCASecretNamespace)
		}

		// Apply enhanced mTLS configuration with runtime values
		if err := setMTLSConfig(ctx, config, setupAgw, setupEnableNxos); err != nil {
			logger.GetLogger().Warn("Failed to set enhanced mTLS configuration", "error", err)
		}

		logger.GetLogger().Info("timescape: configured comprehensive mTLS authentication",
			"enabled", config.UseMTLS,
			"issuerGroup", config.MTLSIssuerGroup,
			"issuerKind", config.MTLSIssuerKind,
			"issuerName", config.MTLSIssuerName,
			"caSecretName", config.MTLSCASecretName,
			"caSecretNamespace", config.MTLSCASecretNamespace)
	} else {
		logger.GetLogger().Warn("timescape: no authentication method configured")
	}

	return config
}

// setMTLSConfig populates comprehensive mTLS configuration fields from proto MTLSConfig
// This function extracts the complete mTLS configuration from the protobuf structure
// and populates all enhanced mTLS fields in the internal TimescapeConfig.
//
// Fields populated from proto MTLSConfig:
// - Certificate Manager configuration (issuer_group, kind, issuer_name)
// - Client CA configuration (ca_secret_name, ca_secret_namespace)
// - mTLS enabled flag
//
// Fields populated from runtime/defaults:
// - Serial number from AGW context
// - Namespace from runtime environment
// - Service IP from AGW or fallback
func setMTLSConfig(ctx context.Context, config *TimescapeConfig, agw *agw.AgentGateway, enableNXOS bool) error {
	if !config.UseMTLS {
		return nil
	}

	if agw == nil {
		logger.GetLogger().Warn("AGW not available, cannot populate mTLS serial number")
		return fmt.Errorf("AGW context not available for mTLS configuration")
	}

	// Populate runtime values from AGW context
	serialNumber := "unknown"
	if ctx != nil && enableNXOS {
		serialNumber = agw.GetSerialNumber(ctx)
	}

	// Service Account Namespace
	saNamespace := ""
	serviceIp := ""
	if agw.Token != nil {
		saNamespace = agw.Token.K8sNamespace()
	} else {
		// TODO
		logger.GetLogger().Warn("AGW token not available, cannot populate Service Account namespace for mTLS configuration")
		saNamespace = "hypershield" // Fallback namespace
	}

	// Fallback for missing service IP (required for mTLS certificate SAN)
	if serviceIp == "" {
		logger.GetLogger().Warn("Service IP not available from AGW, using default for mTLS certificate")
		// Temporary fallback IP for local testing - in production, this should be properly set
		serviceIp = "171.70.188.33" // Fallback IP for certificate SAN
		// return nil
	}

	// Certificate Manager Configuration
	if config.MTLSIssuerGroup == "" || config.MTLSIssuerKind == "" || config.MTLSIssuerName == "" {
		// No certificate manager config from proto
		return fmt.Errorf("mTLS enabled but certificate IssuerName missing from ConfigMap")
	} else {
		logger.GetLogger().Info("timescape: using certificate manager from ConfigMap",
			"issuerGroup", config.MTLSIssuerGroup,
			"issuerKind", config.MTLSIssuerKind,
			"issuerName", config.MTLSIssuerName)
	}

	// Client CA Configuration
	// Use ConfigMap values if available, otherwise apply intelligent defaults
	if config.MTLSCASecretName == "" || config.MTLSCASecretNamespace == "" {
		return fmt.Errorf("mTLS enabled but client CA Secret configuration missing from ConfigMap")
	}
	logger.GetLogger().Info("timescape: using client CA from ConfigMap",
		"caSecretName", config.MTLSCASecretName,
		"caSecretNamespace", config.MTLSCASecretNamespace)

	logger.GetLogger().Info("comprehensive mTLS configuration applied",
		"enabled", config.UseMTLS,
		"serialNumber", serialNumber,
		"namespace", saNamespace,
		"serviceIP", serviceIp,
		"issuerGroup", config.MTLSIssuerGroup,
		"issuerKind", config.MTLSIssuerKind,
		"issuerName", config.MTLSIssuerName,
		"caSecretName", config.MTLSCASecretName,
		"caSecretNamespace", config.MTLSCASecretNamespace)

	// Create mTLS client configuration for certificate manager
	clientConfig := mtls.NewClientConfig(serialNumber, saNamespace,
		serviceIp, config.MTLSCASecretName, config.MTLSCASecretNamespace, config.MTLSIssuerName, config.MTLSIssuerGroup, config.MTLSIssuerKind)
	if clientConfig == nil {
		logger.GetLogger().Error("Failed to create mTLS client configuration")
		return fmt.Errorf("failed to create mTLS client configuration")
	}

	// Create certificate manager
	certManager := mtls.GetCertificateManagerInstance(setupControllerManager, clientConfig)
	if certManager == nil {
		logger.GetLogger().Error("Failed to create mTLS certificate manager")
		return fmt.Errorf("failed to create mTLS certificate manager")
	}

	return certManager.CompleteCertificateFlow(ctx)
}
