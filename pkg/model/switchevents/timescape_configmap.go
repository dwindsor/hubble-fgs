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

	"github.com/isovalent/hubble-fgs/pkg/agw"
	"github.com/isovalent/hubble-fgs/pkg/shutdown"

	v1alpha "github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

// TimescapeConfigMapId is the expected ID for the Timescape ConfigMap
const TimescapeConfigMapId = "timescape-config"

// Package-level variables to store Setup parameters for ConfigMap callbacks
var (
	setupContext    context.Context
	setupAgw        *agw.AgentGateway
	setupEnableNxos bool
)

// SetTimescapeSetupParams stores the parameters needed for Setup calls from ConfigMap callbacks
func SetTimescapeSetupParams(ctx context.Context, agwGateway *agw.AgentGateway, enableNxos bool) {
	setupContext = ctx
	setupAgw = agwGateway
	setupEnableNxos = enableNxos
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
		logger.GetLogger().Debug("Processing Timescape ConfigMap",
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
		internalConfig := convertProtobufToInternalConfig(timescapeConfig)

		// Update the configuration
		configManager := GetTimescapeConfigManager()
		configManager.SetTimescapeConfig(internalConfig)

		// Call Setup to start or restart the timescape client
		if setupContext != nil && setupAgw != nil {
			logger.GetLogger().Info("Starting Timescape client from ConfigMap")
			err := Setup(setupContext, setupAgw, setupEnableNxos)
			if err != nil {
				logger.GetLogger().Error("Failed to setup Timescape client from ConfigMap", "error", err)
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
func convertProtobufToInternalConfig(pbConfig *v1alpha.TimescapeConfig) *TimescapeConfig {
	config := &TimescapeConfig{
		ClientEnabled:        true, // Enable client when ConfigMap is present
		ConfigSource:         "configmap",
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
		config.UseMTLS = true
		config.Username = "" // mTLS doesn't use username/password
		config.Password = ""
		logger.GetLogger().Debug("timescape: configured mTLS authentication", "enabled", mtls.GetEnabled())
	} else {
		logger.GetLogger().Warn("timescape: no authentication method configured in ConfigMap")
	}

	return config
}
