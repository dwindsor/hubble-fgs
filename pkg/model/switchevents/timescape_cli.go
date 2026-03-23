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
	"net/url"
	"strings"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/manager"

	"github.com/isovalent/hubble-fgs/pkg/agw"
	"github.com/isovalent/hubble-fgs/pkg/config/library"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

// SetupTimescapeFromCLI validates timescape configuration from CLI and initializes the client
func SetupTimescapeFromCLI(ctx context.Context, agwAgent *agw.AgentGateway, enableNXOS bool, timescapeClientEnable bool, timescapePassword string, timescapeEndpoint string, controllerManager *manager.ControllerManager) error {
	if !timescapeClientEnable {
		return nil
	}

	// Validate CLI configuration
	trimmedPassword := strings.TrimSpace(timescapePassword)
	trimmedEndpoint := strings.TrimSpace(timescapeEndpoint)

	if trimmedPassword == "" {
		logger.GetLogger().Error("CLI timescape client enabled but password not configured", "flag", "--timescape-password")
		return nil
	}

	if trimmedEndpoint == "" {
		logger.GetLogger().Error("CLI timescape client enabled but endpoint not configured", "flag", "--timescape-endpoint")
		return nil
	}

	// Parse the endpoint URL to extract host and port - URL format required
	if !strings.HasPrefix(trimmedEndpoint, "http://") && !strings.HasPrefix(trimmedEndpoint, "https://") {
		logger.GetLogger().Error("CLI timescape client enabled with invalid endpoint format - URL format required", "endpoint", trimmedEndpoint)
		return nil
	}

	parsed, err := url.Parse(trimmedEndpoint)
	if err != nil {
		logger.GetLogger().Error("CLI timescape client enabled with invalid endpoint format", "endpoint", trimmedEndpoint, logfields.Error, err)
		return nil
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		logger.GetLogger().Error("CLI timescape client enabled but port not specified in endpoint", "endpoint", trimmedEndpoint)
		return nil
	}

	SetTimescapeSetupParams(ctx, agwAgent, enableNXOS, controllerManager)

	// Initialize configuration from CLI values using repository pattern
	err = library.GetRepository().UpdateConfig(v1alpha.ConfigType_CONFIG_TYPE_TIMESCAPE,
		func(_ *v1alpha.ConfigObject) (*v1alpha.ConfigObject, error) {
			timescapeConfig := &v1alpha.TimescapeConfig{
				// Basic identification
				Id:          TimescapeConfigMapId,
				Name:        "SmartSwitch Timescape Client",
				Description: "Timescape client configuration for external SmartSwitch reporting",

				// Connection details
				Host:        host,
				Port:        port,
				Protocol:    "TCP",
				TlsEnabled:  true,
				EndpointApi: "/push",

				// Transport configuration for production deployments
				MaxRetries:           0,
				ConnectionTimeoutSec: 0,
				RequestTimeoutSec:    0,

				// Batching configuration for message processing
				MaxBatchSize:   0,
				BatchTimeoutMs: 0,
				// Authentication using oneof field pattern
				Auth: &v1alpha.TimescapeConfig_BasicAuth{
					BasicAuth: &v1alpha.TimescapeBasicAuth{
						Username: TIMESCAPE_USERNAME,
						Password: trimmedPassword,
					},
				},
			}

			return &v1alpha.ConfigObject{
				Type:   v1alpha.ConfigType_CONFIG_TYPE_TIMESCAPE,
				Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL, // CLI source
				Config: &v1alpha.ConfigObject_ConfigTimescape{ConfigTimescape: timescapeConfig},
			}, nil
		},
	)
	if err != nil {
		logger.GetLogger().Error("Failed to update timescape config", logfields.Error, err)
		return err
	}

	logger.GetLogger().Info("Starting Timescape client from CLI configuration")
	return nil
}
