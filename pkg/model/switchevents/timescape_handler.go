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
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/agw"
	"github.com/isovalent/hubble-fgs/pkg/model/switchevents/policystatus"
	"github.com/isovalent/hubble-fgs/pkg/model/switchevents/systemstatus"
	model "github.com/isovalent/hubble-fgs/pkg/nxosmodel"
	"github.com/isovalent/hubble-fgs/pkg/timescape"
	"github.com/isovalent/hubble-fgs/pkg/timescape/types"
)

// TimescapeHandler implements ITimescape by combining system and policy handlers
type TimescapeHandler struct {
	mu                  sync.RWMutex
	systemStatusHandler systemstatus.SystemConnectionHandler
	policyStatusHandler policystatus.PolicyStatusHandler
}

// TimescapeHandlerConfig provides configuration for the timescape handler
type TimescapeHandlerConfig struct {
	// SystemStatusDataProvider provides data for system status handler
	SystemStatusDataProvider systemstatus.SystemStatusDataProvider
	// PolicyStatusDataProvider provides data for policy status handler
	PolicyStatusDataProvider policystatus.PolicyStatusDataProvider
	// Client is the timescape client for sending events
	Client types.Client
}

// NewTimescapeHandler creates a new timescape handler
func NewTimescapeHandler(config TimescapeHandlerConfig) ITimescape {
	systemHandler := systemstatus.NewSystemConnectionHandler(config.SystemStatusDataProvider)
	systemHandler.SetClient(config.Client)

	policyHandler := policystatus.NewPolicyStatusHandler(config.PolicyStatusDataProvider)
	policyHandler.SetClient(config.Client)

	return &TimescapeHandler{
		systemStatusHandler: systemHandler,
		policyStatusHandler: policyHandler,
	}
}

// Start begins both system and policy status monitoring
func (h *TimescapeHandler) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Start system status handler
	if err := h.systemStatusHandler.Start(ctx); err != nil {
		logger.GetLogger().Error("Failed to start system status handler", "error", err)
		return err
	}

	// Start policy status handler
	if err := h.policyStatusHandler.Start(ctx); err != nil {
		logger.GetLogger().Error("Failed to start policy status handler", "error", err)
		h.systemStatusHandler.Stop(ctx) // Clean up system handler if policy fails
		return err
	}

	return nil
}

// Stop terminates both system and policy status monitoring
func (h *TimescapeHandler) Stop(ctx context.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Stop both handlers
	h.systemStatusHandler.Stop(ctx)
	h.policyStatusHandler.Stop(ctx)

	logger.GetLogger().Info("Timescape handler stopped")
}

// ReportSystemStatus triggers a system status report
func (h *TimescapeHandler) ReportSystemStatus(ctx context.Context) error {
	return h.systemStatusHandler.ReportSystemStatus(ctx)
}

// ReportPolicyStatus triggers a policy status report
func (h *TimescapeHandler) ReportPolicyStatus(ctx context.Context) error {
	return h.policyStatusHandler.ReportPolicyStatus(ctx)
}

// Setup initializes and runs a Timescape client with handler for system connection and policy status.
// It creates a Timescape client using the provided configuration, sets up composite handlers for
// system status and policy status monitoring, and keeps the client running until the context is cancelled.
//
// Parameters:
//   - ctx: Context for controlling the lifecycle of the Timescape client
//   - agw: AgentGateway instance providing system information like startup time, serial number, and version
//   - enableNxos: Flag to enable NX-OS specific functionality for controller connection status
//   - timescapePassword: Password for authenticating with the Timescape service
//   - timescapeEndpoint: URL endpoint for the Timescape service
//
// Returns:
//   - error: Returns an error if client creation fails or handler startup fails.
//
// The function will log warnings if timescapePassword or timescapeEndpoint are empty strings.
// It blocks until the context is cancelled, at which point it gracefully shuts down the handler
// and closes the client connection.
func Setup(ctx context.Context, agw *agw.AgentGateway, enableNxos bool, timescapePassword, timescapeEndpoint string) error {
	if timescapePassword == "" {
		logger.GetLogger().Warn("Timescape password not provided, return")
	}

	if timescapeEndpoint == "" {
		logger.GetLogger().Warn("Timescape endpoint not provided, return")
	}

	timescapeConfig := types.HTTPTransportConfig{
		// Add configuration fields as needed
		Username:    "timescape_push_api",
		Password:    timescapePassword,
		EndpointURL: timescapeEndpoint,

		UseProtobuf:        false,            // Use Protobuf instead of JSON
		InsecureSkipVerify: true,             // Skip TLS verification for development
		Timeout:            60 * time.Second, // Much longer timeout for network issues
		Compression:        true,             // Enable compression
	}
	// Build the timescape client
	client, err := timescape.NewTimescapeClient(ctx, timescapeConfig)
	if err != nil {
		logger.GetLogger().Error("failed to create timescape client", logfields.Error, err)
		return fmt.Errorf("timescape client setup failed: %w", err)
	}

	// Initialize the timescape handler (composite handler for both system and policy status)
	handler := NewTimescapeHandler(
		TimescapeHandlerConfig{
			Client: client,
			SystemStatusDataProvider: systemstatus.SystemStatusDataProvider{
				GetStartupTime: func() time.Time {
					return agw.GetStartupTime()
				},
				GetSerialNumber: func() string {
					if enableNxos {
						return agw.GetSerialNumber(ctx)
					}
					return "unknown"
				},
				GetVersion: func() string {
					return agw.Version()
				},
				GetControllerConnectionStatus: func() model.E_Cisco_NX_OSDevice_Sas_CommonStateE {
					if enableNxos {
						return model.E_Cisco_NX_OSDevice_Sas_CommonStateE(agw.GetControllerConnectionStatus())
					}
					return model.Cisco_NX_OSDevice_Sas_CommonStateE_unknown
				},
			},
			PolicyStatusDataProvider: policystatus.PolicyStatusDataProvider{
				GetSerialNumber: func() string {
					if enableNxos {
						return agw.GetSerialNumber(ctx)
					}
					return "unknown"
				},
			},
		},
	)
	err = handler.Start(ctx)
	if err != nil {
		logger.GetLogger().Error("failed to start timescape client handler", logfields.Error, err)
		return err
	}

	// Keep client running until context is cancelled
	<-ctx.Done()
	logger.GetLogger().Info("shutting down timescape client")
	handler.Stop(ctx)
	return client.Close()
}
