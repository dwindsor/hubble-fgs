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
	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/device"
	"github.com/isovalent/hubble-fgs/pkg/timescape"
	"github.com/isovalent/hubble-fgs/pkg/timescape/types"
)

// Package-level variable to store the handler instance
var (
	globalTimescapeHandler     ITimescape
	globalNetworkPolicyWatcher switchpolicy.SmartSwitchNetworkPolicyWatcher
	handlerMu                  sync.RWMutex
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

// NewTimescapeHandler creates a new timescape handler with bulk policy reporting
func NewTimescapeHandler(config TimescapeHandlerConfig) ITimescape {
	systemHandler := systemstatus.NewSystemConnectionHandler(config.SystemStatusDataProvider)
	logger.GetLogger().Debug("Setting client on system handler", "clientPtr", fmt.Sprintf("%p", config.Client))
	systemHandler.SetClient(config.Client)

	// Get timescape configuration for policy aggregator settings
	timescapeConfig := CurrentTimescapeConfig()
	var bulkReportingInterval time.Duration

	if timescapeConfig != nil && timescapeConfig.PolicystatusReportingIntervalMins > 0 {
		bulkReportingInterval = time.Duration(timescapeConfig.PolicystatusReportingIntervalMins) * time.Minute
	} else {
		bulkReportingInterval = types.DefaultPolicyStatusReportingInterval
	}

	policyHandler := policystatus.NewPolicyStatusHandlerWithConfig(
		config.PolicyStatusDataProvider,
		bulkReportingInterval,
	)
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

// GetPolicyStatusHandler returns the policy status handler from the timescape handler
func (h *TimescapeHandler) GetPolicyStatusHandler() policystatus.PolicyStatusHandler {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.policyStatusHandler
}

// GetGlobalTimescapeHandler returns the global timescape handler instance
func GetGlobalTimescapeHandler() ITimescape {
	handlerMu.RLock()
	defer handlerMu.RUnlock()
	return globalTimescapeHandler
}

// GetGlobalPolicyStatusHandler returns the policy status handler from the global timescape handler
func GetGlobalPolicyStatusHandler() policystatus.PolicyStatusHandler {
	handlerMu.RLock()
	defer handlerMu.RUnlock()

	if globalTimescapeHandler == nil {
		return nil
	}

	if th, ok := globalTimescapeHandler.(*TimescapeHandler); ok {
		return th.GetPolicyStatusHandler()
	}

	return nil
}

func SetGlobalPolicyStatusHandler(handler policystatus.PolicyStatusHandler) {
	logger.GetLogger().Debug("SetGlobalPolicyStatusHandler called", "handler_not_nil", handler != nil)
	handlerMu.Lock()
	defer handlerMu.Unlock()

	if globalTimescapeHandler != nil {
		logger.GetLogger().Debug("Global timescape handler found, setting policy status handler on it")
		if th, ok := globalTimescapeHandler.(*TimescapeHandler); ok {
			th.policyStatusHandler = handler
			logger.GetLogger().Info("Successfully set policy status handler on global timescape handler")
		} else {
			logger.GetLogger().Warn("Global timescape handler is not of expected type, cannot set policy status handler")
		}
	} else {
		logger.GetLogger().Warn("No global timescape handler to set policy status handler on")
	}
}

// SetGlobalNetworkPolicyWatcher stores the network policy watcher globally for later updates
func SetGlobalNetworkPolicyWatcher(watcher switchpolicy.SmartSwitchNetworkPolicyWatcher) {
	logger.GetLogger().Info("SetGlobalNetworkPolicyWatcher called", "watcher_not_nil", watcher != nil)
	handlerMu.Lock()
	defer handlerMu.Unlock()
	globalNetworkPolicyWatcher = watcher
}

// updateNetworkPolicyWatcherWithHandler updates the policy status handler for the global network policy watcher using provided handler
func updateNetworkPolicyWatcherWithHandler(policyStatusHandler policystatus.PolicyStatusHandler) error {
	logger.GetLogger().Info("updateNetworkPolicyWatcherWithHandler called", "handler_not_nil", policyStatusHandler != nil)
	handlerMu.Lock()
	defer handlerMu.Unlock()

	if globalNetworkPolicyWatcher != nil {
		logger.GetLogger().Info("Global network policy watcher found, updating with provided policy status handler")
		globalNetworkPolicyWatcher.SetPolicyStatusHandler(policyStatusHandler)
		logger.GetLogger().Info("Successfully updated network policy watcher with policy status handler")
	} else {
		logger.GetLogger().Warn("No global network policy watcher to update")
		return fmt.Errorf("no global network policy watcher to update")
	}
	return nil
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
//
// Returns:
//   - error: Returns an error if validation fails, client creation fails, or handler startup fails.
//
// It blocks until the context is cancelled, at which point it gracefully shuts down the handler
// and closes the client connection.
func Setup(ctx context.Context, agw *agw.AgentGateway, enableNxos bool) error {
	// Get configuration from the config manager
	config := CurrentTimescapeConfig()
	if config == nil {
		logger.GetLogger().Error("Timescape configuration not available")
		return fmt.Errorf("timescape configuration not available")
	}

	// Validate authentication configuration
	if !config.UseBasicAuth && !config.UseMTLS {
		logger.GetLogger().Warn("No authentication configured - neither BasicAuth nor mTLS is enabled")
	} else if config.UseBasicAuth && config.Password == "" {
		logger.GetLogger().Warn("Timescape password not provided for basic auth, return")
		return fmt.Errorf("timescape password required for BasicAuth")
	}

	if config.Endpoint == "" {
		logger.GetLogger().Warn("Timescape endpoint not provided, return")
		return fmt.Errorf("timescape endpoint is required")
	}

	// Build timescape config with all the new fields
	timescapeConfig := types.HTTPTransportConfig{
		Username:    config.Username,
		Password:    config.Password,
		EndpointURL: config.Endpoint,
		UseMTLS:     config.UseMTLS,

		InsecureSkipVerify: types.DefaultInsecureSkipVerify,                       // Skip verification (development)
		Timeout:            time.Duration(config.RequestTimeoutSec) * time.Second, // Use config value or default

		ConnectionTimeout: time.Duration(config.ConnectionTimeoutSec) * time.Second, // Connection timeout
		MaxRetries:        int(config.MaxRetries),                                   // Retry configurations
		Compression:       true,                                                     // Enable compression
	}

	// Apply timeout defaults if not configured
	if timescapeConfig.Timeout == 0 {
		timescapeConfig.Timeout = types.DefaultHTTPRequestTimeout // Default timeout
	}
	if timescapeConfig.ConnectionTimeout == 0 {
		timescapeConfig.ConnectionTimeout = types.DefaultHTTPConnectionTimeout // Default connection timeout
	}
	if timescapeConfig.MaxRetries == 0 {
		timescapeConfig.MaxRetries = types.DefaultMaxRetries // Default max retries
	}
	if config.PolicystatusReportingIntervalMins == 0 {
		config.PolicystatusReportingIntervalMins = uint32(types.DefaultPolicyStatusReportingInterval.Minutes()) // Default bulk reporting interval in mins
	}

	logger.GetLogger().Info("Setting up timescape client",
		"endpoint", config.Endpoint,
		"auth_type", getAuthTypeString(config),
		"insecure_skip_verify", timescapeConfig.InsecureSkipVerify,
		"max_retries", timescapeConfig.MaxRetries,
		"connection_timeout_sec", timescapeConfig.ConnectionTimeout.Seconds(),
		"request_timeout_sec", timescapeConfig.Timeout.Seconds(),
		"policystatus_reporting_interval_mins", config.PolicystatusReportingIntervalMins)

	// Build the timescape client with isolated context
	client, err := timescape.NewTimescapeClient(ctx, timescapeConfig, config.PolicystatusReportingIntervalMins*60*1000)
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
				GetControllerConnectionStatus: func() string {
					if enableNxos {
						return agw.GetControllerConnectionStatus()
					}
					return device.ControllerStateUnknown
				},
			},
			PolicyStatusDataProvider: policystatus.PolicyStatusDataProvider{
				GetSerialNumber: func() string {
					if enableNxos {
						return agw.GetSerialNumber(ctx)
					}
					return "unknown"
				},
				// Add GetNumDpu function
				GetNumDpu: func() int {
					if enableNxos && agw != nil {
						return agw.GetNumDpu()
					}
					return 0 // Default fallback
				},
			},
		},
	)

	// Store the handler globally BEFORE starting it
	handlerMu.Lock()
	globalTimescapeHandler = handler
	handlerMu.Unlock()

	err = handler.Start(ctx)
	if err != nil {
		logger.GetLogger().Error("failed to start timescape client handler", logfields.Error, err)
		// Clear the global handler on error
		handlerMu.Lock()
		globalTimescapeHandler = nil
		handlerMu.Unlock()
		return err
	}

	// Get the policy status handler from the handler and set it globally
	if th, ok := handler.(*TimescapeHandler); ok {
		globalPolicyStatusHandler := th.GetPolicyStatusHandler()
		updateNetworkPolicyWatcherWithHandler(globalPolicyStatusHandler)
		logger.GetLogger().Info("Policy status handler extracted from timescape handler", "handler_not_nil", globalPolicyStatusHandler != nil)
	}

	// Set the policy status handler from the timescape setup on the DPU listener
	// Do this synchronously to avoid race conditions with incoming policy events
	policyStatusHandler := GetGlobalPolicyStatusHandler()
	if policyStatusHandler != nil {
		// Access the DPU listener through the AgentGateway and set the handler
		dpuListener := agw.GetDPUListener()
		if dpuListener != nil {
			dpuListener.SetPolicyStatusHandler(policyStatusHandler)
			logger.GetLogger().Info("Policy status handler successfully set on DPU listener")
		} else {
			logger.GetLogger().Warn("DPU listener not available to set policy status handler")
		}
	} else {
		logger.GetLogger().Warn("Policy status handler not available from global timescape handler")
	}

	// Keep client running until context is cancelled
	go func() {
		<-ctx.Done()
		logger.GetLogger().Debug("shutting down timescape client")
		handler.Stop(ctx)

		// Ensure client is closed with a timeout to prevent hanging indefinitely
		done := make(chan error, 1)
		go func() {
			done <- client.Close()
		}()

		select {
		case err := <-done:
			if err != nil {
				logger.GetLogger().Error("Error closing timescape client", "error", err)
			}
		case <-time.After(2 * time.Second):
			logger.GetLogger().Warn("timescape client close timed out after 2 seconds, forcing exit")
		}
	}()
	return nil
}

// getAuthTypeString returns a human-readable authentication type for logging
func getAuthTypeString(config *TimescapeConfig) string {
	if config.UseBasicAuth {
		return "basic_auth"
	} else if config.UseMTLS {
		return "mtls"
	}
	return "none"
}
