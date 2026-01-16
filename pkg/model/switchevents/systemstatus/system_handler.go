// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package systemstatus

import (
	"context"
	"sync"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/ipa/system_status/v1alpha"
	"google.golang.org/protobuf/types/known/timestamppb"

	model "github.com/isovalent/hubble-fgs/pkg/nxosmodel"
	"github.com/isovalent/hubble-fgs/pkg/timescape/types"
)

const (
	// Status update interval (30 seconds as requested)
	STATUS_UPDATE_INTERVAL = 30 * time.Second
	// System name for Nexus 9000 series
	SystemStatusName = "Nexus9K"
	// ClusterName is the cluster name used in system status events
	ClusterName = "smartswitch"
	// For ExtraData "connection_status"
	CONNECTED = "CONNECTED"
)

// For ConditionId
const (
	DISCONNECTED       = "DISCONNECTED"
	PENDING_CONNECTION = "PENDING_CONNECTION"
)

// For Subsystem
const (
	SUBSYSTEM_CONTROLLER_CONNECTION = "controller-connection"
)

// SystemStatusDataProvider provides data needed by the system status handler
type SystemStatusDataProvider struct {
	// GetStartupTime returns the startup time for the system
	GetStartupTime func() time.Time
	// GetVersion returns the system version
	GetVersion func() string
	// GetSerialNumber returns the system serial number
	GetSerialNumber func() string
	// GetControllerConnectionStatus returns the controller connection status as nxosmodel.E_Cisco_NX_OSDevice_Sas_CommonStateE
	GetControllerConnectionStatus func() model.E_Cisco_NX_OSDevice_Sas_CommonStateE
}

// SystemConnectionHandler manages periodic system connection status updates to timescape
type SystemConnectionHandler interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context)
	// ReportSystemStatus manually triggers a system status report
	ReportSystemStatus(ctx context.Context) error
	// SetClient sets the timescape client for this handler
	SetClient(client types.Client)
}

// systemConnectionHandler implements SystemConnectionHandler
type systemConnectionHandler struct {
	mu           sync.RWMutex
	running      bool
	stopCh       chan struct{}
	client       types.Client
	dataProvider SystemStatusDataProvider
	metadataSent bool // tracks if metadata has been successfully sent
}

// NewSystemConnectionHandler creates a new system connection handler
func NewSystemConnectionHandler(dataProvider SystemStatusDataProvider) SystemConnectionHandler {
	return &systemConnectionHandler{
		running:      false,
		stopCh:       make(chan struct{}),
		client:       nil, // Client will be set when needed
		dataProvider: dataProvider,
	}
}

// SetClient sets the timescape client for this handler
func (h *systemConnectionHandler) SetClient(client types.Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.client = client
}

// Start begins the periodic system connection status monitoring loop
func (h *systemConnectionHandler) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		return nil // Already running
	}

	h.running = true
	h.metadataSent = false
	// Send metadata update once at start
	h.sendSystemMetadataUpdate(ctx)
	// Start sending periodic status updates
	go h.monitoringLoop(ctx)
	logger.GetLogger().Debug("timescape: system connection status handler started")
	return nil
}

// Stop terminates the monitoring loop
func (h *systemConnectionHandler) Stop(_ context.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return
	}

	h.running = false
	close(h.stopCh)
	logger.GetLogger().Debug("timescape: system connection status handler stopped")
}

// monitoringLoop runs the periodic system connection status check and update
func (h *systemConnectionHandler) monitoringLoop(ctx context.Context) {
	ticker := time.NewTicker(STATUS_UPDATE_INTERVAL)
	defer ticker.Stop()

	// Send initial status
	h.checkAndSendSystemConnectionStatus(ctx)

	for {
		select {
		case <-ctx.Done():
			logger.GetLogger().Debug("timescape: system connection status stopped due to context cancellation")
			return
		case <-h.stopCh:
			logger.GetLogger().Debug("timescape: system connection status stopped")
			return
		case <-ticker.C:
			h.checkAndSendSystemConnectionStatus(ctx)
		}
	}
}

// checkAndSendSystemConnectionStatus checks the NXOS system connection status and sends to timescape if appropriate
func (h *systemConnectionHandler) checkAndSendSystemConnectionStatus(ctx context.Context) {
	logger.GetLogger().Debug("timescape: sending system connection status update to timescape")

	if h.client == nil {
		logger.GetLogger().Debug("timescape: client not initialized, skipping status update")
		return
	}

	// Ensure metadata was sent before sending status updates
	h.mu.RLock()
	if !h.metadataSent {
		logger.GetLogger().Info("timescape: system metadata not sent yet, skipping system status update")
		h.mu.RUnlock()
		return
	}
	h.mu.RUnlock()

	// Get current system connection status from NXOS controller
	currentStatus := h.dataProvider.GetControllerConnectionStatus()

	// Convert system connection status to system status event
	event := h.writeSystemStatusUpdate(currentStatus)
	if event == nil {
		logger.GetLogger().Info("timescape: failed to convert system connection status to system status event")
		return
	}

	err_code := h.client.Send(ctx, event, types.PriorityHigh)
	// Resend if queue is busy
	if err_code == types.ErrCodeQueueBusy {
		logger.GetLogger().Debug("timescape: queue full, waiting before retry", "status", currentStatus.String())

		// Wait for queue to clear before retrying
		select {
		case <-ctx.Done():
			logger.GetLogger().Debug("timescape: context cancelled while waiting to retry queue full")
			return
		case <-time.After(5 * time.Second):
			// Retry after waiting
			err_code = h.client.Send(ctx, event, types.PriorityHigh)
		}
	}

	if err_code != types.ErrCodeSuccess {
		logger.GetLogger().Error("timescape: failed to send system connection status", "error", err_code)
		return
	}

	logger.GetLogger().Debug("timescape: successfully sent system connection status",
		"status", currentStatus.String())
}

// writeSystemStatusUpdate creates a SystemStatusEvent based on the provided system connection status.
// It retrieves system information (startup time, serial number, version) from the data provider
// and maps the NXOS system connection status to appropriate conditions:
//
// - success: Creates an event with no failing conditions (assumes healthy state)
// - failure: Returns nil (skips sending when interface is down)
// - unknown/default: Creates an event with an error condition indicating unknown connection status
//
// Returns:
//   - *v1alpha.SystemStatusEvent: The created system status event, or nil for failure status
func (h *systemConnectionHandler) writeSystemStatusUpdate(status model.E_Cisco_NX_OSDevice_Sas_CommonStateE) *v1alpha.SystemStatusEvent {
	now := time.Now()

	// Create event structure similar to controller writeStatusUpdate
	event := &v1alpha.SystemStatusEvent{
		Time: timestamppb.New(now),
	}

	// Get startup time from data provider
	startupTime := now // fallback to current time
	if h.dataProvider.GetStartupTime != nil {
		startupTime = h.dataProvider.GetStartupTime()
	}
	serialNumber := "unknown"
	if h.dataProvider.GetSerialNumber != nil {
		serialNumber = h.dataProvider.GetSerialNumber()
	}
	version := "unknown"
	if h.dataProvider.GetVersion != nil {
		version = h.dataProvider.GetVersion()
	}

	// Create status update
	statusUpdate := &v1alpha.SystemStatusUpdate{
		ClusterName: ClusterName,
		NodeName:    serialNumber,
		StartedAt:   timestamppb.New(startupTime),
		System: &v1alpha.SystemID{
			Name:    SystemStatusName,
			Version: version,
		},
	}

	// Set the event with status wrapper
	event.Event = &v1alpha.SystemStatusEvent_Status{Status: statusUpdate}

	// Map NXOS system connection status to conditions
	switch status {
	case model.Cisco_NX_OSDevice_Sas_CommonStateE_success:
		statusUpdate.TotalConditions = 0
		statusUpdate.FailingConditions = []*v1alpha.FailingCondition{}
		statusUpdate.ExtraData = map[string]string{
			"connection_status": CONNECTED,
		}
	case model.Cisco_NX_OSDevice_Sas_CommonStateE_failure:
		// Failure: add error condition
		statusUpdate.TotalConditions = 1
		statusUpdate.FailingConditions = []*v1alpha.FailingCondition{
			{
				ConditionId: DISCONNECTED,
				Severity:    v1alpha.Severity_SEVERITY_MAJOR, // Error
				Message:     "On-prem controller connection is disconnected",
			},
		}
		logger.GetLogger().Info("timescape:  sending DISCONNECTED status update")
	case model.Cisco_NX_OSDevice_Sas_CommonStateE_unknown:
		fallthrough
	default:
		// Unknown: add error condition
		statusUpdate.TotalConditions = 1
		statusUpdate.FailingConditions = []*v1alpha.FailingCondition{
			{
				ConditionId: PENDING_CONNECTION,
				Severity:    v1alpha.Severity_SEVERITY_MAJOR, // Error
				Message:     "On-prem controller connection is pending",
			},
		}
	}

	return event
}

// writeSystemMetadataUpdate creates a SystemStatusEvent with SystemMetadataUpdate
// that contains metadata for the system's known conditions. This provides detailed
// descriptions and resolution information for conditions that may be reported
// in SystemStatusUpdate events.
//
// Returns:
//   - *v1alpha.SystemStatusEvent: The created system metadata event
func (h *systemConnectionHandler) writeSystemMetadataUpdate() *v1alpha.SystemStatusEvent {
	now := time.Now()

	// agw software version
	version := "unknown"
	if h.dataProvider.GetVersion != nil {
		version = h.dataProvider.GetVersion()
	}

	// Create event structure
	event := &v1alpha.SystemStatusEvent{
		Time: timestamppb.New(now),
	}

	// Create metadata update
	metadataUpdate := &v1alpha.SystemMetadataUpdate{
		System: &v1alpha.SystemID{
			Name:    SystemStatusName,
			Version: version,
		},
		Conditions: []*v1alpha.ConditionMetadata{
			{
				ConditionId: DISCONNECTED,
				Subsystem:   SUBSYSTEM_CONTROLLER_CONNECTION,
				Description: "SmartSwitch failed to connect to the Kubernetes API server or lost connection with the controller",
				Resolution:  "Check switch network connectivity, verify K8s API server is running, and ensure authentication credentials are valid",
			},
			{
				// Pending connection: nxosmodel.E_Cisco_NX_OSDevice_Sas_CommonStateE_unknown
				ConditionId: PENDING_CONNECTION,
				Subsystem:   SUBSYSTEM_CONTROLLER_CONNECTION,
				Description: "SmartSwitch controller connection status is pending",
				Resolution:  "Check SmartSwitch configuration for NX-OS controller connectivity settings",
			},
		},
	}

	// Set the event with metadata wrapper
	event.Event = &v1alpha.SystemStatusEvent_Metadata{Metadata: metadataUpdate}

	return event
}

// sendSystemMetadataUpdate creates and sends system metadata update to timescape with retry logic.
// This one-time status event is mandatory for Timescape to understand all condition metadata
func (h *systemConnectionHandler) sendSystemMetadataUpdate(ctx context.Context) {
	logger.GetLogger().Debug("timescape: sending system metadata update")

	if h.client == nil {
		logger.GetLogger().Warn("timescape: client not initialized, skipping metadata update")
		return
	}

	// Create system metadata update event
	event := h.writeSystemMetadataUpdate()

	// Keep retrying until successful send or context cancelled
	for {
		errCode := h.client.Send(ctx, event, types.PriorityHigh)

		switch errCode {
		case types.ErrCodeSuccess:
			logger.GetLogger().Debug("timescape: successfully sent system metadata update")
			h.metadataSent = true
			return

		case types.ErrCodeQueueBusy:
			logger.GetLogger().Debug("timescape: queue full, waiting before retry for metadata update")
			fallthrough

		default: // ErrCodeFailure or other errors
			if errCode != types.ErrCodeQueueBusy {
				logger.GetLogger().Debug("timescape: failed to send system metadata update, retrying", "error", errCode)
			}

			// Wait before retrying
			select {
			case <-ctx.Done():
				logger.GetLogger().Debug("timescape: context cancelled while retrying metadata update")
				return
			case <-time.After(2 * time.Second):
				// Continue the retry loop
				continue
			}
		}
	}
}

// ReportSystemStatus manually triggers a system status report
func (h *systemConnectionHandler) ReportSystemStatus(ctx context.Context) error {
	h.checkAndSendSystemConnectionStatus(ctx)
	return nil
}
