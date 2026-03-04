// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package switchstatus

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/manager"
	"github.com/cilium/tetragon/pkg/version"

	isovalentcom "github.com/isovalent/ipa/k8s/apis/isovalent.com"

	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"
	"github.com/isovalent/hubble-fgs/pkg/nxos"
	nxosmodel "github.com/isovalent/hubble-fgs/pkg/nxosmodel"
)

const (
	// SmartSwitch inventory update interval (10 minute)
	INVENTORY_UPDATE_INTERVAL    = 10 * time.Minute
	MAX_INVENTORY_UPDATE_RETRIES = 3
)

// InventoryHandler manages periodic SmartSwitch inventory updates
type InventoryHandler interface {
	AddSmartSwitchInventoryCR(ctx context.Context, kubernetesManager *manager.ControllerManager) error
}

// InventoryDataProvider provides data needed for inventory updates
type InventoryDataProvider struct {
	GetDPUStatus    func() ([]switchpolicy.DPUReportStatus, error)
	GetK8sNamespace func() string
	GetServiceMAC   func() string
}

// inventoryHandler implements InventoryHandler
type inventoryHandler struct {
	mu           sync.RWMutex
	dataProvider InventoryDataProvider
	// Track last known state for change detection
	lastInventory *SmartSwitchInventoryFields
}

// NewInventoryHandler creates a new inventory handler with callback functions
func NewInventoryHandler(dataProvider InventoryDataProvider) InventoryHandler {
	return &inventoryHandler{
		dataProvider: dataProvider,
	}
}

// AddSmartSwitchInventoryCR starts the periodic DPU inventory update process (blocking)
func (h *inventoryHandler) AddSmartSwitchInventoryCR(ctx context.Context, kubernetesManager *manager.ControllerManager) error {
	logger.GetLogger().Info("starting inventory handler with initial CR creation and periodic updates",
		"interval", INVENTORY_UPDATE_INTERVAL)

	// First, ensure the SmartSwitch CRD is available and create initial CR
	if err := h.createInitialSmartSwitchCR(ctx, kubernetesManager); err != nil {
		logger.GetLogger().Error("create initial SmartSwitch CR failed, retry...", logfields.Error, err)
		// Not gating startup on failure to create initial SmartSwitch Inventory CR.
	}

	// Run the periodic loop directly (blocking until context is cancelled)
	h.periodicUpdateLoop(ctx, kubernetesManager)

	logger.GetLogger().Info("stopped periodic SmartSwitch inventory updates")
	return nil
}

// periodicUpdateLoop runs the periodic update loop
func (h *inventoryHandler) periodicUpdateLoop(ctx context.Context, kubernetesManager *manager.ControllerManager) {
	ticker := time.NewTicker(INVENTORY_UPDATE_INTERVAL)
	defer ticker.Stop()

	logger.GetLogger().Debug("Starting periodic inventory update loop", "interval", INVENTORY_UPDATE_INTERVAL)

	for {
		select {
		case <-ctx.Done():
			// cancelled, exit loop
			logger.GetLogger().Debug("inventory update loop stopping due to context cancellation")
			return
		case <-ticker.C:
			if kubernetesManager == nil {
				logger.GetLogger().Info("Kubernetes manager not available during periodic inventory update")
				continue
			}

			// Check if controller connection is healthy before attempting update
			if !h.isControllerConnectionHealthy() {
				logger.GetLogger().Info("controller is not connected, skipping inventory update")
				continue
			}

			if err := h.updateInventory(ctx, kubernetesManager); err != nil {
				logger.GetLogger().Error("update inventory during periodic update",
					logfields.Error, err)
			}
		}
	}
}

// isControllerConnectionHealthy checks if the controller connection is healthy
func (h *inventoryHandler) isControllerConnectionHealthy() bool {
	// Check controller connection status directly
	connectionStatus := nxos.Nexus.Ctrlr.ConnectionStatus

	// Connection is healthy if status is success
	return connectionStatus == nxosmodel.Cisco_NX_OSDevice_Sas_CommonStateE_success
}

// updateInventory performs the actual inventory update
func (h *inventoryHandler) updateInventory(ctx context.Context, kubernetesManager *manager.ControllerManager) error {
	logger.GetLogger().Debug("updating smartswitch inventory")

	// Create DPU inventories from current DPU status
	dpuInventories, err := h.createDPUInventories()
	if err != nil {
		return fmt.Errorf("failed to create DPU inventories: %w", err)
	}

	// Get serial number for SmartSwitch CR name
	serial := nxos.Nexus.GetSerialNum(ctx)
	if serial == "" {
		return fmt.Errorf("failed to get serial number")
	}

	// Create SmartSwitchInventory fields
	newInventory := &SmartSwitchInventoryFields{
		BiosVersion:     "",
		ServiceIP:       nxos.Nexus.GetServiceIp(),
		ServiceMAC:      h.dataProvider.GetServiceMAC(),
		SerialNumber:    serial,
		SoftwareVersion: h.getSoftwareVersion(),
		DPUInventories:  dpuInventories,
	}

	// Check if inventory has changed (but don't update cache yet)
	h.mu.Lock()
	hasChanged := !h.inventoryFieldsEqual(h.lastInventory, newInventory)
	h.mu.Unlock()

	// Skip update if no changes detected
	if !hasChanged {
		logger.GetLogger().Debug("no changes detected in inventory, skipping update",
			"serialNumber", serial,
			"dpuCount", len(dpuInventories))
		return nil
	}

	logger.GetLogger().Debug("inventory changes detected, proceeding with update",
		"serialNumber", serial,
		"dpuCount", len(dpuInventories),
		"serviceIP", newInventory.ServiceIP,
		"serviceMAC", newInventory.ServiceMAC,
		"softwareVersion", newInventory.SoftwareVersion)

	// Create the SmartSwitchInventory CR
	smartSwitchInventory, err := GetSmartSwitchInventory(serial, h.dataProvider.GetK8sNamespace(), newInventory)
	if err != nil {
		return err
	}

	// Apply the CR to the cluster with retry logic
	for i := 0; i < MAX_INVENTORY_UPDATE_RETRIES; i++ {
		if !h.isControllerConnectionHealthy() {
			logger.GetLogger().Info("Controller is not connected before applying SmartSwitchInventory CR, skipping update and retries")
			break
		}

		err := ApplySmartSwitchInventoryCR(ctx, kubernetesManager, smartSwitchInventory)
		if err == nil {
			logger.GetLogger().Debug("successfully updated SmartSwitchInventory CR during periodic update")

			// Only update cache AFTER successful CR application
			h.mu.Lock()
			h.lastInventory = &SmartSwitchInventoryFields{
				BiosVersion:     newInventory.BiosVersion,
				ServiceIP:       newInventory.ServiceIP,
				ServiceMAC:      newInventory.ServiceMAC,
				SerialNumber:    newInventory.SerialNumber,
				SoftwareVersion: newInventory.SoftwareVersion,
				DPUInventories:  make([]DPUInventory, len(newInventory.DPUInventories)),
			}
			copy(h.lastInventory.DPUInventories, newInventory.DPUInventories)
			h.mu.Unlock()

			return nil
		}

		if i == MAX_INVENTORY_UPDATE_RETRIES-1 {
			return fmt.Errorf("failed to apply SmartSwitchInventory CR after retries: %w", err)
		}

		logger.GetLogger().Warn(
			fmt.Sprintf("error applying SmartSwitchInventory CR during periodic update, will retry (attempt %d/%d)", i+1, MAX_INVENTORY_UPDATE_RETRIES),
			logfields.Error, err,
		)

		// Exponential backoff: 1s, 2s, 4s for each retry attempt
		backoff := time.Duration(1<<i) * time.Second
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			// Continue to next retry
		}
	}

	return nil // Should not reach here due to return in loop
}

// createDPUInventories creates DPU inventory entries from connected DPUs
func (h *inventoryHandler) createDPUInventories() ([]DPUInventory, error) {
	var dpuInventories []DPUInventory

	dpuStatuses, err := h.dataProvider.GetDPUStatus()
	if err != nil {
		return nil, fmt.Errorf("failed to get DPU status: %w", err)
	}

	logger.GetLogger().Debug("creating DPU inventories", "count", len(dpuStatuses))

	// Create DPU inventory for each connected DPU
	for _, dpuStatus := range dpuStatuses {
		dpuInventory := DPUInventory{
			HardwareModel:   dpuStatus.HardwareModel,
			ID:              dpuStatus.AgentUid,
			ManagementIP:    dpuStatus.AgentUid, // Use AgentUid as Management IP
			PortLow:         int(dpuStatus.PortLow),
			PortHigh:        int(dpuStatus.PortHigh),
			SoftwareVersion: dpuStatus.DpVersion,
		}

		dpuInventories = append(dpuInventories, dpuInventory)
		logger.GetLogger().Debug("added DPU inventory",
			"id", dpuInventory.ID,
			"hardwareModel", dpuInventory.HardwareModel,
			"mgmtIP", dpuInventory.ManagementIP,
			"softwareVersion", dpuInventory.SoftwareVersion,
			"portRange", fmt.Sprintf("%d-%d", dpuInventory.PortLow, dpuInventory.PortHigh))
	}

	return dpuInventories, nil
}

// createInitialSmartSwitchCR creates the initial SmartSwitch custom resource
func (h *inventoryHandler) createInitialSmartSwitchCR(ctx context.Context, kubernetesManager *manager.ControllerManager) error {
	logger.GetLogger().Info("creating initial SmartSwitchInventory custom resource")

	// Check if kubernetesManager is nil
	if kubernetesManager == nil {
		return fmt.Errorf("kubernetes manager is nil")
	}

	// Ensure the SmartSwitchInventory CRD is present in the cluster
	ssCrd := make(map[string]struct{})
	ssCrd["smartswitches"+"."+isovalentcom.GroupName] = struct{}{}
	if len(ssCrd) > 0 {
		err := kubernetesManager.WaitCRDsWithResync(ctx, ssCrd, 120*time.Second)
		if err != nil {
			logger.GetLogger().Error("failed to wait for SmartSwitch CRD", logfields.Error, err)
			return err
		}
	}

	// Create the initial SmartSwitchInventory CR by doing an immediate update
	if err := h.updateInventory(ctx, kubernetesManager); err != nil {
		return err
	}

	logger.GetLogger().Debug("successfully created initial SmartSwitchInventory CR")
	return nil
}

// inventoryFieldsEqual compares two SmartSwitchInventoryFields for equality
func (h *inventoryHandler) inventoryFieldsEqual(a, b *SmartSwitchInventoryFields) bool {
	// If either inventory is nil, they are only equal if both are nil.
	if a == nil || b == nil {
		return a == b
	}

	// Compare basic fields
	if a.BiosVersion != b.BiosVersion ||
		a.SerialNumber != b.SerialNumber ||
		a.ServiceIP != b.ServiceIP ||
		a.ServiceMAC != b.ServiceMAC ||
		a.SoftwareVersion != b.SoftwareVersion {
		logger.GetLogger().Debug("Inventory basic fields differ",
			"a", a,
			"b", b)
		return false
	}

	// Only compare DPU inventories if basic fields are equal
	return h.dpuInventoriesEqual(a.DPUInventories, b.DPUInventories)
}

// dpuInventoriesEqual compares two slices of DPUInventory for equality
func (h *inventoryHandler) dpuInventoriesEqual(a, b []DPUInventory) bool {
	if len(a) != len(b) {
		return false
	}

	// Create maps for easy comparison (indexed by ID)
	aMap := make(map[string]DPUInventory)
	bMap := make(map[string]DPUInventory)

	for _, dpu := range a {
		aMap[dpu.ID] = dpu
	}
	for _, dpu := range b {
		bMap[dpu.ID] = dpu
	}

	// Check if all DPUs in a exist in b with same values
	for id, dpuA := range aMap {
		dpuB, exists := bMap[id]
		if !exists {
			return false
		}
		if !h.dpuInventoryEqual(dpuA, dpuB) {
			return false
		}
	}

	return true
}

// dpuInventoryEqual compares two DPUInventory structs for equality
func (h *inventoryHandler) dpuInventoryEqual(a, b DPUInventory) bool {
	return a.HardwareModel == b.HardwareModel &&
		a.ID == b.ID &&
		a.ManagementIP == b.ManagementIP &&
		a.PortHigh == b.PortHigh &&
		a.PortLow == b.PortLow &&
		a.SoftwareVersion == b.SoftwareVersion
}

// getSoftwareVersion retrieves software version directly
func (h *inventoryHandler) getSoftwareVersion() string {
	return version.Version
}
