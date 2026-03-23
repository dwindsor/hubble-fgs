// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dpu

import (
	"context"
	"fmt"
	"strconv"

	"github.com/cilium/tetragon/pkg/logger"
	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
	nxosmodel "github.com/isovalent/hubble-fgs/pkg/nxosmodel"
)

// HandleGnmiNotification processes a gNMI notification for DPU state.
// It matches incoming paths against the DPUStore* subscription paths defined in the paths package.
func (s *dpuStore) HandleGnmiNotification(ctx context.Context, path string, update *gnmiproto.Update, isDelete bool) {
	// Handle delete notifications for per-DPU paths
	if isDelete {
		if moduleNum, ok := paths.ExtractDPUModuleNum(path); ok {
			dpuName := fmt.Sprintf("dpu-%d", moduleNum)
			if err := s.Remove(ctx, dpuName); err != nil {
				if !IsNotFound(err) {
					logger.GetLogger().Warn("Failed to remove DPU on gNMI delete", "name", dpuName, "error", err)
				}
			}
		}
		return
	}

	value := update.GetVal()

	switch {
	case paths.PathMatches(path, paths.DPUStoreInitState):
		if strVal, ok := gnmi.ExtractStringValue(value); ok {
			s.SetInventoryComplete(strVal == "inventory-done")
			logger.GetLogger().Debug("DPU initState updated via gNMI notification", "initState", strVal)
		}

	case paths.PathMatches(path, paths.DPUStoreNumDPUs):
		if uintVal, ok := gnmi.ExtractUint32Value(value); ok {
			s.SetExpectedCount(int(uintVal))
			logger.GetLogger().Debug("DPU numDpus updated via gNMI notification", "count", uintVal)
		} else if strVal, ok := gnmi.ExtractStringValue(value); ok {
			if count, err := strconv.Atoi(strVal); err == nil {
				s.SetExpectedCount(count)
				logger.GetLogger().Debug("DPU numDpus updated via gNMI notification", "count", count)
			}
		}

	case paths.PathMatches(path, paths.DPUStoreIP):
		moduleNum, ok := paths.ExtractDPUModuleNum(path)
		if !ok {
			logger.GetLogger().Warn("Failed to extract moduleNum from DPU IP path", "path", path)
			return
		}
		if strVal, ok := gnmi.ExtractStringValue(value); ok {
			s.upsertDPUField(ctx, moduleNum, func(dpu *types.DPU) {
				dpu.IP = strVal
			})
			logger.GetLogger().Debug("DPU IP updated via gNMI notification", "moduleNum", moduleNum, "ip", strVal)
		}

	case paths.PathMatches(path, paths.DPUStoreState):
		moduleNum, ok := paths.ExtractDPUModuleNum(path)
		if !ok {
			logger.GetLogger().Warn("Failed to extract moduleNum from DPU state path", "path", path)
			return
		}
		if strVal, ok := gnmi.ExtractStringValue(value); ok {
			state := parseDpuState(strVal)
			s.upsertDPUField(ctx, moduleNum, func(dpu *types.DPU) {
				dpu.State = state
			})
			logger.GetLogger().Debug("DPU state updated via gNMI notification", "moduleNum", moduleNum, "state", strVal)
		}

	case paths.PathMatches(path, paths.DPUStoreVersion):
		moduleNum, ok := paths.ExtractDPUModuleNum(path)
		if !ok {
			logger.GetLogger().Warn("Failed to extract moduleNum from DPU version path", "path", path)
			return
		}
		if strVal, ok := gnmi.ExtractStringValue(value); ok {
			s.upsertDPUField(ctx, moduleNum, func(dpu *types.DPU) {
				dpu.Version = strVal
			})
			logger.GetLogger().Debug("DPU version updated via gNMI notification", "moduleNum", moduleNum, "version", strVal)
		}

	default:
		logger.GetLogger().Warn("Failed to handle DPU gNMI update notification", "path", path)
	}
}

// upsertDPUField gets or creates a DPU by moduleNum and applies the given update function.
func (s *dpuStore) upsertDPUField(ctx context.Context, moduleNum int, updateFn func(dpu *types.DPU)) {
	dpuName := fmt.Sprintf("dpu-%d", moduleNum)
	dpu, exists := s.Get(dpuName)
	if !exists {
		dpu = types.DPU{
			Name:      dpuName,
			ModuleNum: moduleNum,
		}
	}
	updateFn(&dpu)
	_ = s.Update(ctx, dpu)
}

// parseDpuState maps a DPU state string from gNMI to the nxosmodel enum value.
func parseDpuState(state string) nxosmodel.E_Cisco_NX_OSDevice_Sas_DpuStateE {
	switch state {
	case "none":
		return nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_none
	case "init":
		return nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_init
	case "update":
		return nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_update
	case "online":
		return nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_online
	case "failed":
		return nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_failed
	case "power-down", "power_down":
		return nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_power_down
	case "discovery":
		return nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_discovery
	case "gold-fw-boot", "gold_fw_boot":
		return nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_gold_fw_boot
	case "main-fw-boot", "main_fw_boot":
		return nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_main_fw_boot
	default:
		return nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_UNSET
	}
}

// SetDpuPortRange writes TCP/UDP control plane port ranges for a DPU via gNMI SET (gnmi.md SET #6).
func (s *dpuStore) SetDpuPortRange(ctx context.Context, moduleNum int, tcpRange, udpRange string) error {
	s.mu.RLock()
	handler := s.gnmiHandler
	s.mu.RUnlock()

	if handler == nil {
		return nil
	}

	tcpPath := fmt.Sprintf(paths.DPUStoreTCPPorts, moduleNum)
	if err := handler.Set(ctx, tcpPath, tcpRange); err != nil {
		logger.GetLogger().Warn("Failed to set DPU TCP port range via gNMI", "moduleNum", moduleNum, "error", err)
		return fmt.Errorf("set DPU port range: %w", err)
	}

	udpPath := fmt.Sprintf(paths.DPUStoreUDPPorts, moduleNum)
	if err := handler.Set(ctx, udpPath, udpRange); err != nil {
		logger.GetLogger().Warn("Failed to set DPU UDP port range via gNMI", "moduleNum", moduleNum, "error", err)
		return fmt.Errorf("set DPU port range: %w", err)
	}
	return nil
}

// DeleteDpuPortRange deletes control plane port ranges for a DPU via gNMI DELETE (gnmi.md DELETE #7).
func (s *dpuStore) DeleteDpuPortRange(ctx context.Context, moduleNum int) error {
	s.mu.RLock()
	handler := s.gnmiHandler
	s.mu.RUnlock()

	if handler == nil {
		return nil
	}

	tcpPath := fmt.Sprintf(paths.DPUStoreTCPPorts, moduleNum)
	if err := handler.Delete(ctx, tcpPath); err != nil {
		logger.GetLogger().Warn("Failed to delete DPU TCP port range via gNMI", "moduleNum", moduleNum, "error", err)
		return fmt.Errorf("delete DPU port range: %w", err)
	}

	udpPath := fmt.Sprintf(paths.DPUStoreUDPPorts, moduleNum)
	if err := handler.Delete(ctx, udpPath); err != nil {
		logger.GetLogger().Warn("Failed to delete DPU UDP port range via gNMI", "moduleNum", moduleNum, "error", err)
		return fmt.Errorf("delete DPU port range: %w", err)
	}
	return nil
}
