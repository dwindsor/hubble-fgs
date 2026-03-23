// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package vlan

import (
	"context"

	"github.com/cilium/tetragon/pkg/logger"
	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
)

// HandleGnmiNotification processes a gNMI notification for VLAN state.
func (s *vlanStore) HandleGnmiNotification(ctx context.Context, path string, update *gnmiproto.Update, isDelete bool) {
	logger.GetLogger().Debug("====VLAN GNMI====", "isDelete", isDelete, "path", path, "update", update)

	switch {
	case paths.PathMatches(path, paths.VlanStoreGlobalVlanName), paths.PathMatches(path, paths.VlanStoreGlobalVlan):
		if isDelete {
			vlanName, ok := paths.ExtractVLANEncap(path)
			if !ok {
				logger.GetLogger().Debug("Could not extract VLAN name from path", "path", path)
				return
			}
			if err := s.SetGlobal(ctx, vlanName, false); err != nil {
				logger.GetLogger().Error("Failed to clear VLAN global flag from notification", "vlan", vlanName, "error", err)
			} else {
				logger.GetLogger().Debug("VLAN global flag cleared via gNMI notification", "vlan", vlanName)
			}
		} else {
			value := update.GetVal()
			if vlanName, ok := gnmi.ExtractStringValue(value); ok {
				if vlanName != "" {
					if err := s.SetGlobal(ctx, vlanName, true); err != nil {
						logger.GetLogger().Error("Failed to set VLAN global from notification", "vlan", vlanName, "error", err)
					} else {
						logger.GetLogger().Debug("VLAN updated via gNMI notification", "vlan", vlanName)
					}
				}
			}
		}

	case paths.PathMatches(path, paths.VlanStoreServiceVlanName):
		value := update.GetVal()
		if vlanName, ok := gnmi.ExtractStringValue(value); ok {
			if vlanName != "" {
				if err := s.SetService(ctx, vlanName, true); err != nil {
					logger.GetLogger().Error("Failed to set VLAN service from notification", "vlan", vlanName, "error", err)
				} else {
					logger.GetLogger().Debug("VLAN service updated via gNMI notification", "vlan", vlanName)
				}
			}
		}

	case paths.PathMatches(path, paths.VlanStoreServiceVlanAffinity):
		vlanID, ok := paths.ExtractVLANId(path)
		if !ok {
			logger.GetLogger().Debug("Could not extract VLAN ID from fwpolicy path", "path", path)
			return
		}
		value := update.GetVal()
		if affinityVal, ok := gnmi.ExtractUint32Value(value); ok {
			if err := s.SetAffinity(ctx, vlanID, uint16(affinityVal)); err != nil {
				logger.GetLogger().Error("Failed to update VLAN affinity from notification", "vlan", vlanID, "error", err)
			} else {
				logger.GetLogger().Debug("VLAN affinity updated via gNMI notification", "vlan", vlanID, "affinity", affinityVal)
			}
		}

	case paths.PathMatches(path, paths.VlanStoreServiceVlan):
		if isDelete {
			vlanID, ok := paths.ExtractVLANId(path)
			if !ok {
				logger.GetLogger().Debug("Could not extract VLAN ID from fwpolicy path", "path", path)
				return
			}
			if err := s.SetService(ctx, vlanID, false); err != nil {
				logger.GetLogger().Error("Failed to clear VLAN service flag from notification", "vlan", vlanID, "error", err)
			} else {
				logger.GetLogger().Debug("VLAN service flag cleared via gNMI notification", "vlan", vlanID)
			}
		}

	default:
		logger.GetLogger().Debug("Failed to handle VLAN gNMI notification", "isDelete", isDelete, "path", path, "value", update)
	}
}
