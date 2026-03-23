// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package vrf

import (
	"context"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"
)

// HandleGnmiNotification processes a gNMI notification for VRF state.
func (s *vrfStore) HandleGnmiNotification(ctx context.Context, path string, update *gnmiproto.Update, isDelete bool) {
	logger.GetLogger().Debug("====VRF GNMI====", "isDelete", isDelete, "path", path, "update", update)

	switch {
	case paths.PathMatches(path, paths.VrfStoreGlobalVrfName), paths.PathMatches(path, paths.VrfStoreGlobalVrf):
		if isDelete {
			vrfName, ok := paths.ExtractVRFInstName(path)
			if !ok {
				logger.GetLogger().Debug("Could not extract VRF name from path", "path", path)
				return
			}
			if err := s.SetGlobal(ctx, vrfName, false); err != nil {
				logger.GetLogger().Error("Failed to clear VRF global flag from notification", "vrf", vrfName, "error", err)
			} else {
				logger.GetLogger().Debug("VRF global flag cleared via gNMI notification", "vrf", vrfName)
			}
		} else {
			value := update.GetVal()
			if vrfName, ok := gnmi.ExtractStringValue(value); ok {
				if vrfName != "" {
					if err := s.SetGlobal(ctx, vrfName, true); err != nil {
						logger.GetLogger().Error("Failed to set VRF global from notification", "vrf", vrfName, "error", err)
					} else {
						logger.GetLogger().Debug("VRF updated via gNMI notification", "vrf", vrfName)
					}
				}
			}
		}

	case paths.PathMatches(path, paths.VrfStoreServiceVrfName), paths.PathMatches(path, paths.VrfStoreServiceVrf):
		if isDelete {
			vrfName, ok := paths.ExtractVRFDomName(path)
			if !ok {
				logger.GetLogger().Debug("Could not extract VRF name from fwpolicy path", "path", path)
				return
			}
			if err := s.SetService(ctx, vrfName, false); err != nil {
				logger.GetLogger().Error("Failed to clear VRF service flag from notification", "vrf", vrfName, "error", err)
			} else {
				logger.GetLogger().Debug("VRF service flag cleared via gNMI notification", "vrf", vrfName)
			}
		} else {
			value := update.GetVal()
			if vrfName, ok := gnmi.ExtractStringValue(value); ok {
				if vrfName != "" {
					if err := s.SetService(ctx, vrfName, true); err != nil {
						logger.GetLogger().Error("Failed to set VRF service from notification", "vrf", vrfName, "error", err)
					} else {
						logger.GetLogger().Debug("VRF service updated via gNMI notification", "vrf", vrfName)
					}
				}
			}
		}

	case paths.PathMatches(path, paths.VrfStoreServiceVrfAffinity):
		vrfName, ok := paths.ExtractVRFDomName(path)
		if !ok {
			logger.GetLogger().Debug("Could not extract VRF name from fwpolicy path", "path", path)
			return
		}
		value := update.GetVal()
		if affinityVal, ok := gnmi.ExtractUint32Value(value); ok {
			if err := s.SetAffinity(ctx, vrfName, uint16(affinityVal)); err != nil {
				logger.GetLogger().Error("Failed to update VRF affinity from notification", "vrf", vrfName, "error", err)
			} else {
				logger.GetLogger().Debug("VRF affinity updated via gNMI notification", "vrf", vrfName, "affinity", affinityVal)
			}
		}

	default:
		logger.GetLogger().Debug("Failed to handle VRF gNMI notification", "isDelete", isDelete, "path", path, "value", update)
	}
}
