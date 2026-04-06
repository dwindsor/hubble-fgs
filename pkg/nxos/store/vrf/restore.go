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
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/openconfig/ygot/ytypes"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
	model "github.com/isovalent/hubble-fgs/pkg/nxosmodel"
)

// RestoreGIDsFromGnmi reads existing service redirect configuration from gNMI
// and populates GIDs for VRFs that should have them. This ensures GID allocation
// matches what's actually configured on the switch after restart.
func (s *vrfStore) RestoreGIDsFromGnmi(ctx context.Context) error {
	s.mu.RLock()
	handler := s.gnmiHandler
	s.mu.RUnlock()
	if handler == nil {
		return nil // No handler, nothing to restore
	}

	// GET from paths.ServiceRedirServiceItems
	jstrs, err := handler.Get(ctx, paths.ServiceRedirServiceItems)
	if err != nil {
		return fmt.Errorf("failed to get service-items: %w", err)
	}
	if len(jstrs) == 0 || len(jstrs[0]) == 0 {
		logger.GetLogger().Debug("No existing service redirect configuration found")
		// No existing data - allocate GIDs to active VRFs
		s.mu.Lock()
		defer s.mu.Unlock()
		for name, vrf := range s.vrfs {
			if vrf.Active && vrf.GID == 0 {
				vrf = s.allocateGIDLocked(vrf)
				vrf = s.assignPinningLocked(vrf)
				s.vrfs[name] = vrf
			}
		}
		return nil
	}

	// Parse using model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems
	items := &model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems{}
	opts := []ytypes.UnmarshalOpt{&ytypes.IgnoreExtraFields{}}
	if err := model.Unmarshal([]byte(jstrs[0]), items, opts...); err != nil {
		return fmt.Errorf("failed to unmarshal service-items: %w", err)
	}

	// Extract VRF names and GIDs from ServiceList
	s.mu.Lock()
	defer s.mu.Unlock()

	var maxGID uint16
	restoredCount := 0
	switchVRFs := make(map[string]bool) // VRF names found on the switch
	for name, svc := range items.ServiceList {
		if svc == nil || svc.DpuepItems == nil || svc.Type != model.Cisco_NX_OSDevice_Epbr_EpbrType_dpu {
			continue
		}
		// Extract VRF name from service name "__<vrfname>_dpu_redir"
		vrfName := strings.TrimPrefix(name, "__")
		vrfName = strings.TrimSuffix(vrfName, "_dpu_redir")
		switchVRFs[vrfName] = true

		// Get GID from first endpoint with a VLAN value
		for _, ep := range svc.DpuepItems.SvcEndPointDpuList {
			if ep != nil && ep.Vlan != nil {
				gid := *ep.Vlan
				s.gidsInUse[gid] = true
				if gid > maxGID {
					maxGID = gid
				}
				// Update VRF if it exists in store
				if vrf, ok := s.vrfs[vrfName]; ok {
					vrf.GID = gid
					vrf.Preset = gid
					s.vrfs[vrfName] = vrf
					restoredCount++
				}
				break
			}
		}
	}

	if maxGID >= s.nextGID {
		s.nextGID = maxGID + 1
	}

	logger.GetLogger().Info("Restored GIDs from gNMI", "count", restoredCount, "maxGID", maxGID)

	// Delete stale VRF redirects that exist on the switch but are not active locally.
	// This handles crash recovery where Close() didn't run to clean up.
	activeVRFs := make(map[string]bool)
	for _, vrf := range s.vrfs {
		if vrf.Active {
			activeVRFs[vrf.Name] = true
		}
	}
	staleCount := 0
	for vrfName := range switchVRFs {
		if !activeVRFs[vrfName] {
			staleCount++
			logger.GetLogger().Warn("Cleaning up stale VRF redirect from previous run", "vrf", vrfName)
			s.cleanupRedirectsLocked(ctx, vrfName)
		}
	}
	if staleCount > 0 {
		logger.GetLogger().Info("Cleaned up stale VRF redirects", "count", staleCount)
	}

	// Allocate GIDs to any active VRFs that weren't found in gNMI
	for name, vrf := range s.vrfs {
		if vrf.Active && vrf.GID == 0 {
			vrf = s.allocateGIDLocked(vrf)
			vrf = s.assignPinningLocked(vrf)
			s.vrfs[name] = vrf
		}
	}

	return nil
}
