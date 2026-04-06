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

	// Extract VRF names, GIDs, and all DPU keys from ServiceList.
	s.mu.Lock()
	defer s.mu.Unlock()

	type switchVRFState struct {
		gid  uint16
		dpus []uint16 // all DPU enum keys found on the switch
	}
	switchVRFs := make(map[string]switchVRFState)

	var maxGID uint16
	restoredCount := 0
	for name, svc := range items.ServiceList {
		if svc == nil || svc.DpuepItems == nil || svc.Type != model.Cisco_NX_OSDevice_Epbr_EpbrType_dpu {
			continue
		}
		// Extract VRF name from service name "__<vrfname>_dpu_redir"
		vrfName := strings.TrimPrefix(name, "__")
		vrfName = strings.TrimSuffix(vrfName, "_dpu_redir")

		state := switchVRFs[vrfName]
		gidFound := false
		for dpuEnum, ep := range svc.DpuepItems.SvcEndPointDpuList {
			dpuKey := modulePinningToDPU(dpuEnum)
			state.dpus = append(state.dpus, dpuKey)
			if ep != nil && ep.Vlan != nil && !gidFound {
				gid := *ep.Vlan
				state.gid = gid
				gidFound = true
				if gid > maxGID {
					maxGID = gid
				}
				// Update VRF if it exists in store
				if vrf, ok := s.vrfs[vrfName]; ok {
					// Decrement old refcounts before overwriting.
					if vrf.GID > 0 && vrf.GID != gid {
						s.gidsInUse[vrf.GID]--
						if s.gidsInUse[vrf.GID] <= 0 {
							delete(s.gidsInUse, vrf.GID)
						}
					}
					if vrf.GID == 0 && vrf.Preset > 0 && vrf.Preset != gid {
						// Skeleton preset being replaced by actual GID from switch.
						s.gidsInUse[vrf.Preset]--
						if s.gidsInUse[vrf.Preset] <= 0 {
							delete(s.gidsInUse, vrf.Preset)
						}
					}
					s.gidsInUse[gid]++
					vrf.GID = gid
					vrf.Preset = gid
					s.vrfs[vrfName] = vrf
					restoredCount++
				} else {
					s.gidsInUse[gid]++
				}
			}
		}
		switchVRFs[vrfName] = state
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

	// Delete stale DPU endpoints for VRFs whose DPU pinning has changed.
	// gNMI MERGE adds new DPU keys but doesn't remove old ones.
	// Mirrors hubble-fgs/pkg/nxos/nxos.go:933-939.
	repinCount := 0
	for vrfName, switchState := range switchVRFs {
		if !activeVRFs[vrfName] {
			continue // already handled by stale cleanup above
		}
		vrf := s.vrfs[vrfName]
		for _, switchDPU := range switchState.dpus {
			if !dpuMatchesDesired(switchDPU, vrf.DPUPinned) {
				s.deleteDpuEndpoint(ctx, handler, vrfName, switchDPU)
				repinCount++
			}
		}
	}
	if repinCount > 0 {
		logger.GetLogger().Info("Deleted stale DPU endpoints due to repinning", "count", repinCount)
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

// dpuMatchesDesired returns true if the given switchDPU key (from the switch state)
// matches the desired DPUPinned value.
//   - DPUPinned == 0: no endpoint expected, delete all (returns false for any switchDPU)
//   - DPUPinned == 65535: "all" mode, only key 0 ("all") is correct
//   - DPUPinned == 1..4: pinning mode, only the matching key is correct
func dpuMatchesDesired(switchDPU uint16, dpuPinned uint16) bool {
	switch dpuPinned {
	case 0:
		return false // no endpoint expected
	case 65535:
		return switchDPU == 0 // "all" mode: only the "all" key (0) is correct
	default:
		return switchDPU == dpuPinned
	}
}
