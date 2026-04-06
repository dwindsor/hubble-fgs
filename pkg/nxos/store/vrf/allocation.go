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
	"hash/fnv"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/openconfig/ygot/ygot"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
	model "github.com/isovalent/hubble-fgs/pkg/nxosmodel"
)

const (
	// DefaultVRFName is the name of the default VRF.
	DefaultVRFName = "default"
	// DefaultVRFGID is the reserved GID for the default VRF.
	DefaultVRFGID = 1
	// GIDAllocationStart is the starting GID for non-default VRFs.
	GIDAllocationStart = 10
	// GIDAllocationMax is the maximum valid GID value. Allocation wraps around
	// back to GIDAllocationStart after reaching this value.
	GIDAllocationMax = 4095
)

// rebuildGIDStateLocked reconstructs the GID allocation state from loaded VRFs.
// Called during initialization before any concurrent access.
// Note: Active VRFs without GIDs are NOT allocated here - that's handled by
// RestoreGIDsFromGnmi which reads the actual switch configuration.
func (s *vrfStore) rebuildGIDStateLocked() {
	var maxGID uint16
	for name, vrf := range s.vrfs {
		if vrf.GID > 0 {
			s.gidsInUse[vrf.GID]++
			if vrf.GID >= maxGID {
				maxGID = vrf.GID
			}
			// Backward compat: set Preset = GID for VRFs loaded from old storage
			// (pre-Preset field) so reconcilePresets does not treat them as needing change.
			if vrf.Preset == 0 {
				vrf.Preset = vrf.GID
				s.vrfs[name] = vrf
			}
		} else if vrf.Preset > 0 {
			// Skeleton VRF: count its reserved Preset in gidsInUse.
			s.gidsInUse[vrf.Preset]++
		}
	}
	// Set nextGID to one past the maximum allocated, with wrap-around
	if maxGID > 0 {
		s.nextGID = maxGID + 1
		if s.nextGID > GIDAllocationMax {
			s.nextGID = GIDAllocationStart
		}
	}
}

// allocateGIDLocked assigns the next available GID to the VRF.
// Must be called with write lock held.
//
// Allocation order:
//  1. GID already set → return unchanged.
//  2. "default" VRF → GID=1, Preset=1.
//  3. Preset > 0 and not in gidsInUse → use Preset as GID.
//  4. Sequential scan: skip GIDs in gidsInUse OR claimed as Preset by another VRF.
//     Sets both GID and Preset to the allocated value.
func (s *vrfStore) allocateGIDLocked(vrf types.VRF) types.VRF {
	if vrf.GID > 0 {
		return vrf
	}

	// Special case: "default" VRF always gets GID 1.
	if vrf.Name == DefaultVRFName {
		vrf.GID = DefaultVRFGID
		vrf.Preset = DefaultVRFGID
		s.gidsInUse[DefaultVRFGID]++
		return vrf
	}

	// Honor Preset if no other VRF actively holds it.
	// A refcount of 1 in gidsInUse may come from this VRF's own skeleton reservation
	// (via ReservePreset); the skeleton → active transition reuses that slot.
	if vrf.Preset > 0 {
		otherHasIt := false
		for otherName, otherVRF := range s.vrfs {
			if otherName != vrf.Name && otherVRF.GID == vrf.Preset {
				otherHasIt = true
				break
			}
		}
		if !otherHasIt {
			vrf.GID = vrf.Preset
			if s.gidsInUse[vrf.Preset] == 0 {
				s.gidsInUse[vrf.Preset]++ // fresh allocation
			}
			// else: skeleton reservation (refcount=1) transitions to active GID — no change
			if s.nextGID <= vrf.Preset {
				s.nextGID = vrf.Preset + 1
				if s.nextGID > GIDAllocationMax {
					s.nextGID = GIDAllocationStart
				}
			}
			return vrf
		}
	}

	// Sequential allocation: skip GIDs in use OR claimed as Preset by another VRF.
	gid := s.nextGID
	start := gid
	for {
		if s.gidsInUse[gid] == 0 {
			// Check if any other VRF claims this as a preset
			presetClaimed := false
			for otherName, otherVRF := range s.vrfs {
				if otherName != vrf.Name && otherVRF.Preset == gid {
					presetClaimed = true
					break
				}
			}
			if !presetClaimed {
				break
			}
		}
		gid++
		if gid > GIDAllocationMax {
			gid = GIDAllocationStart
		}
		if gid == start {
			// All GIDs exhausted
			return vrf
		}
	}
	vrf.GID = gid
	vrf.Preset = gid
	s.gidsInUse[gid]++
	s.nextGID = gid + 1
	if s.nextGID > GIDAllocationMax {
		s.nextGID = GIDAllocationStart
	}
	return vrf
}

// reconcilePresets applies pending Preset→GID transitions for all active VRFs
// where GID != Preset. Uses two-phase batching and in-place endpoint updates
// to avoid teardown+rebuild and transient GID conflicts.
func (s *vrfStore) reconcilePresets(ctx context.Context) error {
	type entry struct {
		oldGID uint16
		vrf    types.VRF // snapshot with updated GID
	}

	s.mu.Lock()

	var entries []entry
	for _, vrf := range s.vrfs {
		if !vrf.Active || vrf.Preset == 0 || vrf.GID == vrf.Preset {
			continue
		}
		entries = append(entries, entry{oldGID: vrf.GID, vrf: vrf})
	}

	if len(entries) == 0 {
		s.mu.Unlock()
		return nil
	}

	// Free all old GIDs first to avoid blocking new GID assignments.
	for _, e := range entries {
		if e.oldGID > 0 {
			s.gidsInUse[e.oldGID]--
			if s.gidsInUse[e.oldGID] <= 0 {
				delete(s.gidsInUse, e.oldGID)
			}
		}
	}
	// Assign new GIDs and capture updated VRF snapshots.
	for i, e := range entries {
		vrf := e.vrf
		vrf.GID = vrf.Preset
		s.gidsInUse[vrf.Preset]++
		s.vrfs[vrf.Name] = vrf
		entries[i].vrf = vrf
		logger.GetLogger().Info("Applying preset GID change", "vrf", vrf.Name, "oldGID", e.oldGID, "newGID", vrf.GID)
	}

	handler := s.gnmiHandler
	inService := s.inService
	s.mu.Unlock()

	if handler == nil || !inService {
		return nil
	}

	// Two-phase batching: contested GIDs first (their old GID is needed by another VRF),
	// then non-contested. This prevents transient GID conflicts.
	newGIDs := make(map[uint16]bool)
	for _, e := range entries {
		newGIDs[e.vrf.GID] = true
	}

	var batch1, batch2 []types.VRF
	for _, e := range entries {
		if newGIDs[e.oldGID] {
			batch1 = append(batch1, e.vrf) // contested
		} else {
			batch2 = append(batch2, e.vrf) // non-contested
		}
	}

	if err := s.sendGIDUpdateBatch(ctx, handler, batch1); err != nil {
		return err
	}
	return s.sendGIDUpdateBatch(ctx, handler, batch2)
}

// sendGIDUpdateBatch issues a single gNMI SET that updates only the VLAN (GID) field
// on existing service endpoints. Does NOT set Type or Vrf fields — preserved by MERGE.
func (s *vrfStore) sendGIDUpdateBatch(ctx context.Context, handler gnmi.GnmiHandler, vrfs []types.VRF) error {
	if len(vrfs) == 0 {
		return nil
	}

	serviceItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems{
		ServiceList: make(map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList),
	}

	for _, vrf := range vrfs {
		svcName := fmt.Sprintf("__%s_dpu_redir", vrf.Name)
		gid := vrf.GID
		dpuNum := model.Cisco_NX_OSDevice_Sas_SvcModulePinning_all
		if vrf.DPUPinned > 0 && s.isPinningActive() {
			dpuNum = dpuToModulePinning(vrf.DPUPinned)
		}
		serviceItems.ServiceList[svcName] = &model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList{
			Name: &svcName,
			DpuepItems: &model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems{
				SvcEndPointDpuList: map[model.E_Cisco_NX_OSDevice_Sas_SvcModulePinning]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems_SvcEndPointDpuList{
					dpuNum: {Vlan: &gid, DpuNum: dpuNum},
				},
			},
		}
	}

	jstr, err := ygot.EmitJSON(&serviceItems, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		return fmt.Errorf("failed to marshal GID update batch: %w", err)
	}
	if err := handler.Set(ctx, paths.ServiceRedirServiceItems, jstr); err != nil {
		return fmt.Errorf("failed to send GID update batch via gNMI: %w", err)
	}
	return nil
}

// assignPinningLocked sets DPUPinned based on lb mode and VRF affinity.
//
// Symmetric hash mode (!isPinningActive):
//   - DPUPinned is always set to 65535 (all DPUs)
//   - Logs an error if affinity is non-zero (misconfiguration)
//
// Pinning mode (isPinningActive):
//   - Affinity 1..dpuCount → direct DPU assignment
//   - Affinity > dpuCount → invalid, log warning, fall back to FNV-1a
//   - Affinity 0 → FNV-1a hash to distribute across DPUs
//
// Must be called with write lock held.
func (s *vrfStore) assignPinningLocked(vrf types.VRF) types.VRF {
	if !s.isPinningActive() {
		// Symmetric hash mode: all VRFs use dpu_all redirect
		if vrf.Affinity != 0 {
			logger.GetLogger().Error("VRF has non-zero affinity in symmetric hash mode",
				"vrf", vrf.Name, "affinity", vrf.Affinity)
		}
		vrf.DPUPinned = 65535
		return vrf
	}
	// Pinning mode
	if vrf.Affinity >= 1 {
		if s.dpuCount > 0 && vrf.Affinity > s.dpuCount {
			logger.GetLogger().Warn("VRF affinity exceeds DPU count, using FNV-1a",
				"vrf", vrf.Name, "affinity", vrf.Affinity, "dpuCount", s.dpuCount)
		} else {
			vrf.DPUPinned = vrf.Affinity
			return vrf
		}
	}
	// Affinity 0 or out-of-range fallback: FNV-1a hash
	if s.dpuCount > 0 {
		vrf.DPUPinned = 1 + uint16(fnv1a([]byte(vrf.Name))%uint64(s.dpuCount))
	} else {
		vrf.DPUPinned = 0
	}
	return vrf
}

// fnv1a computes an FNV-1a 64-bit hash. Used to distribute dynamic VRFs
// across DPUs deterministically.
func fnv1a(buf []byte) uint64 {
	h := fnv.New64a()
	h.Write(buf)
	return h.Sum64()
}
