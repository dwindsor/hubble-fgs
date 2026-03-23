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
	"hash/fnv"

	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
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
			s.gidsInUse[vrf.GID] = true
			if vrf.GID >= maxGID {
				maxGID = vrf.GID
			}
			// Backward compat: set Preset = GID for VRFs loaded from old storage
			// (pre-Preset field) so reconcilePresets does not treat them as needing change.
			if vrf.Preset == 0 {
				vrf.Preset = vrf.GID
				s.vrfs[name] = vrf
			}
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
		s.gidsInUse[DefaultVRFGID] = true
		return vrf
	}

	// Honor Preset if available and not already taken.
	if vrf.Preset > 0 && !s.gidsInUse[vrf.Preset] {
		vrf.GID = vrf.Preset
		s.gidsInUse[vrf.Preset] = true
		if s.nextGID <= vrf.Preset {
			s.nextGID = vrf.Preset + 1
			if s.nextGID > GIDAllocationMax {
				s.nextGID = GIDAllocationStart
			}
		}
		return vrf
	}

	// Sequential allocation: skip GIDs in use OR claimed as Preset by another VRF.
	gid := s.nextGID
	start := gid
	for {
		if !s.gidsInUse[gid] {
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
	s.gidsInUse[gid] = true
	s.nextGID = gid + 1
	if s.nextGID > GIDAllocationMax {
		s.nextGID = GIDAllocationStart
	}
	return vrf
}

// reconcilePresets applies pending Preset→GID transitions for all active VRFs
// where GID != Preset. It cleans up old redirects then programs new ones.
func (s *vrfStore) reconcilePresets(ctx context.Context) {
	type change struct {
		name   string
		oldGID uint16
		newVRF types.VRF
	}

	s.mu.Lock()

	var changes []change
	for name, vrf := range s.vrfs {
		if !vrf.Active {
			continue
		}
		if vrf.Preset > 0 && vrf.GID != vrf.Preset {
			changes = append(changes, change{
				name:   name,
				oldGID: vrf.GID,
				newVRF: vrf,
			})
		}
	}

	if len(changes) == 0 {
		s.mu.Unlock()
		return
	}

	// Free all old GIDs first to avoid blocking the new GID assignments.
	for _, c := range changes {
		if c.oldGID > 0 {
			delete(s.gidsInUse, c.oldGID)
		}
	}
	// Assign new GIDs.
	for i, c := range changes {
		c.newVRF.GID = c.newVRF.Preset
		s.gidsInUse[c.newVRF.Preset] = true
		s.vrfs[c.name] = c.newVRF
		changes[i] = c
	}

	s.mu.Unlock()

	// Cleanup old redirects, then program new ones.
	for _, c := range changes {
		logger.GetLogger().Info("Applying preset GID change", "vrf", c.name, "oldGID", c.oldGID, "newGID", c.newVRF.Preset)
		s.cleanupRedirects(ctx, c.name)
	}
	for _, c := range changes {
		if v, ok := s.Get(c.name); ok && v.Active {
			s.programRedirects(ctx, v)
		}
	}
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
