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

	"github.com/isovalent/hubble-fgs/pkg/nxos/store"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

// handleActivateLocked checks whether the VRF should be active, allocates
// resources (GID, pinning) if so, and stores the result.
// Returns (vrf, oldActive, oldDPUPinned). Use vrf.Active for current state.
// Must be called with the write lock held.
func (s *vrfStore) handleActivateLocked(vrf types.VRF, oldVRF *types.VRF) (types.VRF, bool, uint16) {
	var oldActive bool
	var oldDPUPinned uint16
	if oldVRF != nil {
		oldActive = oldVRF.Active
		oldDPUPinned = oldVRF.DPUPinned
	}

	shouldBeActive := vrf.Global && vrf.Service && vrf.HasAffinity

	if shouldBeActive {
		vrf.Active = true
		vrf = s.allocateGIDLocked(vrf)
		vrf = s.assignPinningLocked(vrf)
	} else {
		vrf.Active = false
		if oldVRF != nil && oldVRF.Active {
			// Free the GID allocation so it can be reused, but keep Preset
			// intact so re-activation honors the same GID.
			if vrf.GID > 0 {
				s.gidsInUse[vrf.GID]--
				if s.gidsInUse[vrf.GID] <= 0 {
					delete(s.gidsInUse, vrf.GID)
				}
				vrf.GID = 0
			}
			vrf.DPUPinned = 0
		}
	}

	s.vrfs[vrf.Name] = vrf
	return vrf, oldActive, oldDPUPinned
}

func (s *vrfStore) SetGlobal(ctx context.Context, name string, isGlobal bool) error {
	s.mu.Lock()
	vrf, exists := s.vrfs[name]
	var oldVRF *types.VRF
	if exists {
		old := vrf
		oldVRF = &old
		if vrf.Global == isGlobal {
			s.mu.Unlock()
			return nil
		}
	}
	vrf.Name = name
	vrf.Global = isGlobal

	// Auto-remove: if both flags are now false, delete the entry entirely.
	if !vrf.Global && !vrf.Service {
		if !exists {
			s.mu.Unlock()
			return nil
		}
		// Free skeleton preset refcount if this was a skeleton VRF.
		if vrf.GID == 0 && vrf.Preset > 0 {
			s.gidsInUse[vrf.Preset]--
			if s.gidsInUse[vrf.Preset] <= 0 {
				delete(s.gidsInUse, vrf.Preset)
			}
		}
		delete(s.vrfs, name)
		s.mu.Unlock()
		s.notify(Event{Type: store.EventDeleted, VRF: vrf, OldVRF: oldVRF})
		s.persist(ctx)
		s.cleanupRedirects(ctx, name)
		return nil
	}

	vrf, oldActive, oldDPUPinned := s.handleActivateLocked(vrf, oldVRF)
	s.mu.Unlock()

	eventType := store.EventUpdated
	if !exists {
		eventType = store.EventCreated
	}
	s.notify(Event{Type: eventType, VRF: vrf, OldVRF: oldVRF})
	s.persist(ctx)

	switch {
	case !oldActive && vrf.Active:
		s.programRedirects(ctx, vrf)
	case oldActive && !vrf.Active:
		s.cleanupRedirects(ctx, vrf.Name)
	case oldActive && vrf.Active && oldDPUPinned != vrf.DPUPinned:
		s.deleteDpuEndpointForRepin(ctx, vrf.Name, oldDPUPinned)
		s.repinRedirects(ctx, vrf)
	}
	return nil
}

func (s *vrfStore) SetService(ctx context.Context, name string, isService bool) error {
	s.mu.Lock()
	vrf, exists := s.vrfs[name]
	var oldVRF *types.VRF
	if exists {
		old := vrf
		oldVRF = &old
		if vrf.Service == isService {
			s.mu.Unlock()
			return nil
		}
	}
	vrf.Name = name
	vrf.Service = isService

	// When removing service, also clear affinity (logically coupled — affinity
	// is part of the service VRF config and goes away with it).
	if !isService {
		vrf.HasAffinity = false
		vrf.Affinity = 0
	}

	// Auto-remove: if both flags are now false, delete the entry entirely.
	if !vrf.Global && !vrf.Service {
		if !exists {
			s.mu.Unlock()
			return nil
		}
		// Free skeleton preset refcount if this was a skeleton VRF.
		if vrf.GID == 0 && vrf.Preset > 0 {
			s.gidsInUse[vrf.Preset]--
			if s.gidsInUse[vrf.Preset] <= 0 {
				delete(s.gidsInUse, vrf.Preset)
			}
		}
		delete(s.vrfs, name)
		s.mu.Unlock()
		s.notify(Event{Type: store.EventDeleted, VRF: vrf, OldVRF: oldVRF})
		s.persist(ctx)
		s.cleanupRedirects(ctx, name)
		return nil
	}

	vrf, oldActive, oldDPUPinned := s.handleActivateLocked(vrf, oldVRF)
	s.mu.Unlock()

	eventType := store.EventUpdated
	if !exists {
		eventType = store.EventCreated
	}
	s.notify(Event{Type: eventType, VRF: vrf, OldVRF: oldVRF})
	s.persist(ctx)

	switch {
	case !oldActive && vrf.Active:
		s.programRedirects(ctx, vrf)
	case oldActive && !vrf.Active:
		s.cleanupRedirects(ctx, vrf.Name)
	case oldActive && vrf.Active && oldDPUPinned != vrf.DPUPinned:
		s.deleteDpuEndpointForRepin(ctx, vrf.Name, oldDPUPinned)
		s.repinRedirects(ctx, vrf)
	}
	return nil
}

func (s *vrfStore) SetAffinity(ctx context.Context, name string, affinity uint16) error {
	s.mu.Lock()
	vrf, exists := s.vrfs[name]
	var oldVRF *types.VRF
	if exists {
		old := vrf
		oldVRF = &old
		if vrf.HasAffinity && vrf.Affinity == affinity {
			s.mu.Unlock()
			return nil
		}
	}
	vrf.Name = name
	vrf.HasAffinity = true
	vrf.Affinity = affinity

	vrf, oldActive, oldDPUPinned := s.handleActivateLocked(vrf, oldVRF)
	s.mu.Unlock()

	eventType := store.EventUpdated
	if !exists {
		eventType = store.EventCreated
	}
	s.notify(Event{Type: eventType, VRF: vrf, OldVRF: oldVRF})
	s.persist(ctx)

	switch {
	case !oldActive && vrf.Active:
		s.programRedirects(ctx, vrf)
	case oldActive && !vrf.Active:
		s.cleanupRedirects(ctx, vrf.Name)
	case oldActive && vrf.Active && oldDPUPinned != vrf.DPUPinned:
		s.deleteDpuEndpointForRepin(ctx, vrf.Name, oldDPUPinned)
		s.repinRedirects(ctx, vrf)
	}
	return nil
}
