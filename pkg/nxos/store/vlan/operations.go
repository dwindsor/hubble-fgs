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
	"strconv"
	"strings"

	"github.com/isovalent/hubble-fgs/pkg/nxos/store"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

// parseVLANID extracts the integer ID from a VLAN name (e.g. "vlan-100" → 100).
// Returns 0 if the name does not match the expected format.
func parseVLANID(name string) uint16 {
	s, ok := strings.CutPrefix(name, "vlan-")
	if !ok {
		return 0
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(n)
}

// handleActivateLocked checks whether the VLAN should be active, assigns
// pinning if so, and stores the result. Returns (vlan, oldActive).
// Use vlan.Active for current state.
// Must be called with the write lock held.
func (s *vlanStore) handleActivateLocked(vlan types.VLAN, oldVLAN *types.VLAN) (types.VLAN, bool) {
	var oldActive bool
	if oldVLAN != nil {
		oldActive = oldVLAN.Active
	}

	shouldBeActive := vlan.Global && vlan.Service && vlan.HasAffinity

	if shouldBeActive {
		vlan.Active = true
		vlan = s.assignPinningLocked(vlan)
	} else {
		vlan.Active = false
		if oldVLAN != nil && oldVLAN.Active {
			vlan.DPUPinned = 0
		}
	}

	s.vlans[vlan.Name] = vlan
	return vlan, oldActive
}

func (s *vlanStore) SetGlobal(ctx context.Context, name string, isGlobal bool) error {
	s.mu.Lock()
	vlan, exists := s.vlans[name]
	var oldVLAN *types.VLAN
	if exists {
		old := vlan
		oldVLAN = &old
		if vlan.Global == isGlobal {
			s.mu.Unlock()
			return nil
		}
	}
	vlan.Name = name
	vlan.Global = isGlobal
	if !exists && vlan.ID == 0 {
		vlan.ID = parseVLANID(name)
	}

	// Auto-remove: if both flags are now false, delete the entry entirely.
	if !vlan.Global && !vlan.Service {
		if !exists {
			s.mu.Unlock()
			return nil
		}
		delete(s.vlans, name)
		s.mu.Unlock()
		s.notify(Event{Type: store.EventDeleted, VLAN: vlan, OldVLAN: oldVLAN})
		s.persist(ctx)
		s.cleanupRedirects(ctx, name)
		s.programRedirects(ctx)
		return nil
	}

	vlan, oldActive := s.handleActivateLocked(vlan, oldVLAN)
	s.mu.Unlock()

	eventType := store.EventUpdated
	if !exists {
		eventType = store.EventCreated
	}
	s.notify(Event{Type: eventType, VLAN: vlan, OldVLAN: oldVLAN})
	s.persist(ctx)

	switch {
	case !oldActive && vlan.Active:
		s.programRedirects(ctx)
	case oldActive && !vlan.Active:
		s.cleanupRedirects(ctx, vlan.Name)
	}
	return nil
}

func (s *vlanStore) SetService(ctx context.Context, name string, isService bool) error {
	s.mu.Lock()
	vlan, exists := s.vlans[name]
	var oldVLAN *types.VLAN
	if exists {
		old := vlan
		oldVLAN = &old
		if vlan.Service == isService {
			s.mu.Unlock()
			return nil
		}
	}
	vlan.Name = name
	vlan.Service = isService
	if !exists && vlan.ID == 0 {
		vlan.ID = parseVLANID(name)
	}

	// When removing service, also clear affinity (logically coupled — affinity
	// is part of the service VLAN config and goes away with it).
	if !isService {
		vlan.HasAffinity = false
		vlan.Affinity = 0
	}

	// Auto-remove: if both flags are now false, delete the entry entirely.
	if !vlan.Global && !vlan.Service {
		if !exists {
			s.mu.Unlock()
			return nil
		}
		delete(s.vlans, name)
		s.mu.Unlock()
		s.notify(Event{Type: store.EventDeleted, VLAN: vlan, OldVLAN: oldVLAN})
		s.persist(ctx)
		s.cleanupRedirects(ctx, name)
		s.programRedirects(ctx)
		return nil
	}

	vlan, oldActive := s.handleActivateLocked(vlan, oldVLAN)
	s.mu.Unlock()

	eventType := store.EventUpdated
	if !exists {
		eventType = store.EventCreated
	}
	s.notify(Event{Type: eventType, VLAN: vlan, OldVLAN: oldVLAN})
	s.persist(ctx)

	switch {
	case !oldActive && vlan.Active:
		s.programRedirects(ctx)
	case oldActive && !vlan.Active:
		s.cleanupRedirects(ctx, vlan.Name)
	}
	return nil
}

func (s *vlanStore) SetAffinity(ctx context.Context, name string, affinity uint16) error {
	s.mu.Lock()
	vlan, exists := s.vlans[name]
	var oldVLAN *types.VLAN
	if exists {
		old := vlan
		oldVLAN = &old
		if vlan.HasAffinity && vlan.Affinity == affinity {
			s.mu.Unlock()
			return nil
		}
	}
	vlan.Name = name
	vlan.HasAffinity = true
	vlan.Affinity = affinity

	vlan, oldActive := s.handleActivateLocked(vlan, oldVLAN)
	s.mu.Unlock()

	eventType := store.EventUpdated
	if !exists {
		eventType = store.EventCreated
	}
	s.notify(Event{Type: eventType, VLAN: vlan, OldVLAN: oldVLAN})
	s.persist(ctx)

	switch {
	case !oldActive && vlan.Active:
		s.programRedirects(ctx)
	case oldActive && !vlan.Active:
		s.cleanupRedirects(ctx, vlan.Name)
	}
	return nil
}

func (s *vlanStore) SetPinning(ctx context.Context, name string, dpuPinned uint16) error {
	s.mu.Lock()
	vlan, exists := s.vlans[name]
	if !exists {
		s.mu.Unlock()
		return &ErrNotFound{Name: name}
	}
	old := vlan
	vlan.DPUPinned = dpuPinned
	s.vlans[name] = vlan
	s.mu.Unlock()

	s.notify(Event{Type: store.EventUpdated, VLAN: vlan, OldVLAN: &old})
	s.persist(ctx)
	return nil
}
