// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package storage

import (
	"context"
	"sync"

	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

// MemoryStorage implements Storage using in-memory maps.
// This is useful for testing and environments where persistence is not needed.
type MemoryStorage struct {
	mu     sync.RWMutex
	vrfs   map[string]types.VRF
	vlans  map[string]types.VLAN
	dpus   map[string]types.DPU
	device *DeviceState
	ha     *HAState
}

// NewMemoryStorage creates a new MemoryStorage.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		vrfs:  make(map[string]types.VRF),
		vlans: make(map[string]types.VLAN),
		dpus:  make(map[string]types.DPU),
	}
}

// EnsureReady is a no-op for memory storage.
func (ms *MemoryStorage) EnsureReady(ctx context.Context) error {
	return nil
}

// LoadVRFs returns the stored VRF data.
func (ms *MemoryStorage) LoadVRFs(ctx context.Context) (map[string]types.VRF, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	if len(ms.vrfs) == 0 {
		return nil, &ErrNotFound{Key: "vrfs"}
	}

	// Return a copy to prevent external modification
	result := make(map[string]types.VRF, len(ms.vrfs))
	for k, v := range ms.vrfs {
		result[k] = v
	}
	return result, nil
}

// SaveVRFs stores VRF data in memory.
func (ms *MemoryStorage) SaveVRFs(ctx context.Context, vrfs map[string]types.VRF) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	// Store a copy to prevent external modification
	ms.vrfs = make(map[string]types.VRF, len(vrfs))
	for k, v := range vrfs {
		ms.vrfs[k] = v
	}
	return nil
}

// LoadVLANs returns the stored VLAN data.
func (ms *MemoryStorage) LoadVLANs(ctx context.Context) (map[string]types.VLAN, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	if len(ms.vlans) == 0 {
		return nil, &ErrNotFound{Key: "vlans"}
	}

	// Return a copy to prevent external modification
	result := make(map[string]types.VLAN, len(ms.vlans))
	for k, v := range ms.vlans {
		result[k] = v
	}
	return result, nil
}

// SaveVLANs stores VLAN data in memory.
func (ms *MemoryStorage) SaveVLANs(ctx context.Context, vlans map[string]types.VLAN) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	// Store a copy to prevent external modification
	ms.vlans = make(map[string]types.VLAN, len(vlans))
	for k, v := range vlans {
		ms.vlans[k] = v
	}
	return nil
}

// LoadDevice returns the stored device state.
func (ms *MemoryStorage) LoadDevice(ctx context.Context) (*DeviceState, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	if ms.device == nil {
		return nil, &ErrNotFound{Key: "device"}
	}

	// Return a copy
	state := *ms.device
	return &state, nil
}

// SaveDevice stores device state in memory.
func (ms *MemoryStorage) SaveDevice(ctx context.Context, state *DeviceState) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	// Store a copy
	s := *state
	ms.device = &s
	return nil
}

// LoadHA returns the stored HA state.
func (ms *MemoryStorage) LoadHA(ctx context.Context) (*HAState, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	if ms.ha == nil {
		return nil, &ErrNotFound{Key: "ha"}
	}

	state := &HAState{
		Enabled:     ms.ha.Enabled,
		SwitchState: ms.ha.SwitchState,
		HaIP:        ms.ha.HaIP,
		HaPort:      ms.ha.HaPort,
	}
	if len(ms.ha.PeerIPs) > 0 {
		state.PeerIPs = append([]string(nil), ms.ha.PeerIPs...)
	}
	return state, nil
}

// SaveHA stores HA state in memory.
func (ms *MemoryStorage) SaveHA(ctx context.Context, state *HAState) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	s := &HAState{
		Enabled:     state.Enabled,
		SwitchState: state.SwitchState,
		HaIP:        state.HaIP,
		HaPort:      state.HaPort,
	}
	if len(state.PeerIPs) > 0 {
		s.PeerIPs = append([]string(nil), state.PeerIPs...)
	}
	ms.ha = s
	return nil
}

// LoadDPUs returns the stored DPU data.
func (ms *MemoryStorage) LoadDPUs(ctx context.Context) (map[string]types.DPU, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	if len(ms.dpus) == 0 {
		return nil, &ErrNotFound{Key: "dpus"}
	}

	// Return a copy to prevent external modification
	result := make(map[string]types.DPU, len(ms.dpus))
	for k, v := range ms.dpus {
		result[k] = v
	}
	return result, nil
}

// SaveDPUs stores DPU data in memory.
func (ms *MemoryStorage) SaveDPUs(ctx context.Context, dpus map[string]types.DPU) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	// Store a copy to prevent external modification
	ms.dpus = make(map[string]types.DPU, len(dpus))
	for k, v := range dpus {
		ms.dpus[k] = v
	}
	return nil
}

// Clear removes all stored data.
func (ms *MemoryStorage) Clear(ctx context.Context) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.vrfs = make(map[string]types.VRF)
	ms.vlans = make(map[string]types.VLAN)
	ms.dpus = make(map[string]types.DPU)
	ms.device = nil
	ms.ha = nil
	return nil
}

// FlushAll is a no-op for memory storage since all operations are synchronous.
func (ms *MemoryStorage) FlushAll(ctx context.Context) error {
	return nil
}

// Ensure MemoryStorage implements Storage.
var _ Storage = (*MemoryStorage)(nil)
