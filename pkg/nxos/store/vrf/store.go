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
	"sync"

	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/storage"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

// vrfStore implements Store with integrated persistence.
//
// Persistence contract: fields in this struct are NOT persisted by default.
// To persist a new field on types.VRF, you must ensure it is included in the
// types.VRF struct (storage/file.go serializes the whole VRF map). Struct-level
// fields of vrfStore (nextGID, gidsInUse, etc.) are NOT persisted — they are
// recomputed from the loaded VRF data in NewStore().
type vrfStore struct {
	mu          sync.RWMutex
	vrfs        map[string]types.VRF
	callbacks   map[int]func(Event)
	nextCbID    int
	storage     storage.Storage
	gnmiHandler gnmi.GnmiHandler
	// GID allocation state
	nextGID   uint16
	gidsInUse map[uint16]bool
	// DPU pinning configuration
	dpuCount        uint16      // number of DPUs for hash-based pinning
	isLbModePinning func() bool // returns true when per-DPU pinning is active
	// In-service gate: when false, reactive programRedirects no-ops.
	// Set to true when the device transitions to in-service.
	inService bool
	// HA-aware allocation: non-leader prefers peer GIDs to avoid conflicts.
	peerGIDs map[string]uint16 // peer's VRF→GID map (set by SetPeerGIDs)
	isLeader func() bool       // returns true if this node is HA leader
}

// Option configures Store.
type Option func(*vrfStore)

// WithStorage sets the storage backend for the VRF store.
func WithStorage(s storage.Storage) Option {
	return func(vs *vrfStore) {
		vs.storage = s
	}
}

// WithPreSeededGIDs sets GIDs that should be honored for named VRFs during
// allocation by creating skeleton VRF entries with the Preset field set.
// Seeds from --vrf-map are injected here so that the VRF store's GIDs match
// the policy layer.
func WithPreSeededGIDs(seeds map[string]uint16) Option {
	return func(vs *vrfStore) {
		for name, gid := range seeds {
			vrf := vs.vrfs[name]
			vrf.Name = name
			vrf.Preset = gid
			vs.vrfs[name] = vrf
		}
	}
}

// WithDPUCount sets the number of DPUs for hash-based dynamic pinning.
func WithDPUCount(count uint16) Option {
	return func(vs *vrfStore) {
		vs.dpuCount = count
	}
}

// WithLbModePinning sets the callback that determines whether per-DPU
// pinning is active. When this returns false, all redirects use "all" DPUs
// regardless of the computed DPUPinned value.
func WithLbModePinning(fn func() bool) Option {
	return func(vs *vrfStore) {
		vs.isLbModePinning = fn
	}
}

// WithIsLeader sets a callback that returns true if this node is the HA leader.
// Used during GID allocation: non-leaders prefer the peer's GID to avoid conflicts.
func WithIsLeader(fn func() bool) Option {
	return func(vs *vrfStore) {
		vs.isLeader = fn
	}
}

// NewStore creates a new VRF store with optional storage backend.
// If storage is provided, it loads initial state and persists changes automatically.
func NewStore(ctx context.Context, opts ...Option) Store {
	s := &vrfStore{
		vrfs:      make(map[string]types.VRF),
		nextGID:   GIDAllocationStart,
		gidsInUse: make(map[uint16]bool),
		callbacks: make(map[int]func(Event)),
	}

	// Apply options first (may populate skeleton VRFs from WithPreSeededGIDs)
	for _, opt := range opts {
		opt(s)
	}

	// Save skeleton presets before storage load so we can preserve them.
	skeletonPresets := make(map[string]uint16, len(s.vrfs))
	for name, vrf := range s.vrfs {
		if vrf.Preset > 0 {
			skeletonPresets[name] = vrf.Preset
		}
	}

	// Load initial state from storage if available
	if s.storage != nil {
		vrfs, err := s.storage.LoadVRFs(ctx)
		if err != nil && !storage.IsNotFound(err) {
			logger.GetLogger().Warn("Failed to load VRFs from storage", "error", err)
		}
		if vrfs != nil {
			for name, loaded := range vrfs {
				// Loaded VRFs override skeletons, but preserve Preset from WithPreSeededGIDs
				// if the loaded VRF has no Preset yet (old storage format).
				if loaded.Preset == 0 {
					if preset, hasSeed := skeletonPresets[name]; hasSeed {
						loaded.Preset = preset
					}
				}
				s.vrfs[name] = loaded
			}
			logger.GetLogger().Info("Loaded VRFs from storage", "count", len(vrfs))
		}
	}

	// Rebuild GID allocation state from loaded VRFs
	s.rebuildGIDStateLocked()

	return s
}

func (s *vrfStore) Get(name string) (types.VRF, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	vrf, ok := s.vrfs[name]
	return vrf, ok
}

func (s *vrfStore) List() []types.VRF {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]types.VRF, 0, len(s.vrfs))
	for _, vrf := range s.vrfs {
		result = append(result, vrf)
	}
	return result
}

func (s *vrfStore) ListActive() []types.VRF {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []types.VRF
	for _, vrf := range s.vrfs {
		if vrf.Active {
			result = append(result, vrf)
		}
	}
	return result
}

func (s *vrfStore) GetGID(name string) (uint16, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if vrf, ok := s.vrfs[name]; ok && vrf.GID > 0 {
		return vrf.GID, true
	}
	return 0, false
}

func (s *vrfStore) GetPinning(name string) (uint16, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if vrf, ok := s.vrfs[name]; ok && vrf.DPUPinned > 0 {
		return vrf.DPUPinned, true
	}
	return 0, false
}

func (s *vrfStore) NextGID() uint16 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nextGID
}

func (s *vrfStore) Watch(callback func(Event)) func() {
	s.mu.Lock()
	id := s.nextCbID
	s.nextCbID++
	s.callbacks[id] = callback
	s.mu.Unlock()

	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.callbacks, id)
	}
}

func (s *vrfStore) notify(event Event) {
	s.mu.RLock()
	callbacks := make([]func(Event), 0, len(s.callbacks))
	for _, cb := range s.callbacks {
		callbacks = append(callbacks, cb)
	}
	s.mu.RUnlock()

	for _, cb := range callbacks {
		cb(event)
	}
}

// persist saves the current state to storage if available.
func (s *vrfStore) persist(ctx context.Context) {
	if s.storage == nil {
		return
	}

	// Make a copy of vrfs while holding the lock
	s.mu.RLock()
	vrfsCopy := make(map[string]types.VRF, len(s.vrfs))
	for k, v := range s.vrfs {
		vrfsCopy[k] = v
	}
	s.mu.RUnlock()

	// Persist synchronously
	if err := s.storage.SaveVRFs(ctx, vrfsCopy); err != nil {
		logger.GetLogger().Warn("Failed to persist VRFs", "error", err)
	}
}

// SetGnmiHandler sets the gNMI handler for state synchronization.
// When set, service redirects are automatically programmed when VRFs change.
func (s *vrfStore) SetGnmiHandler(handler gnmi.GnmiHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gnmiHandler = handler
}

// SetGID sets the desired GID (Preset) for a VRF. Delegates to SetGIDs.
func (s *vrfStore) SetGID(ctx context.Context, name string, gid uint16) error {
	return s.SetGIDs(ctx, map[string]uint16{name: gid})
}

// SetGIDs atomically sets desired GIDs (Presets) for multiple VRFs and resolves
// collisions with other VRFs whose current GID is claimed by one of the new presets.
func (s *vrfStore) SetGIDs(ctx context.Context, changes map[string]uint16) error {
	if len(changes) == 0 {
		return nil
	}

	s.mu.Lock()

	// Step 1: For each change, create skeleton VRF if new, set Preset.
	for name, gid := range changes {
		vrf := s.vrfs[name]
		vrf.Name = name
		vrf.Preset = gid
		s.vrfs[name] = vrf
	}

	// Step 2: Collision pass — for each VRF NOT in changes, if its current GID is
	// claimed by a changes entry's preset, allocate a new preset via sequential scan.
	claimedPresets := make(map[uint16]struct{}, len(changes))
	for _, gid := range changes {
		claimedPresets[gid] = struct{}{}
	}

	for name, vrf := range s.vrfs {
		if _, inChanges := changes[name]; inChanges {
			continue
		}
		if vrf.GID == 0 {
			continue
		}
		if _, claimed := claimedPresets[vrf.GID]; !claimed {
			continue
		}
		// Find a new preset for this VRF, skipping gidsInUse and all presets.
		gid := s.nextGID
		start := gid
		for {
			if !s.gidsInUse[gid] {
				presetClaimed := false
				for otherName, otherVRF := range s.vrfs {
					if otherName != name && otherVRF.Preset == gid {
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
				break // exhausted, leave preset as-is
			}
		}
		if !s.gidsInUse[gid] {
			vrf.Preset = gid
			s.vrfs[name] = vrf
		}
	}

	s.mu.Unlock()

	// Step 3: Apply preset→GID transitions and reprogram redirects.
	s.reconcilePresets(ctx)

	// Step 4: Persist.
	s.persist(ctx)
	return nil
}

// SetDPUCount updates the number of DPUs for hash-based dynamic pinning.
func (s *vrfStore) SetDPUCount(count uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dpuCount = count
}

// SetInService controls the in-service gate for reactive redirect programming.
func (s *vrfStore) SetInService(inService bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inService = inService
}

// SetPeerGIDs stores the peer's GID allocations for HA-aware allocation.
// Non-leader nodes will prefer peer GIDs when allocating for new VRFs.
func (s *vrfStore) SetPeerGIDs(peerGIDs map[string]uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peerGIDs = peerGIDs
}

// ClearPeerGIDs removes peer GID information (e.g., on peer disconnect).
func (s *vrfStore) ClearPeerGIDs() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peerGIDs = nil
}

// isPinningActive returns true when per-DPU pinning is active.
// Needed as a nil check on isLbModePinning closure
func (s *vrfStore) isPinningActive() bool {
	if s.isLbModePinning == nil {
		return false
	}
	return s.isLbModePinning()
}

// Ensure vrfStore implements Store interface
var _ Store = (*vrfStore)(nil)
