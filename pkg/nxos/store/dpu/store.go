// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dpu

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/storage"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

// Default DPU port range constants.
const (
	DefaultPortLow  uint16 = 28672
	DefaultPortHigh uint16 = 29695

	// EnvDPUPortStart is the environment variable for the DPU port range start.
	EnvDPUPortStart = "NX_DPU_PORT_START"

	// EnvDPUPortEnd is the environment variable for the DPU port range end.
	EnvDPUPortEnd = "NX_DPU_PORT_END"

	// EnvSkipDPU is the environment variable that enables DPUless mode.
	// Set to "1" to skip all DPU discovery and agent checks.
	EnvSkipDPU = "NX_AGENT_IGNORE_MODULES"
)

// dpuStore implements Store.
//
// Persistence contract: fields in this struct are NOT persisted by default.
// To persist a new field, you must explicitly:
//  1. Add it to storage.persistedDPUState (via types.DPU) in storage/file.go
//  2. Include it in persist() below
//  3. Include it in the NewStore() load path above
//
// Note: DPU.State is intentionally reset to UNSET on load — persisted state
// values may be stale; actual state is only authoritative from gNMI notifications.
type dpuStore struct {
	mu                sync.RWMutex
	dpus              map[string]types.DPU
	dpuCount          int
	inventoryComplete bool
	inSync            bool
	healthy           bool
	healthyCount      int
	inSyncCount       int
	globalPortLow     uint16
	globalPortHigh    uint16
	callbacks         map[int]func(Event)
	nextCbID          int
	gnmiHandler       gnmi.GnmiHandler
	storage           storage.Storage
	skipDPU           bool
	skipDPUSet        bool

	// inventoryCond signals when inventory state changes (for WaitForInventory)
	inventoryCond *sync.Cond
}

// Option configures the DPU store.
type Option func(*dpuStore)

// WithStorage sets the storage backend for the DPU store.
func WithStorage(s storage.Storage) Option {
	return func(ds *dpuStore) {
		ds.storage = s
	}
}

// WithSkipDPU configures the DPU store to operate in DPUless mode.
// When enabled, health/sync/readiness checks return true immediately and
// WaitForInventory returns without blocking.
// This overrides the NX_AGENT_IGNORE_MODULES environment variable.
func WithSkipDPU(skip bool) Option {
	return func(ds *dpuStore) {
		ds.skipDPU = skip
		ds.skipDPUSet = true
	}
}

// NewStore creates a new DPU store with optional configuration.
func NewStore(ctx context.Context, opts ...Option) Store {
	s := &dpuStore{
		dpus:           make(map[string]types.DPU),
		globalPortLow:  DefaultPortLow,
		globalPortHigh: DefaultPortHigh,
		callbacks:      make(map[int]func(Event)),
	}
	s.inventoryCond = sync.NewCond(&s.mu)

	for _, opt := range opts {
		opt(s)
	}

	// If no explicit WithSkipDPU option was provided, check the environment variable.
	if !s.skipDPUSet {
		if os.Getenv(EnvSkipDPU) == "1" {
			logger.GetLogger().Info("Skip DPUs")
			s.skipDPU = true
		}
	}

	// Read port range from environment variables, overriding defaults if valid.
	if startVal, endVal := os.Getenv(EnvDPUPortStart), os.Getenv(EnvDPUPortEnd); startVal != "" && endVal != "" {
		low, errLow := parsePort(startVal)
		high, errHigh := parsePort(endVal)
		if errLow != nil {
			logger.GetLogger().Warn("Invalid NX_DPU_PORT_START, using defaults", "value", startVal, "error", errLow)
		} else if errHigh != nil {
			logger.GetLogger().Warn("Invalid NX_DPU_PORT_END, using defaults", "value", endVal, "error", errHigh)
		} else if low >= high {
			logger.GetLogger().Warn("Invalid port range: start must be less than end, using defaults", "start", low, "end", high)
		} else {
			s.globalPortLow = low
			s.globalPortHigh = high
			logger.GetLogger().Info("DPU port range configured from env", "low", low, "high", high)
		}
	}

	// Load initial state from storage if available.
	// DPU State is reset to UNSET after loading because persisted state may be
	// stale — actual online/offline status is only authoritative from gNMI.
	if s.storage != nil {
		dpus, err := s.storage.LoadDPUs(ctx)
		if err != nil && !storage.IsNotFound(err) {
			logger.GetLogger().Warn("Failed to load DPU state from storage", "error", err)
		}
		if dpus != nil {
			for name, dpu := range dpus {
				dpu.State = 0 // UNSET — actual state will be populated by gNMI notifications
				dpus[name] = dpu
			}
			s.dpus = dpus
			logger.GetLogger().Info("Loaded DPU state from storage", "count", len(dpus))
		}
	}

	return s
}

func (s *dpuStore) Get(name string) (types.DPU, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	dpu, ok := s.dpus[name]
	return dpu, ok
}

func (s *dpuStore) List() []types.DPU {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]types.DPU, 0, len(s.dpus))
	for _, dpu := range s.dpus {
		result = append(result, dpu)
	}
	return result
}

func (s *dpuStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.dpus)
}

func (s *dpuStore) DpuCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dpuCount
}

func (s *dpuStore) IsInventoryComplete() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inventoryComplete
}

func (s *dpuStore) AreAllOnline() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.skipDPU {
		return true
	}
	if len(s.dpus) == 0 {
		return false
	}
	for _, dpu := range s.dpus {
		if !dpu.IsOnline() {
			return false
		}
	}
	return true
}

func (s *dpuStore) Watch(callback func(Event)) func() {
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

func (s *dpuStore) notify(event Event) {
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

func (s *dpuStore) Update(ctx context.Context, dpu types.DPU) error {
	s.mu.Lock()
	old, exists := s.dpus[dpu.Name]
	var oldDPU *types.DPU
	if exists {
		oldDPU = &old
	}
	portCalculated := dpu.CalculatePortRange(s.globalPortLow, s.globalPortHigh, s.dpuCount)
	if !portCalculated {
		if s.dpuCount > 0 {
			logger.GetLogger().Error("Failed to calculate port range for DPU", "dpu", dpu.Name, "moduleNum", dpu.ModuleNum, "dpuCount", s.dpuCount, "portLow", s.globalPortLow, "portHigh", s.globalPortHigh)
		} else {
			logger.GetLogger().Debug("Deferring port range calculation until DPU count is known", "dpu", dpu.Name)
		}
	}
	portChanged := portCalculated && (oldDPU == nil || oldDPU.PortLow != dpu.PortLow || oldDPU.PortHigh != dpu.PortHigh)
	s.dpus[dpu.Name] = dpu
	s.mu.Unlock()

	// Signal waiters that DPU count may have changed
	if !exists {
		s.inventoryCond.Broadcast()
	}

	s.persist(ctx)

	if portChanged {
		s.writeDpuPortRange(ctx, dpu)
	}

	eventType := store.EventUpdated
	if !exists {
		eventType = store.EventCreated
	}
	s.notify(Event{Type: eventType, DPU: dpu, OldDPU: oldDPU})
	return nil
}

func (s *dpuStore) Remove(ctx context.Context, name string) error {
	s.mu.Lock()
	dpu, exists := s.dpus[name]
	if !exists {
		s.mu.Unlock()
		return &ErrNotFound{Name: name}
	}
	delete(s.dpus, name)
	s.mu.Unlock()

	s.persist(ctx)

	if err := s.DeleteDpuPortRange(ctx, dpu.ModuleNum); err != nil {
		logger.GetLogger().Warn("Failed to delete DPU port range from gNMI", "dpu", name, "error", err)
	}

	s.notify(Event{Type: store.EventDeleted, DPU: dpu, OldDPU: &dpu})
	return nil
}

// persist saves the current DPU state to storage if available.
func (s *dpuStore) persist(ctx context.Context) {
	if s.storage == nil {
		return
	}

	// Make a copy of the dpus map while holding the lock
	s.mu.RLock()
	dpusCopy := make(map[string]types.DPU, len(s.dpus))
	for k, v := range s.dpus {
		dpusCopy[k] = v
	}
	s.mu.RUnlock()

	if err := s.storage.SaveDPUs(ctx, dpusCopy); err != nil {
		logger.GetLogger().Warn("Failed to persist DPU state", "error", err)
	}
}

func (s *dpuStore) SetExpectedCount(ctx context.Context, count int) {
	s.mu.Lock()
	s.dpuCount = count
	// Recalculate per-DPU port ranges for all known DPUs now that dpuCount is known.
	var toWrite []types.DPU
	for name, dpu := range s.dpus {
		old := dpu
		if !dpu.CalculatePortRange(s.globalPortLow, s.globalPortHigh, s.dpuCount) {
			logger.GetLogger().Error("Failed to calculate port range for DPU", "dpu", dpu.Name, "moduleNum", dpu.ModuleNum, "dpuCount", s.dpuCount, "portLow", s.globalPortLow, "portHigh", s.globalPortHigh)
		} else if old.PortLow != dpu.PortLow || old.PortHigh != dpu.PortHigh {
			toWrite = append(toWrite, dpu)
		}
		s.dpus[name] = dpu
	}
	s.mu.Unlock()
	// Signal waiters that expected count changed
	s.inventoryCond.Broadcast()

	for _, dpu := range toWrite {
		s.writeDpuPortRange(ctx, dpu)
	}
}

func (s *dpuStore) SetInventoryComplete(complete bool) {
	s.mu.Lock()
	s.inventoryComplete = complete
	s.mu.Unlock()
	// Signal waiters that inventory state changed
	s.inventoryCond.Broadcast()
}

func (s *dpuStore) SetInSync(inSync bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inSync = inSync
}

func (s *dpuStore) SetHealth(healthy bool, count int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.healthy = healthy
	s.healthyCount = count
}

// HealthyCount returns the count of healthy DPUs.
func (s *dpuStore) HealthyCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.healthyCount
}

// IsHealthy returns whether the DPU fleet is considered healthy.
// Requires all expected DPUs to be connected and reporting healthy.
// Returns true immediately when skipDPU is set.
func (s *dpuStore) IsHealthy() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.skipDPU {
		return true
	}
	return s.healthy && s.healthyCount == s.dpuCount && s.dpuCount > 0
}

// IsInSync returns whether the DPU fleet is in sync.
// Returns true immediately when skipDPU is set.
func (s *dpuStore) IsInSync() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.skipDPU {
		return true
	}
	return s.inSync
}

// InSyncCount returns the count of DPUs that are in sync.
func (s *dpuStore) InSyncCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inSyncCount
}

// SetInSyncCount tracks the count of DPUs that are in sync.
func (s *dpuStore) SetInSyncCount(count int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inSyncCount = count
}

// IsReady returns true when inventory is complete AND all expected DPUs are discovered.
// Returns true immediately when skipDPU is set.
func (s *dpuStore) IsReady() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.skipDPU {
		return true
	}
	return s.inventoryComplete && len(s.dpus) >= s.dpuCount && s.dpuCount > 0
}

// WaitForInventory blocks until inventory is complete AND all expected DPUs are discovered,
// or until the context is cancelled.
// Returns immediately when skipDPU is set.
func (s *dpuStore) WaitForInventory(ctx context.Context) error {
	// Return immediately in DPUless mode.
	s.mu.RLock()
	skip := s.skipDPU
	s.mu.RUnlock()
	if skip {
		return nil
	}

	// Check if already ready without holding lock
	s.mu.RLock()
	ready := s.inventoryComplete && len(s.dpus) >= s.dpuCount && s.dpuCount > 0
	s.mu.RUnlock()
	if ready {
		return nil
	}

	// Wait for inventory to become ready
	errCh := make(chan error, 1)
	go func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		for !(s.inventoryComplete && len(s.dpus) >= s.dpuCount && s.dpuCount > 0) {
			if ctx.Err() != nil {
				errCh <- ctx.Err()
				return
			}
			s.inventoryCond.Wait()
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		s.inventoryCond.Broadcast() // Wake up waiter to exit
		return ctx.Err()
	}
}

// SetGnmiHandler sets the gNMI handler for state synchronization.
func (s *dpuStore) SetGnmiHandler(handler gnmi.GnmiHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gnmiHandler = handler
}

// GetGlobalPortRange returns the configured fleet-wide port range (low, high).
func (s *dpuStore) GetGlobalPortRange() (uint16, uint16) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.globalPortLow, s.globalPortHigh
}

// SetGlobalPortRange sets the fleet-wide port range and recalculates all per-DPU ranges.
func (s *dpuStore) SetGlobalPortRange(ctx context.Context, low, high uint16) {
	s.mu.Lock()
	s.globalPortLow = low
	s.globalPortHigh = high
	var toWrite []types.DPU
	for name, dpu := range s.dpus {
		old := dpu
		if !dpu.CalculatePortRange(s.globalPortLow, s.globalPortHigh, s.dpuCount) {
			logger.GetLogger().Error("Failed to calculate port range for DPU", "dpu", dpu.Name, "moduleNum", dpu.ModuleNum, "dpuCount", s.dpuCount, "portLow", s.globalPortLow, "portHigh", s.globalPortHigh)
		} else if old.PortLow != dpu.PortLow || old.PortHigh != dpu.PortHigh {
			toWrite = append(toWrite, dpu)
		}
		s.dpus[name] = dpu
	}
	s.mu.Unlock()

	for _, dpu := range toWrite {
		s.writeDpuPortRange(ctx, dpu)
	}
}

// IsSkipDPU returns true if the store is operating in DPUless mode.
func (s *dpuStore) IsSkipDPU() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.skipDPU
}

// writeDpuPortRange formats and writes the TCP/UDP port range for a DPU to gNMI.
func (s *dpuStore) writeDpuPortRange(ctx context.Context, dpu types.DPU) {
	portRange := formatPortRange(dpu)
	if err := s.SetDpuPortRange(ctx, dpu.ModuleNum, portRange, portRange); err != nil {
		logger.GetLogger().Warn("Failed to write DPU port range to gNMI", "dpu", dpu.Name, "range", portRange, "error", err)
	}
}

// formatPortRange formats a DPU's port range as "low-high".
func formatPortRange(dpu types.DPU) string {
	return fmt.Sprintf("%d-%d", dpu.PortLow, dpu.PortHigh)
}

// parsePort parses a port number string into a uint16 value.
func parsePort(s string) (uint16, error) {
	port, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port: %w", err)
	}
	return uint16(port), nil
}

// Ensure dpuStore implements Store interface
var _ Store = (*dpuStore)(nil)
