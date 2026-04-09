// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package ha

import (
	"context"
	"sync"

	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/storage"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

// haStore implements Store.
//
// Persistence contract: fields in this struct are NOT persisted by default.
// To persist a new field, you must explicitly:
//  1. Add it to storage.HAState in storage/storage.go
//  2. Include it in persist() below
//  3. Include it in the NewStore() load path above
//
// Only configuration values (Enabled, SwitchState, HaIP) and peer IPs are persisted.
// All runtime state (local criteria, adjacency status, peer criteria, member info,
// DPU statuses) is rebuilt from scratch via gNMI and the HA adjacency protocol.
type haStore struct {
	mu          sync.RWMutex
	enabled     string
	switchState string
	haIP        string
	haPort      uint16
	localState  types.HALocalState
	peers       map[string]types.HAPeerState
	callbacks   map[int]func(Event)
	nextCbID    int
	storage     storage.Storage
	gnmiHandler gnmi.GnmiHandler
}

// Option configures Store.
type Option func(*haStore)

// WithStorage sets the storage backend for the HA store.
func WithStorage(s storage.Storage) Option {
	return func(hs *haStore) {
		hs.storage = s
	}
}

// WithGnmiHandler sets the gNMI handler for state synchronization.
func WithGnmiHandler(handler gnmi.GnmiHandler) Option {
	return func(hs *haStore) {
		hs.gnmiHandler = handler
	}
}

// SetGnmiHandler sets the gNMI handler for state synchronization.
func (s *haStore) SetGnmiHandler(handler gnmi.GnmiHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gnmiHandler = handler
}

// NewStore creates a new HA store with optional storage backend.
func NewStore(ctx context.Context, opts ...Option) Store {
	s := &haStore{
		peers:     make(map[string]types.HAPeerState),
		callbacks: make(map[int]func(Event)),
		localState: types.HALocalState{
			Criteria: make(types.HACriteria),
		},
	}

	for _, opt := range opts {
		opt(s)
	}

	// Load initial state from storage if available
	if s.storage != nil {
		state, err := s.storage.LoadHA(ctx)
		if err != nil && !storage.IsNotFound(err) {
			logger.GetLogger().Warn("Failed to load HA state from storage", "error", err)
		}
		if state != nil {
			s.enabled = state.Enabled
			s.switchState = state.SwitchState
			s.haIP = state.HaIP
			s.haPort = state.HaPort
			// Restore peer IPs from storage so the HA adjacency protocol can
			// reconnect to known peers on startup. IpConfigState is set to
			// "success" because peers were valid when persisted; gNMI will
			// correct this if the peer is no longer reachable. Without this,
			// checkAdjacencies silently skips peers.
			for _, ip := range state.PeerIPs {
				if _, exists := s.peers[ip]; !exists {
					s.peers[ip] = types.HAPeerState{
						IP:                ip,
						MemberCriteria:    make(types.HACriteria),
						ServiceCriteria:   make(types.HACriteria),
						AdjacencyCriteria: make(types.HACriteria),
						IpConfigState:     PeerIpCfgStateSuccess,
					}
				}
			}
			logger.GetLogger().Info("Loaded HA state from storage")
		}
	}

	return s
}

func (s *haStore) Enabled() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled
}

func (s *haStore) SwitchState() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.switchState
}

func (s *haStore) IsLeader() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.localState.Leader
}

func (s *haStore) HaIP() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.haIP
}

func (s *haStore) HaPort() uint16 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.haPort
}

func (s *haStore) Local() types.HALocalState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.localState.Copy()
}

func (s *haStore) IsServiceFunctional() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.localState.Criteria.AllOk()
}

func (s *haStore) Peer(ip string) (types.HAPeerState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, ok := s.peers[ip]
	if !ok {
		return types.HAPeerState{}, false
	}
	return peer.Copy(), true
}

func (s *haStore) AllPeers() map[string]types.HAPeerState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]types.HAPeerState, len(s.peers))
	for k, v := range s.peers {
		result[k] = v.Copy()
	}
	return result
}

func (s *haStore) PeerIPs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ips := make([]string, 0, len(s.peers))
	for ip := range s.peers {
		ips = append(ips, ip)
	}
	return ips
}

func (s *haStore) AnyPeerAdjacencyCriteriaOk() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, peer := range s.peers {
		if peer.Connected && peer.AdjacencyCriteria.AllOk() {
			return true
		}
	}
	return false
}

func (s *haStore) AnyPeerMemberCriteriaFail() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, peer := range s.peers {
		if len(peer.MemberCriteria) > 0 && !peer.MemberCriteria.AllOk() {
			return true
		}
	}
	return false
}

func (s *haStore) AnyPeerInHaReady() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, peer := range s.peers {
		if peer.HaState == types.PeerHAStateOk {
			return true
		}
	}
	return false
}

func (s *haStore) Watch(callback func(Event)) func() {
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

func (s *haStore) notify(event Event) {
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
// Only configuration values and peer IPs are persisted; all runtime state is
// rebuilt at startup via gNMI and the HA adjacency protocol.
func (s *haStore) persist(ctx context.Context) {
	if s.storage == nil {
		return
	}

	s.mu.RLock()
	state := &storage.HAState{
		Enabled:     s.enabled,
		SwitchState: s.switchState,
		HaIP:        s.haIP,
		HaPort:      s.haPort,
	}
	if len(s.peers) > 0 {
		state.PeerIPs = make([]string, 0, len(s.peers))
		for ip := range s.peers {
			state.PeerIPs = append(state.PeerIPs, ip)
		}
	}
	s.mu.RUnlock()

	if err := s.storage.SaveHA(ctx, state); err != nil {
		logger.GetLogger().Warn("Failed to persist HA state", "error", err)
	}
}

// isHAConfiguredLocked reports whether any HA configuration exists on the switch.
// Must be called with s.mu held.
func (s *haStore) isHAConfiguredLocked() bool {
	return s.haIP != "" || s.switchState != "" || len(s.peers) > 0 || s.enabled != ""
}

// Ensure haStore implements Store interface
var _ Store = (*haStore)(nil)
