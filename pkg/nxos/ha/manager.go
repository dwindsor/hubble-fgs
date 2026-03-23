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
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/nxos/store/device"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/dpu"
	hastore "github.com/isovalent/hubble-fgs/pkg/nxos/store/ha"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/vlan"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/vrf"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
	hav1 "github.com/isovalent/hubble-fgs/pkg/proto/ha/v1"
)

// haPort returns the HA gRPC port derived from the device store's HSA port range.
// Returns an error if the device store is not configured.
func (m *manager) haPort() (uint16, error) {
	if m.deviceStore == nil {
		return 0, fmt.Errorf("device store not configured: cannot determine HA port")
	}
	return m.deviceStore.HSAPortLow(), nil
}

// isConfigReady returns true when all three prerequisites for HA activation are met:
//   - HA is enabled
//   - at least one peer is configured
//   - service function is configured (InServiceState != ""), or deviceStore is nil (no gating)
func (m *manager) isConfigReady() bool {
	if m.haStore.Enabled() != "enabled" || len(m.haStore.PeerIPs()) == 0 {
		return false
	}
	if m.deviceStore != nil && m.deviceStore.InServiceState() == "" {
		return false
	}
	return true
}

const (
	// AdjacencyTimeout is the timeout for considering a peer as down.
	AdjacencyTimeout = 30 * time.Second

	// AdjacencyInterval is the interval between adjacency checks.
	AdjacencyInterval = 10 * time.Second

	// HeartbeatInterval is the interval between heartbeat messages.
	HeartbeatInterval = 5 * time.Second

	// HeartbeatTimeout is the timeout for considering a peer unreachable via heartbeat.
	HeartbeatTimeout = 15 * time.Second

	// MemberTimeout is the timeout for considering a peer member as expired.
	MemberTimeout = 30 * time.Second
)

// Manager defines the interface for HA orchestration.
type Manager interface {
	Run(ctx context.Context) error
	IsLeader() bool
	Peers() []string
	ConnectPeer(ctx context.Context, peer string) error
	DisconnectPeer(peer string) error
	ProcessMemberInfo(ctx context.Context, peer string, info types.HAPeerMember) (bool, string)
	NotifyRemoval(ctx context.Context, peer string)
	HandleAdjFailureNotify(ctx context.Context, peer string, reason string)

	// DPU HA event handling (satisfies switchpolicy.HaEventHandler interface).
	RegisterDpu(ctx context.Context, dpuUid string)
	UpdateKeepalive(ctx context.Context, dpuUid string, up bool)
	UpdateBulkSyncLocal(ctx context.Context, dpuUid string, done bool)
	UpdateBulkSyncPeer(ctx context.Context, dpuUid string, done bool)
	UpdatePolicyRevision(ctx context.Context, revision string)
}

// ManagerOption configures the HA manager.
type ManagerOption func(*manager)

// WithHAStoreForManager sets the HA store for the manager.
func WithHAStoreForManager(s hastore.Store) ManagerOption {
	return func(m *manager) {
		m.haStore = s
	}
}

// WithLocalIP sets the local IP address (used when not reading from haStore directly).
func WithLocalIP(ip string) ManagerOption {
	return func(m *manager) {
		m.localIP = ip
	}
}

// WithManagerMemberInfoProvider sets the function to get local member info (fallback for tests).
func WithManagerMemberInfoProvider(provider func() types.HAPeerMember) ManagerOption {
	return func(m *manager) {
		m.memberInfoProvider = provider
	}
}

// WithClientFactory sets the factory function for creating HA clients.
func WithClientFactory(factory func() Client) ManagerOption {
	return func(m *manager) {
		m.clientFactory = factory
	}
}

// WithVRFStore sets the VRF store for reconciliation.
func WithVRFStore(s vrf.Store) ManagerOption {
	return func(m *manager) {
		m.vrfStore = s
	}
}

// WithVLANStore sets the VLAN store for reconciliation.
func WithVLANStore(s vlan.Store) ManagerOption {
	return func(m *manager) {
		m.vlanStore = s
	}
}

// WithDeviceInfoProvider sets the function to get local device info for validation (fallback for tests).
func WithDeviceInfoProvider(fn func() LocalDeviceInfo) ManagerOption {
	return func(m *manager) {
		m.deviceInfoProvider = fn
	}
}

// WithDeviceStore sets the device store for reading device information.
func WithDeviceStore(s device.Store) ManagerOption {
	return func(m *manager) {
		m.deviceStore = s
	}
}

// WithDPUStore sets the DPU store for reading DPU information.
func WithDPUStore(s dpu.Store) ManagerOption {
	return func(m *manager) {
		m.dpuStore = s
	}
}

// dpuStatus tracks per-DPU HA keepalive and bulk-sync state.
type dpuStatus struct {
	keepaliveUp   bool
	bulkSyncLocal bool
	bulkSyncPeer  bool
}

// manager implements the Manager interface.
type manager struct {
	mu                 sync.RWMutex
	haStore            hastore.Store
	localIP            string
	peerClients        map[string]Client
	lastAdjTime        map[string]time.Time
	lastHeartbeatTime  map[string]time.Time
	memberInfoProvider func() types.HAPeerMember
	deviceInfoProvider func() LocalDeviceInfo
	clientFactory      func() Client

	// HA business logic
	stateMachine *StateMachine
	validator    *Validator
	reconciler   *Reconciler
	vrfStore     vrf.Store
	vlanStore    vlan.Store

	// Store-based dependencies (preferred over providers)
	deviceStore device.Store
	dpuStore    dpu.Store

	// Per-DPU HA status tracking
	dpuStatuses map[string]*dpuStatus

	// Server owned by this manager during Run() activation
	server Server
}

// NewManager creates a new HA manager.
func NewManager(opts ...ManagerOption) Manager {
	m := &manager{
		peerClients:       make(map[string]Client),
		lastAdjTime:       make(map[string]time.Time),
		lastHeartbeatTime: make(map[string]time.Time),
		dpuStatuses:       make(map[string]*dpuStatus),
		clientFactory: func() Client {
			return NewClient()
		},
	}

	for _, opt := range opts {
		opt(m)
	}

	// Pre-populate per-DPU status from dpuStore.
	if m.dpuStore != nil {
		skipDPU := m.dpuStore.IsSkipDPU()
		for _, d := range m.dpuStore.List() {
			s := &dpuStatus{}
			if skipDPU {
				s.keepaliveUp = true
				s.bulkSyncLocal = true
				s.bulkSyncPeer = true
			}
			m.dpuStatuses[d.Name] = s
		}
	}

	// Initialize business logic components
	if m.haStore != nil {
		m.stateMachine = NewStateMachine(m.haStore)
		// Use deviceStore if available, otherwise fall back to provider
		if m.deviceStore != nil {
			m.validator = NewValidator(m.haStore, m.buildDeviceInfo)
		} else if m.deviceInfoProvider != nil {
			m.validator = NewValidator(m.haStore, m.deviceInfoProvider)
		}
		if m.vrfStore != nil && m.vlanStore != nil {
			m.reconciler = NewReconciler(m.haStore, m.vrfStore, m.vlanStore)
		}
	}

	return m
}

// buildMemberInfo builds the local member info for adjacency exchanges.
// Uses deviceStore if available, falls back to memberInfoProvider.
func (m *manager) buildMemberInfo() types.HAPeerMember {
	var local types.HALocalState
	if m.haStore != nil {
		local = m.haStore.Local()
	}
	info := types.HAPeerMember{
		PolicyRev:   local.PolicyRev,
		PolicyCheck: local.PolicyCheck,
		HaState:     local.HaState,
		Service:     local.SvcState,
	}
	if m.deviceStore != nil {
		info.SerialNum = m.deviceStore.SerialNumber()
		info.Model = m.deviceStore.Model()
		info.SWVersion = m.deviceStore.SoftwareVersion()
		info.LbMode = m.deviceStore.LbMode()
	} else if m.memberInfoProvider != nil {
		provided := m.memberInfoProvider()
		info.SerialNum = provided.SerialNum
		info.Model = provided.Model
		info.SWVersion = provided.SWVersion
		info.CPAVersion = provided.CPAVersion
	}
	if m.dpuStore != nil {
		for _, d := range m.dpuStore.List() {
			info.DPUs = append(info.DPUs, types.DPUVersion{
				Name:    d.Name,
				Version: d.Version,
			})
		}
	}
	return info
}

// buildDeviceInfo builds the local device info for member validation.
// Uses deviceStore and dpuStore if available, falls back to deviceInfoProvider.
func (m *manager) buildDeviceInfo() LocalDeviceInfo {
	if m.deviceStore == nil {
		if m.deviceInfoProvider != nil {
			return m.deviceInfoProvider()
		}
		return LocalDeviceInfo{}
	}
	info := LocalDeviceInfo{
		SerialNum: m.deviceStore.SerialNumber(),
		Model:     m.deviceStore.Model(),
		SWVersion: m.deviceStore.SoftwareVersion(),
		LbMode:    m.deviceStore.LbMode(),
	}
	if m.dpuStore != nil {
		dpus := make(map[string]string)
		for _, d := range m.dpuStore.List() {
			dpus[d.Name] = d.Version
		}
		info.DPUs = dpus
	}
	return info
}

// Run is the long-lived lifecycle goroutine for the HA manager.
// It waits for HA configuration, activates (starts server + event loop),
// and can cycle between active/inactive states as config changes.
func (m *manager) Run(ctx context.Context) error {
	if m.haStore == nil {
		logger.GetLogger().Warn("HA manager Run called with no haStore, exiting")
		return nil
	}

	// Subscribe to HA store events.
	storeCh := make(chan hastore.Event, 32)
	unsub := m.haStore.Watch(func(e hastore.Event) {
		select {
		case storeCh <- e:
		default:
			logger.GetLogger().Error("HA store event dropped, channel full", "event", e.Type)
		}
	})
	defer unsub()

	// Subscribe to device store events if available.
	var deviceCh chan device.Event
	if m.deviceStore != nil {
		deviceCh = make(chan device.Event, 32)
		unsubDevice := m.deviceStore.Watch(func(e device.Event) {
			select {
			case deviceCh <- e:
			default:
				logger.GetLogger().Error("Device store event dropped, channel full", "event", e.Type)
			}
		})
		defer unsubDevice()
	}

	logger.GetLogger().Info("HA manager Run started")

	for {
		// Wait until all prerequisites are met: HA enabled, peers configured, SF configured.
		if !m.isConfigReady() {
			logger.GetLogger().Info("HA manager waiting for configuration")
			if done := m.waitForConfig(ctx, storeCh, deviceCh); done {
				logger.GetLogger().Info("HA manager Run exiting")
				return nil
			}
		}

		// Activate: read local IP, create server, run event loop.
		localIP := m.haStore.HaIP()
		m.mu.Lock()
		if localIP != "" {
			m.localIP = localIP
		}
		m.mu.Unlock()

		if localIP != "" {
			m.haStore.SetHaIP(ctx, localIP)
		}

		// Ensure validator is initialized now that stores are available.
		// Use a closure to ensure the mutex is released via defer, making it panic-safe.
		func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.validator == nil && m.deviceStore != nil && m.haStore != nil {
				m.validator = NewValidator(m.haStore, m.buildDeviceInfo)
			}
		}()

		// Create and start the HA server in a sub-context.
		serverCtx, serverCancel := context.WithCancel(ctx)
		srv := NewServer(
			WithHAStore(m.haStore),
			WithManager(m),
			WithMemberInfoProvider(m.buildMemberInfo),
			WithServerVRFStore(m.vrfStore),
			WithServerVLANStore(m.vlanStore),
			WithServerReconciler(m.reconciler),
		)
		m.mu.Lock()
		m.server = srv
		m.mu.Unlock()

		logger.GetLogger().Info("HA manager activating", "localIP", m.localIP)
		port, err := m.haPort()
		if err != nil {
			serverCancel()
			return fmt.Errorf("HA manager activation failed: %w", err)
		}
		// Track the server goroutine so we can wait for it during shutdown.
		var serverWg sync.WaitGroup
		serverWg.Add(1)
		go func() {
			defer serverWg.Done()
			backoff := 5 * time.Second
			const maxBackoff = 60 * time.Second
			for {
				if err := srv.Start(serverCtx, port); err != nil {
					select {
					case <-serverCtx.Done():
						return
					default:
					}
					logger.GetLogger().Error("HA server start failed, retrying",
						"error", err, "port", port, "backoff", backoff)
					select {
					case <-serverCtx.Done():
						return
					case <-time.After(backoff):
					}
					if backoff *= 2; backoff > maxBackoff {
						backoff = maxBackoff
					}
				} else {
					return
				}
			}
		}()

		// Set initial HACritSvcRedir criterion based on current in-service state.
		if m.deviceStore != nil {
			m.haStore.UpdateLocalCriterion(ctx, types.HACritSvcRedir, m.deviceStore.IsInService())
		}

		// Run the active event loop (blocks until deactivation or ctx cancellation).
		done := m.runActive(ctx, serverCancel, storeCh, deviceCh)

		// Cleanup: stop server, disconnect all peers.
		serverCancel()
		serverWg.Wait() // Wait for server goroutine to exit before proceeding.
		m.mu.Lock()
		m.server = nil
		m.mu.Unlock()
		m.disconnectAllPeers()

		if done {
			logger.GetLogger().Info("HA manager Run exiting")
			return nil
		}

		logger.GetLogger().Info("HA manager deactivated, waiting for reconfiguration")
	}
}

// waitForConfig blocks until all prerequisites are met, or ctx is cancelled.
// Returns true if the caller should exit (ctx done), false if config is ready.
func (m *manager) waitForConfig(ctx context.Context, storeCh <-chan hastore.Event, deviceCh <-chan device.Event) bool {
	for {
		select {
		case <-ctx.Done():
			return true
		case event := <-storeCh:
			switch event.Type {
			case hastore.EventAdminStateChanged, hastore.EventPeerAdded:
				if m.isConfigReady() {
					return false
				}
			}
		case event := <-deviceCh:
			if event.Type == device.EventInServiceChanged {
				if m.isConfigReady() {
					return false
				}
			}
		}
	}
}

// runActive is the active event loop. It blocks until HA is deconfigured or ctx is cancelled.
// Returns true if the caller should exit (ctx done), false if HA was deconfigured.
func (m *manager) runActive(ctx context.Context, serverCancel context.CancelFunc, storeCh <-chan hastore.Event, deviceCh <-chan device.Event) bool {
	// Track peer connection goroutines so they don't outlive the active event loop.
	var peerWg sync.WaitGroup
	defer peerWg.Wait()

	ticker := time.NewTicker(AdjacencyInterval)
	defer ticker.Stop()

	heartbeatTicker := time.NewTicker(HeartbeatInterval)
	defer heartbeatTicker.Stop()

	logger.GetLogger().Debug("HA active event loop started")

	for {
		select {
		case <-ctx.Done():
			serverCancel()
			logger.GetLogger().Debug("HA active event loop stopped (ctx done)")
			return true

		case event := <-storeCh:
			switch event.Type {
			case hastore.EventAdminStateChanged:
				// If HA becomes disabled, deactivate.
				if m.haStore.Enabled() != "enabled" {
					serverCancel()
					logger.GetLogger().Info("HA disabled, deactivating")
					return false
				}
			case hastore.EventCriterionChanged, hastore.EventCriterionSet, hastore.EventPeerCriteriaUpdated:
				m.recomputeAndApplyState(ctx)
			case hastore.EventPeerAdded:
				peerWg.Add(1)
				go func(ip string) {
					defer peerWg.Done()
					if err := m.ConnectPeer(ctx, ip); err != nil {
						logger.GetLogger().Debug("Failed to connect to new peer", logfields.Error, err, "peer", ip)
					}
				}(event.PeerIP)
			case hastore.EventPeerRemoved:
				if err := m.DisconnectPeer(event.PeerIP); err != nil {
					logger.GetLogger().Debug("Failed to disconnect peer", logfields.Error, err, "peer", event.PeerIP)
				}
			}

		case devEvent := <-deviceCh:
			if devEvent.Type == device.EventInServiceChanged {
				// Update HACritSvcRedir based on in-service state.
				// "" (delete) won't arrive here — gNMI delete triggers process restart.
				isInService := devEvent.Status == "in-service"
				m.haStore.UpdateLocalCriterion(ctx, types.HACritSvcRedir, isInService)
				logger.GetLogger().Info("HACritSvcRedir updated", "in-service", isInService)
			}

		case <-ticker.C:
			m.haUpdateNx(ctx)
			m.checkHoldDown(ctx)
			m.checkAdjacencies(ctx)
			m.checkAdjMbrTimeouts(ctx)

		case <-heartbeatTicker.C:
			m.sendHeartbeats(ctx)
			m.checkHeartbeatTimeouts(ctx)
		}
	}
}

// disconnectAllPeers closes all peer connections.
func (m *manager) disconnectAllPeers() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for peer, client := range m.peerClients {
		if err := client.Close(); err != nil {
			logger.GetLogger().Warn("Failed to close peer connection during deactivation", logfields.Error, err, "peer", peer)
		}
	}
	m.peerClients = make(map[string]Client)
	m.lastAdjTime = make(map[string]time.Time)
	m.lastHeartbeatTime = make(map[string]time.Time)
}

// IsLeader returns true if this node is the HA leader.
func (m *manager) IsLeader() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.haStore != nil {
		return m.haStore.IsLeader()
	}
	return false
}

// Peers returns the list of configured peer addresses.
func (m *manager) Peers() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	peers := make([]string, 0, len(m.peerClients))
	for peer := range m.peerClients {
		peers = append(peers, peer)
	}
	return peers
}

// ConnectPeer establishes a connection to a peer.
func (m *manager) ConnectPeer(ctx context.Context, peer string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if client, ok := m.peerClients[peer]; ok && client.IsConnected() {
		return nil
	}

	client := m.clientFactory()
	port, err := m.haPort()
	if err != nil {
		return fmt.Errorf("cannot connect to peer %s: %w", peer, err)
	}
	addr := fmt.Sprintf("%s:%d", peer, port)

	if err := client.Connect(ctx, addr); err != nil {
		return err
	}

	m.peerClients[peer] = client
	m.lastAdjTime[peer] = time.Now()

	logger.GetLogger().Info("Connected to HA peer", "peer", peer)
	return nil
}

// DisconnectPeer closes the connection to a peer.
func (m *manager) DisconnectPeer(peer string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if client, ok := m.peerClients[peer]; ok {
		if err := client.Close(); err != nil {
			return err
		}
		delete(m.peerClients, peer)
		delete(m.lastAdjTime, peer)
		logger.GetLogger().Info("Disconnected from HA peer", "peer", peer)
	}
	return nil
}

// ProcessMemberInfo processes member info from a peer. Called by the server and adjacency loop.
func (m *manager) ProcessMemberInfo(ctx context.Context, peer string, info types.HAPeerMember) (bool, string) {
	if m.validator == nil {
		return false, ""
	}

	// Store the member info on the peer
	memberCopy := info
	m.haStore.UpdatePeerMember(ctx, peer, &memberCopy)

	// Validate
	isDel, reason := m.validator.ValidateMemberInfo(ctx, peer, info)

	// Update member criteria
	m.haStore.UpdatePeerMemberCriterion(ctx, peer, types.HACritPeerCompatible, !isDel)

	// Clear VRF GID criterion when membership fails
	if isDel {
		m.haStore.UpdatePeerAdjacencyCriterion(ctx, peer, types.HACritPeerVrfGid, false)
	}

	// Update partner state
	m.validator.UpdatePartner(ctx, peer, isDel, reason)

	// Update peer service criterion
	svcOk := info.Service == types.SvcStateSuccess
	m.haStore.UpdatePeerAdjacencyCriterion(ctx, peer, types.HACritPeerServiceRedir, svcOk)

	// Compute peer policy criterion
	localInfo := m.haStore.Local()
	polOk := m.validator.ComputePeerPolicy(localInfo.PolicyCheck, localInfo.PolicyRev, info)
	m.haStore.UpdatePeerAdjacencyCriterion(ctx, peer, types.HACritPeerPolicy, polOk)

	// Recompute state
	m.recomputeAndApplyState(ctx)

	return isDel, reason
}

// NotifyRemoval sends a NO_HA adjacency request to a peer.
func (m *manager) NotifyRemoval(ctx context.Context, peer string) {
	logger.GetLogger().Debug("NotifyRemoval", "peer", peer)

	m.mu.RLock()
	client, ok := m.peerClients[peer]
	localIP := m.localIP
	m.mu.RUnlock()

	if !ok || !client.IsConnected() {
		logger.GetLogger().Debug("NotifyRemoval: peer not connected, skip", "peer", peer)
		return
	}

	req := &hav1.AdjRequest{
		HaIp: localIP,
		MbrInfo: &hav1.MbrInfo{
			HaInfo: &hav1.HaInfo{
				Ha: hav1.HA_STATE_NO_HA,
			},
		},
	}

	_, err := client.Adjacency(ctx, req)
	if err != nil {
		logger.GetLogger().Error("Failed to send removal notification", "peer", peer, "error", err)
	}
}

// HandleAdjFailureNotify processes an incoming AdjFailureNotify from a peer.
func (m *manager) HandleAdjFailureNotify(ctx context.Context, peer string, reason string) {
	logger.GetLogger().Info("Received AdjFailureNotify", "peer", peer, "reason", reason)

	local := m.haStore.Local()

	if local.Leader {
		// Leader: mark peer svc state as failure and recompute.
		m.haStore.UpdatePeerSvcState(ctx, peer, types.SvcStateFailure, types.NewReasonString("adj failure notify: "+reason))
		m.recomputeAndApplyState(ctx)
	} else {
		// Follower: set local derived states to switchover / not-ready.
		m.haStore.SetLocalDerivedStates(ctx,
			types.HAStateSwitchover, types.SvcStateFailure,
			types.NewReasonString("adj failure notify from leader: "+reason),
			types.NewReasonString("adj failure notify from leader"),
		)
	}
}

// sendAdjFailureNotify sends an AdjFailureNotify to a peer.
func (m *manager) sendAdjFailureNotify(ctx context.Context, peer string, reason string) {
	m.mu.RLock()
	client, ok := m.peerClients[peer]
	localIP := m.localIP
	m.mu.RUnlock()

	if !ok || !client.IsConnected() {
		logger.GetLogger().Debug("sendAdjFailureNotify: peer not connected", "peer", peer)
		return
	}

	req := &hav1.NotifyRequest{
		HaIp: localIP,
	}

	resp, err := client.Notify(ctx, req)
	if err != nil {
		logger.GetLogger().Warn("AdjFailureNotify failed", "peer", peer, "error", err)
		return
	}

	if resp.Status != hav1.ADJ_RESPONSE_STATUS_ADJ_SUCCESS {
		logger.GetLogger().Warn("AdjFailureNotify rejected", "peer", peer, "details", resp.Details)
	}
}

// recomputeAndApplyState recalculates CriteriaMet and derived HA/SVC states.
func (m *manager) recomputeAndApplyState(ctx context.Context) {
	if m.stateMachine == nil || m.haStore == nil {
		return
	}

	// Recalculate CriteriaMet with anti-flapping
	local := m.haStore.Local()
	updated := m.stateMachine.RecalculateCriteriaMet(local)
	if updated.CriteriaMet != local.CriteriaMet || updated.CriteriaRecoveryPending != local.CriteriaRecoveryPending {
		m.haStore.SetLocalCriteriaMet(ctx, updated)
	}

	// Compute derived states
	result := m.stateMachine.ComputeState()
	currentLocal := m.haStore.Local()

	if result.HaState == types.HAStateReady && !currentLocal.AdjacencyReached {
		m.haStore.SetLocalAdjacencyReached(ctx, true)
		logger.GetLogger().Info("HA_READY reached for the first time")
	}

	m.haStore.SetLocalDerivedStates(ctx, result.HaState, result.SvcState, result.HaReason, result.SvcReason)
}

// haUpdateNx performs debounced gNMI SET for HA state and service state.
func (m *manager) haUpdateNx(ctx context.Context) {
	if m.haStore == nil {
		return
	}

	local := m.haStore.Local()
	now := time.Now().Unix()
	nxUpdateSec := int64(NxUpdateTimeout / time.Second)

	// Process service state only when SF is configured (InServiceState != "").
	// Mirrors the old n.Configured gate: only push svc state/redirects to NX-OS
	// once the service function path has been seen.
	if m.deviceStore == nil || m.deviceStore.InServiceState() != "" {
		if local.SvcStateEpoch != 0 && now-local.SvcStateEpoch > nxUpdateSec {
			if err := m.haStore.SetLocalSvcState(ctx, local.SvcState, local.SvcStateReason); err != nil {
				logger.GetLogger().Warn("Failed to set local svc state", "error", err)
			}
		}
	}

	// Then process HA state
	if local.HaStateEpoch != 0 && now-local.HaStateEpoch > nxUpdateSec {
		if err := m.haStore.SetLocalHaState(ctx, local.HaState, local.HaStateReason); err != nil {
			logger.GetLogger().Warn("Failed to set local ha state", "error", err)
		}
	}
}

// checkHoldDown checks the anti-flapping hold-down timer.
func (m *manager) checkHoldDown(ctx context.Context) {
	if m.stateMachine == nil || m.haStore == nil {
		return
	}

	local := m.haStore.Local()
	promoted, updated := m.stateMachine.CheckHoldDown(local)
	if promoted {
		m.haStore.SetLocalCriteriaMet(ctx, updated)
		m.recomputeAndApplyState(ctx)
	}
}

// checkAdjMbrTimeouts checks for timed out members and adjacencies.
func (m *manager) checkAdjMbrTimeouts(ctx context.Context) {
	if m.haStore == nil {
		return
	}

	now := time.Now().Unix()
	mbrTimeoutSec := int64(MemberTimeout / time.Second)

	peers := m.haStore.AllPeers()
	for ip, peer := range peers {
		// Check member timeout
		if peer.MemberInfo != nil && peer.MemberCriteriaMetEpoch > 0 && now-peer.MemberCriteriaMetEpoch > mbrTimeoutSec {
			logger.GetLogger().Debug("Member timed out", "ip", ip)
			m.haStore.UpdatePeerMember(ctx, ip, nil)
		}

		// Check adjacency timeout
		if peer.AdjacencyConnected && peer.AdjacencyConnectedEpoch > 0 && now-peer.AdjacencyConnectedEpoch > int64(AdjacencyTimeout/time.Second) {
			logger.GetLogger().Debug("Adjacency timed out", "ip", ip)
			m.haStore.UpdatePeerAdjacency(ctx, ip, false, 0)
			m.haStore.UpdatePeerSvcState(ctx, ip, types.SvcStateUnknown, types.NewReasonString("adjacency timed out"))
			if err := m.haStore.SetRemoteStatesAdjDown(ctx, ip); err != nil {
				logger.GetLogger().Warn("Failed to set remote states adj down", "peer", ip, "error", err)
			}
		}
	}
}

// checkAdjacencies checks adjacencies with all configured peers.
func (m *manager) checkAdjacencies(ctx context.Context) {
	if m.haStore == nil {
		return
	}

	peers := m.haStore.AllPeers()
	if len(peers) == 0 {
		return
	}

	localInfo := m.buildMemberInfo()

	for ip, peer := range peers {
		if !peer.AdjacencyCriteria[types.HACritPeerIpConfig] {
			continue
		}

		if err := m.ConnectPeer(ctx, ip); err != nil {
			logger.GetLogger().Debug("Failed to connect to peer", logfields.Error, err, "peer", ip)
			m.handlePeerFailure(ctx, ip)
			continue
		}

		if err := m.sendAdjacency(ctx, ip, localInfo); err != nil {
			logger.GetLogger().Debug("Adjacency failed", logfields.Error, err, "peer", ip)
			m.handlePeerFailure(ctx, ip)
			continue
		}

		// Update adjacency state
		m.haStore.UpdatePeerAdjacency(ctx, ip, true, time.Now().Unix())

		m.mu.Lock()
		m.lastAdjTime[ip] = time.Now()
		m.mu.Unlock()
	}

	// Perform leader election
	m.electLeader(ctx)
}

// sendAdjacency sends an adjacency request to a peer.
func (m *manager) sendAdjacency(ctx context.Context, peer string, localInfo types.HAPeerMember) error {
	m.mu.RLock()
	client, ok := m.peerClients[peer]
	localIP := m.localIP
	m.mu.RUnlock()

	if !ok || !client.IsConnected() {
		return fmt.Errorf("not connected to peer %s", peer)
	}

	sysInfo := &hav1.SysInfo{
		SerNum: localInfo.SerialNum,
		Model:  localInfo.Model,
		SwVer:  localInfo.SWVersion,
		Cpa:    localInfo.CPAVersion,
		LbMode: localInfo.LbMode,
	}
	for _, dpu := range localInfo.DPUs {
		sysInfo.Dpus = append(sysInfo.Dpus, &hav1.DpuVer{
			Name:    dpu.Name,
			Version: dpu.Version,
		})
	}

	req := &hav1.AdjRequest{
		HaIp: localIP,
		MbrInfo: &hav1.MbrInfo{
			SysInfo: sysInfo,
			PolInfo: &hav1.PolInfo{
				Revision: localInfo.PolicyRev,
				Watching: localInfo.PolicyCheck,
			},
		},
	}

	// Add VRF and VLAN info for reconciliation
	if m.vrfStore != nil {
		req.MbrInfo.VrfInfo = BuildLocalVRFInfo(m.vrfStore)
	}
	if m.vlanStore != nil {
		req.MbrInfo.VlanInfo = BuildLocalVLANInfo(m.vlanStore)
	}

	// Add HA state info
	local := m.haStore.Local()
	svc := hav1.LOCAL_SVC_STATE_LOCAL_SVC_FAILURE
	if local.CriteriaMet && !local.CriteriaRecoveryPending {
		svc = hav1.LOCAL_SVC_STATE_LOCAL_SVC_SUCCESS
	}
	haState := hav1.HA_STATE_HA_NOTREADY
	switch local.HaState {
	case types.HAStateReady:
		haState = hav1.HA_STATE_HA_READY
	case types.HAStateSwitchover:
		haState = hav1.HA_STATE_HA_SWITCHOVER
	case types.HAStateTakeover:
		haState = hav1.HA_STATE_HA_TAKEOVER
	}
	req.MbrInfo.HaInfo = &hav1.HaInfo{
		LocalSvcState: svc,
		Ha:            haState,
	}

	resp, err := client.Adjacency(ctx, req)
	if err != nil {
		return err
	}

	if resp.Status != hav1.ADJ_RESPONSE_STATUS_ADJ_SUCCESS {
		// Process MbrInfo from failure response to detect criteria failures fast
		if resp.MbrInfo != nil {
			peerInfo := convertMbrInfoToPeerMember(resp.MbrInfo)
			m.ProcessMemberInfo(ctx, peer, peerInfo)
		}
		return fmt.Errorf("adjacency failed: %s", resp.Details)
	}

	// Process peer member info
	if resp.MbrInfo != nil {
		peerInfo := convertMbrInfoToPeerMember(resp.MbrInfo)
		isDel, reason := m.ProcessMemberInfo(ctx, peer, peerInfo)

		// If membership validation failed, notify the peer immediately.
		if isDel {
			m.sendAdjFailureNotify(ctx, peer, "membership failure: "+reason)
		}

		// Reconcile GIDs and VLANs, and set the peer_vrf_gid adjacency criterion.
		if m.reconciler != nil {
			ok, err := m.reconciler.Reconcile(ctx, peer, resp.MbrInfo, localInfo.LbMode)
			if err != nil {
				logger.GetLogger().Warn("HA reconciliation failed", "peer", peer, "error", err)
			}
			m.haStore.UpdatePeerAdjacencyCriterion(ctx, peer, types.HACritPeerVrfGid, ok)
		}
	}

	return nil
}

// sendHeartbeats sends heartbeat messages to all connected peers.
func (m *manager) sendHeartbeats(ctx context.Context) {
	if m.haStore == nil {
		return
	}

	m.mu.RLock()
	localIP := m.localIP
	m.mu.RUnlock()

	peers := m.haStore.AllPeers()
	for ip, peer := range peers {
		if peer.SvcState != types.SvcStateSuccess {
			continue
		}
		if !peer.AdjacencyCriteria[types.HACritPeerIpConfig] {
			continue
		}

		m.mu.RLock()
		client, ok := m.peerClients[ip]
		m.mu.RUnlock()

		if !ok || !client.IsConnected() {
			continue
		}

		req := &hav1.AdjRequest{
			HaIp: localIP,
		}

		_, err := client.Adjacency(ctx, req)
		if err != nil {
			logger.GetLogger().Debug("Heartbeat failed", "peer", ip, "error", err)
			continue
		}

		m.mu.Lock()
		m.lastHeartbeatTime[ip] = time.Now()
		m.mu.Unlock()
	}
}

// checkHeartbeatTimeouts checks for peers that have exceeded the heartbeat timeout.
func (m *manager) checkHeartbeatTimeouts(ctx context.Context) {
	if m.haStore == nil {
		return
	}

	m.mu.RLock()
	heartbeatTimes := make(map[string]time.Time, len(m.lastHeartbeatTime))
	for k, v := range m.lastHeartbeatTime {
		heartbeatTimes[k] = v
	}
	m.mu.RUnlock()

	now := time.Now()
	peers := m.haStore.AllPeers()
	reelectionNeeded := false

	for ip, peer := range peers {
		if peer.SvcState != types.SvcStateSuccess {
			continue
		}

		lastHeartbeat, ok := heartbeatTimes[ip]
		if !ok {
			m.mu.Lock()
			m.lastHeartbeatTime[ip] = now
			m.mu.Unlock()
			continue
		}

		if now.Sub(lastHeartbeat) > HeartbeatTimeout {
			logger.GetLogger().Warn("Peer heartbeat timeout", "peer", ip, "lastHeartbeat", lastHeartbeat)
			m.haStore.UpdatePeerSvcState(ctx, ip, types.SvcStateUnknown, types.NewReasonString("heartbeat timeout"))
			reelectionNeeded = true
		}
	}

	if reelectionNeeded {
		logger.GetLogger().Info("Triggering re-election due to heartbeat timeout")
		m.electLeader(ctx)
	}
}

// handlePeerFailure handles a peer failure.
func (m *manager) handlePeerFailure(ctx context.Context, peer string) {
	m.mu.Lock()
	lastAdj, ok := m.lastAdjTime[peer]
	m.mu.Unlock()

	if ok && time.Since(lastAdj) > AdjacencyTimeout {
		logger.GetLogger().Warn("Peer adjacency timeout", "peer", peer)
		m.haStore.UpdatePeerSvcState(ctx, peer, types.SvcStateUnknown, types.NewReasonString("peer adjacency timeout"))
		m.DisconnectPeer(peer)
	}
}

// electLeader performs leader election using the lowest IP address wins rule.
func (m *manager) electLeader(ctx context.Context) {
	if m.haStore == nil {
		return
	}

	m.mu.RLock()
	localIPStr := m.localIP
	m.mu.RUnlock()

	if localIPStr == "" {
		return
	}

	localIP := net.ParseIP(localIPStr)
	if localIP == nil {
		logger.GetLogger().Warn("Invalid local IP for leader election", "ip", localIPStr)
		return
	}

	isLeader := true
	peers := m.haStore.AllPeers()
	for ip, peer := range peers {
		if peer.SvcState != types.SvcStateSuccess {
			continue
		}

		peerIP := net.ParseIP(ip)
		if peerIP == nil {
			continue
		}

		if compareIPs(peerIP, localIP) < 0 {
			isLeader = false
			break
		}
	}

	currentLeader := m.haStore.IsLeader()
	if isLeader != currentLeader {
		logger.GetLogger().Info("Leader status changed", "isLeader", isLeader, "localIP", localIPStr)
		m.haStore.SetLeader(ctx, isLeader)
	}
}

// resolveDpuUid resolves an IP-based DPU UID to a DPU name using the dpuStore.
// This ensures consistency with pre-populated entries which use DPU names as keys.
func (m *manager) resolveDpuUid(uid string) string {
	if m.dpuStore != nil {
		for _, d := range m.dpuStore.List() {
			if d.IP == uid {
				return d.Name
			}
		}
	}
	return uid
}

// RegisterDpu registers a DPU with the HA manager.
func (m *manager) RegisterDpu(ctx context.Context, dpuUid string) {
	dpuUid = m.resolveDpuUid(dpuUid)
	m.mu.Lock()
	if _, ok := m.dpuStatuses[dpuUid]; !ok {
		s := &dpuStatus{}
		if m.dpuStore != nil && m.dpuStore.IsSkipDPU() {
			s.keepaliveUp = true
			s.bulkSyncLocal = true
			s.bulkSyncPeer = true
		}
		m.dpuStatuses[dpuUid] = s
	}
	m.mu.Unlock()
	m.aggregateDPUStatus(ctx)
}

// UpdateKeepalive updates the keepalive status for a DPU.
func (m *manager) UpdateKeepalive(ctx context.Context, dpuUid string, up bool) {
	if m.dpuStore != nil && m.dpuStore.IsSkipDPU() {
		return
	}
	dpuUid = m.resolveDpuUid(dpuUid)
	m.mu.Lock()
	s, ok := m.dpuStatuses[dpuUid]
	if !ok {
		s = &dpuStatus{}
		m.dpuStatuses[dpuUid] = s
	}
	s.keepaliveUp = up
	m.mu.Unlock()
	m.aggregateDPUStatus(ctx)
}

// UpdateBulkSyncLocal updates the local bulk-sync status for a DPU.
func (m *manager) UpdateBulkSyncLocal(ctx context.Context, dpuUid string, done bool) {
	if m.dpuStore != nil && m.dpuStore.IsSkipDPU() {
		return
	}
	dpuUid = m.resolveDpuUid(dpuUid)
	m.mu.Lock()
	s, ok := m.dpuStatuses[dpuUid]
	if !ok {
		s = &dpuStatus{}
		m.dpuStatuses[dpuUid] = s
	}
	s.bulkSyncLocal = done
	m.mu.Unlock()
	m.aggregateDPUStatus(ctx)
}

// UpdateBulkSyncPeer updates the peer bulk-sync status for a DPU.
func (m *manager) UpdateBulkSyncPeer(ctx context.Context, dpuUid string, done bool) {
	if m.dpuStore != nil && m.dpuStore.IsSkipDPU() {
		return
	}
	dpuUid = m.resolveDpuUid(dpuUid)
	m.mu.Lock()
	s, ok := m.dpuStatuses[dpuUid]
	if !ok {
		s = &dpuStatus{}
		m.dpuStatuses[dpuUid] = s
	}
	s.bulkSyncPeer = done
	m.mu.Unlock()
	m.aggregateDPUStatus(ctx)
}

// UpdatePolicyRevision stores the latest policy revision from a DPU.
func (m *manager) UpdatePolicyRevision(ctx context.Context, revision string) {
	if m.haStore != nil {
		m.haStore.SetLocalPolicyRevision(ctx, revision)
	}
}

// aggregateDPUStatus computes aggregate keepalive/bulk-sync criteria from all DPUs
// and updates per-peer adjacency criteria and DPU status snapshots in the HA store.
func (m *manager) aggregateDPUStatus(ctx context.Context) {
	if m.haStore == nil {
		return
	}

	m.mu.RLock()
	n := len(m.dpuStatuses)
	allKeepaliveUp := n > 0
	allBulkSyncDone := n > 0
	snapshot := make(map[string]types.DPUHAStatus, n)
	for uid, s := range m.dpuStatuses {
		if !s.keepaliveUp {
			allKeepaliveUp = false
		}
		if !s.bulkSyncLocal || !s.bulkSyncPeer {
			allBulkSyncDone = false
		}
		snapshot[uid] = types.DPUHAStatus{
			KeepaliveUp:   s.keepaliveUp,
			BulkSyncLocal: s.bulkSyncLocal,
			BulkSyncPeer:  s.bulkSyncPeer,
		}
	}
	m.mu.RUnlock()

	for _, ip := range m.haStore.PeerIPs() {
		m.haStore.UpdatePeerAdjacencyCriterion(ctx, ip, types.HACritPeerDPUKeepalive, allKeepaliveUp)
		m.haStore.UpdatePeerAdjacencyCriterion(ctx, ip, types.HACritPeerDPUBulkSync, allBulkSyncDone)
		m.haStore.UpdatePeerDPUStatuses(ctx, ip, snapshot)
	}
}

// compareIPs compares two IP addresses.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func compareIPs(a, b net.IP) int {
	a = a.To16()
	b = b.To16()

	for i := 0; i < len(a); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// Ensure implementation satisfies the interface
var _ Manager = (*manager)(nil)
