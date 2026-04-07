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

	"github.com/isovalent/hubble-fgs/pkg/config/library"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/device"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/dpu"
	hastore "github.com/isovalent/hubble-fgs/pkg/nxos/store/ha"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/vlan"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/vrf"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
	hav1 "github.com/isovalent/hubble-fgs/pkg/proto/ha/v1"
	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

// haPort returns the HA gRPC port reserved from the device store's HSA port range.
// Returns an error if the device store is not configured.
func (m *manager) haPort() (uint16, error) {
	if m.deviceStore == nil {
		return 0, fmt.Errorf("device store not configured: cannot determine HA port")
	}
	return m.deviceStore.ReservePort(device.HAService)
}

// syncServerToAdminState starts or stops the HA server based on the current admin state.
func (m *manager) syncServerToAdminState(ctx context.Context) {
	if m.haStore.Enabled() == hastore.AdminStateEnabled {
		m.startServer(ctx)
	} else {
		m.stopServer()
	}
}

// startServer starts the HA gRPC server if not already running.
// Should only be called when admin state is enabled.
func (m *manager) startServer(ctx context.Context) {
	// Fast path: check without write lock first.
	m.mu.RLock()
	if m.server != nil {
		m.mu.RUnlock()
		return
	}
	m.mu.RUnlock()

	// Prepare server and port outside the lock to minimise lock contention.
	srv := NewServer(
		WithHAStore(m.haStore),
		WithManager(m),
		WithMemberInfoProvider(m.buildMemberInfo),
		WithServerVRFStore(m.vrfStore),
		WithServerVLANStore(m.vlanStore),
		WithServerReconciler(m.reconciler),
	)

	port, err := m.haPort()
	if err != nil {
		logger.GetLogger().Error("Failed to reserve HA port, cannot start server", logfields.Error, err)
		return
	}

	serverCtx, serverCancel := context.WithCancel(ctx)

	// Re-check under write lock to guard against a concurrent startServer call.
	m.mu.Lock()
	if m.server != nil {
		m.mu.Unlock()
		serverCancel()
		return
	}
	m.server = srv
	m.serverCtx = serverCtx
	m.serverCancel = serverCancel
	// Add to WaitGroup inside the lock so stopServer's Wait() never misses this goroutine.
	m.serverWg.Add(1)
	m.mu.Unlock()

	logger.GetLogger().Info("Starting HA server", "port", port)

	if err := m.haStore.SetHaPort(serverCtx, port); err != nil {
		logger.GetLogger().Warn("Failed to SET HA port to gNMI", "port", port, "error", err)
	}

	// Start server in background with retry/backoff.
	go func() {
		defer m.serverWg.Done()

		// Single goroutine to trigger GracefulStop on context cancellation.
		go func() {
			<-serverCtx.Done()
			srv.Stop()
		}()

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
}

// stopServer stops the HA gRPC server if running.
func (m *manager) stopServer() {
	m.mu.Lock()
	if m.server == nil {
		m.mu.Unlock()
		return
	}
	serverCancel := m.serverCancel
	m.mu.Unlock()

	logger.GetLogger().Info("Stopping HA server")
	serverCancel()
	m.serverWg.Wait()

	m.mu.Lock()
	m.server = nil
	m.serverCtx = nil
	m.serverCancel = nil
	m.mu.Unlock()
}

// holdDownChan returns the channel for the hold-down timer, or nil if no timer is active.
// A nil channel blocks forever in a select, effectively disabling the case.
func (m *manager) holdDownChan() <-chan time.Time {
	if m.holdDownTimer != nil {
		return m.holdDownTimer.C
	}
	return nil
}

// isConfigReady returns true when all three prerequisites for HA activation are met:
//   - HA is enabled
//   - at least one peer is configured
//   - service function is configured (InServiceState != ""), or deviceStore is nil (no gating)
func (m *manager) isConfigReady() bool {
	if m.haStore.Enabled() != hastore.AdminStateEnabled || len(m.haStore.PeerIPs()) == 0 {
		return false
	}
	if m.haStore.HaIP() == "" {
		return false
	}
	if m.deviceStore != nil && m.deviceStore.InServiceState() == "" {
		return false
	}
	return true
}

// computeAndPushSvcOnly computes svc state from raw local criteria and pushes it to
// NX-OS without touching HA state. Used in waitForConfig where HA is not yet active
// (no peers or HA not enabled) but SF is configured and DPUs are reporting.
// No anti-flap hold-down is applied — svc state directly reflects Criteria.AllOk().
func (m *manager) computeAndPushSvcOnly(ctx context.Context) {
	if m.haStore == nil {
		return
	}
	local := m.haStore.Local()
	criteriaMet := local.Criteria.AllOk()

	// Keep CriteriaMet in sync with raw criteria (no anti-flap hold-down in pre-HA).
	// This ensures a smooth transition when HA activates — recomputeAndApplyState
	// sees CriteriaMet already true and skips the 30s hold-down.
	if criteriaMet != local.CriteriaMet {
		local.CriteriaMet = criteriaMet
		local.CriteriaMetEpoch = time.Now().Unix()
		local.CriteriaRecoveryPending = false
		local.CriteriaRecoveryEpoch = 0
		m.haStore.SetLocalCriteriaMet(ctx, local)
	}

	svcState := types.SvcStateSuccess
	var svcReason types.ReasonString
	if criteriaMet {
		svcReason = types.NewReasonString("all criteria met")
	} else {
		svcState = types.SvcStateFailure
		svcReason = types.NewReasonString(
			fmt.Sprintf("criteria not met: %s", failedLocalCriteria(local)))
	}
	// Pass current HA state/reason unchanged so haChanged=false and no HA gNMI write occurs.
	pushSvcToNx := m.deviceStore == nil || m.deviceStore.InServiceState() != ""
	m.haStore.SetLocalDerivedStates(ctx,
		local.HaState, svcState,
		local.HaStateReason, svcReason,
		pushSvcToNx)
}

// computeAndPushHaConfig computes the HaConfig from store state and pushes it to
// the config library, which triggers fan-out to DPUs via the registered callback.
// This implements the old updateHaConfig() logic:
//   - Enabled:  adminEnabled && operUp && peers > 0
//   - FlowSync: Enabled && haEnabled (admin enabled && oper up)
func (m *manager) computeAndPushHaConfig() {
	if m.haStore == nil {
		return
	}

	// Read store state
	enabled := m.haStore.Enabled()
	switchState := m.haStore.SwitchState()
	peerIPs := m.haStore.PeerIPs()
	haIP := m.haStore.HaIP()

	// Compute conditions (matching old doUpdateHaConfig logic)
	operUp := switchState == hastore.SwitchStateHaReady         // NxHaOperState operational
	haEnabled := enabled == hastore.AdminStateEnabled && operUp // admin enabled AND oper up

	// Check inService criterion: default to true if not set (matches old behavior)
	inService := true
	if v, ok := m.haStore.Local().Criteria[types.HACritInService]; ok {
		inService = v
	}

	// haIp must be non-empty and not 0.0.0.0 (matches old haIp validation)
	haIpValid := haIP != "" && haIP != "0.0.0.0"

	shouldEnable := enabled == hastore.AdminStateEnabled && operUp && len(peerIPs) > 0 && haIpValid && inService

	// If conditions not met, push config with enabled=false (matches old doUpdateHaConfig
	// behavior — DPUs expect UPDATE with enabled=false, not DELETE).
	if !shouldEnable {
		disabledConfig := &v1alpha.ConfigObject{
			Type:   v1alpha.ConfigType_CONFIG_TYPE_HA,
			Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
			Config: &v1alpha.ConfigObject_ConfigHa{ConfigHa: &v1alpha.HaConfig{
				Enabled:  false,
				FlowSync: false,
				HaIp:     haIP,
			}},
		}
		err := library.GetRepository().UpdateConfig(v1alpha.ConfigType_CONFIG_TYPE_HA,
			func(existing *v1alpha.ConfigObject) (*v1alpha.ConfigObject, error) {
				return disabledConfig, nil
			})
		if err != nil {
			logger.GetLogger().Error("Failed to update HaConfig (disabled) in config library", logfields.Error, err)
		}
		return
	}

	// Get global port range for peers
	var portLow, portHigh uint32
	if m.dpuStore != nil {
		low, high := m.dpuStore.GetGlobalPortRange()
		portLow = uint32(low)
		portHigh = uint32(high)
	}

	// Build peers list
	peers := make([]*v1alpha.HaPeer, 0, len(peerIPs))
	for _, ip := range peerIPs {
		peers = append(peers, &v1alpha.HaPeer{
			Ip:      ip,
			MinPort: portLow,
			MaxPort: portHigh,
		})
	}

	// Build HaConfig
	haConfig := &v1alpha.HaConfig{
		Enabled:  shouldEnable,
		FlowSync: shouldEnable && haEnabled && m.allDPUKeepaliveUp(),
		HaIp:     haIP,
		Peers:    peers,
	}

	configObj := &v1alpha.ConfigObject{
		Type:   v1alpha.ConfigType_CONFIG_TYPE_HA,
		Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
		Config: &v1alpha.ConfigObject_ConfigHa{ConfigHa: haConfig},
	}

	// UpdateConfig is atomic and no-ops if unchanged (proto.Equal check)
	err := library.GetRepository().UpdateConfig(v1alpha.ConfigType_CONFIG_TYPE_HA,
		func(existing *v1alpha.ConfigObject) (*v1alpha.ConfigObject, error) {
			return configObj, nil
		})
	if err != nil {
		logger.GetLogger().Error("Failed to update HaConfig in config library", logfields.Error, err)
	}
}

const (
	// HAKeepaliveInterval is the interval between adjacency keepalive checks.
	HAKeepaliveInterval = 5 * time.Second

	// HATimeout is the timeout for considering a peer adjacency or member as expired.
	HATimeout = 10 * time.Second
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
	HandleRemoval(ctx context.Context, peer string)
	HandleAdjFailureNotify(ctx context.Context, peer string, reason string)
	ProcessHaInfo(ctx context.Context, peer string, haInfo *hav1.HaInfo)

	// DPU HA event handling (satisfies switchpolicy.HaEventHandler interface).
	RegisterDpu(ctx context.Context, dpuUid string)
	UpdateKeepalive(ctx context.Context, dpuUid string, up bool)
	UpdateBulkSyncLocal(ctx context.Context, dpuUid string, done bool)
	UpdateBulkSyncPeer(ctx context.Context, dpuUid string, done bool)
	UpdatePolicyRevision(ctx context.Context, revision string)

	// Debug overrides for HA testing.
	SetDebugPeerFail(ctx context.Context, peer string, membership, adjacency bool)
	SetDebugPeerOk(ctx context.Context, peer string)
	SetDebugFail(ctx context.Context, fail bool)

	// Service failure notification before shutdown.
	NotifyServiceFailure(ctx context.Context)
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

	// holdDownTimer fires once when the CriteriaMet recovery hold-down expires.
	// nil when no recovery is pending. Only accessed from the runActive goroutine.
	holdDownTimer *time.Timer

	// Server lifecycle — managed independently by startServer/stopServer
	server       Server
	serverCtx    context.Context
	serverCancel context.CancelFunc
	serverWg     sync.WaitGroup
}

// NewManager creates a new HA manager.
func NewManager(opts ...ManagerOption) Manager {
	m := &manager{
		peerClients: make(map[string]Client),
		lastAdjTime: make(map[string]time.Time),
		dpuStatuses: make(map[string]*dpuStatus),
		clientFactory: func() Client {
			return NewClient()
		},
	}

	for _, opt := range opts {
		opt(m)
	}

	// Pre-populate per-DPU status from dpuStore.
	// When DPUs are skipped for testing, do not populate any DPU entries;
	// the DPU count stays at 0 and DPU criteria are never added to the map.
	if m.dpuStore != nil && !m.dpuStore.IsSkipDPU() {
		for _, d := range m.dpuStore.List() {
			m.dpuStatuses[d.Name] = &dpuStatus{}
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
		info.CPAVersion = m.deviceStore.CPAVersion()
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
		SerialNum:  m.deviceStore.SerialNumber(),
		Model:      m.deviceStore.Model(),
		SWVersion:  m.deviceStore.SoftwareVersion(),
		CPAVersion: m.deviceStore.CPAVersion(),
		LbMode:     m.deviceStore.LbMode(),
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

	// Start server if already enabled at startup.
	m.syncServerToAdminState(ctx)

	// Ensure server is stopped on exit
	defer m.stopServer()

	for {
		// Wait until all prerequisites are met: HA enabled, peers configured, SF configured.
		if !m.isConfigReady() {
			logger.GetLogger().Info("HA manager waiting for configuration")
			// Seed all local criteria from current state so AllOk() has a complete
			// picture on the first svc push, not just whatever events have fired so far.
			// HACritInService is only set in the activation block otherwise; DPU criteria
			// may not yet be present if the relevant nxos.Manager events haven't arrived.
			if m.deviceStore != nil {
				m.haStore.UpdateLocalCriterion(ctx, types.HACritInService, m.deviceStore.IsInService())
			}
			if m.dpuStore != nil && !m.dpuStore.IsSkipDPU() {
				m.haStore.UpdateLocalCriterion(ctx, types.HACritDpuHealth, m.dpuStore.IsHealthy())
				m.haStore.UpdateLocalCriterion(ctx, types.HACritDpuInSync, m.dpuStore.IsInSync())
			}
			m.computeAndPushSvcOnly(ctx)
			if done := m.waitForConfig(ctx, storeCh, deviceCh); done {
				logger.GetLogger().Info("HA manager Run exiting")
				return nil
			}
		}

		// Activate: read local IP, run event loop.
		// Server lifecycle is managed independently via EventAdminStateChanged.
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

		logger.GetLogger().Info("HA manager activating", "localIP", m.localIP)

		// Restart server if it was stopped during a prior deactivation.
		m.syncServerToAdminState(ctx)

		// Set initial HACritInService criterion based on current in-service state.
		if m.deviceStore != nil {
			m.haStore.UpdateLocalCriterion(ctx, types.HACritInService, m.deviceStore.IsInService())
		}

		// Pre-populate local DPU criteria as false when DPUs are expected and criteria
		// have not already been set. Criteria may already be set if DPU health events
		// arrived during waitForConfig (pre-HA phase). Only seed false on cold start
		// (criteria absent) to prevent a brief "ready" state before DPU events arrive.
		if m.dpuStore != nil && !m.dpuStore.IsSkipDPU() && len(m.dpuStore.List()) > 0 {
			activationCriteria := m.haStore.Local().Criteria
			if _, ok := activationCriteria[types.HACritDpuHealth]; !ok {
				m.haStore.UpdateLocalCriterion(ctx, types.HACritDpuHealth, false)
			}
			if _, ok := activationCriteria[types.HACritDpuInSync]; !ok {
				m.haStore.UpdateLocalCriterion(ctx, types.HACritDpuInSync, false)
			}
		}

		// Initialize DPU criteria for peers. DPUs may have been loaded into
		// dpuStore via gNMI after NewManager, but no FWA has connected yet to
		// report keepalive/bulk-sync status. Populate dpuStatuses and write
		// initial false criteria to all peers.
		m.initDPUCriteriaFromStore(ctx)

		// Push initial HaConfig to DPUs now that HA is activated.
		// CriteriaMet is already maintained by computeAndPushSvcOnly during pre-HA.
		m.computeAndPushHaConfig()

		// Run the active event loop (blocks until deactivation or ctx cancellation).
		done := m.runActive(ctx, storeCh, deviceCh)

		// Cleanup: clear HaConfig, disconnect all peers, stop server.
		if err := library.GetRepository().DeleteConfig(v1alpha.ConfigType_CONFIG_TYPE_HA); err != nil {
			logger.GetLogger().Debug("Failed to delete HaConfig on deactivation", logfields.Error, err)
		}
		m.stopServer()
		m.disconnectAllPeers(ctx)
		// Reset HA-domain local state on deactivation. Clears ha_standby and other
		// HA-domain criteria so they don't persist into the next waitForConfig phase
		// (where they would cause stale "syncing: ha_standby" svc state).
		// Preserves svc criteria (dpu_healthy, dpu_insync, in_service).
		m.haStore.ResetLocalHaState(ctx)

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
			case hastore.EventAdminStateChanged:
				m.syncServerToAdminState(ctx)
				// Recompute svc state: ha-items deletion fires ResetLocalHaState
				// (clearing ha_standby) then EventAdminStateChanged — without this
				// the stale "syncing: ha_standby" reason would persist in waitForConfig.
				m.computeAndPushSvcOnly(ctx)
				if m.isConfigReady() {
					return false
				}
			case hastore.EventSwitchStateChanged,
				hastore.EventPeerAdded, hastore.EventHaIPChanged:
				if m.isConfigReady() {
					return false
				}
			case hastore.EventCriterionChanged, hastore.EventCriterionSet:
				// Push svc state to NX-OS even while waiting for full HA config,
				// so the switch reflects DPU/service readiness independently of HA.
				m.computeAndPushSvcOnly(ctx)
				if m.isConfigReady() {
					return false
				}
			}
		case event := <-deviceCh:
			if event.Type == device.EventInServiceChanged {
				if m.deviceStore != nil {
					m.haStore.UpdateLocalCriterion(ctx, types.HACritInService, m.deviceStore.IsInService())
				}
				m.computeAndPushSvcOnly(ctx)
				if m.isConfigReady() {
					return false
				}
			}
		}
	}
}

// runActive is the active event loop. It blocks until HA is deconfigured or ctx is cancelled.
// Returns true if the caller should exit (ctx done), false if HA was deconfigured.
func (m *manager) runActive(ctx context.Context, storeCh <-chan hastore.Event, deviceCh <-chan device.Event) bool {
	// Track peer connection goroutines so they don't outlive the active event loop.
	var peerWg sync.WaitGroup
	defer peerWg.Wait()

	ticker := time.NewTicker(HAKeepaliveInterval)
	defer ticker.Stop()

	logger.GetLogger().Debug("HA active event loop started")

	for {
		select {
		case <-ctx.Done():
			if m.holdDownTimer != nil {
				m.holdDownTimer.Stop()
				m.holdDownTimer = nil
			}
			logger.GetLogger().Debug("HA active event loop stopped (ctx done)")
			return true

		case event := <-storeCh:
			switch event.Type {
			case hastore.EventAdminStateChanged:
				m.syncServerToAdminState(ctx)
				// Recompute config — if HA became disabled, computeAndPushHaConfig
				// pushes enabled=false. If still enabled, it recomputes normally.
				m.computeAndPushHaConfig()
				if m.haStore.Enabled() != hastore.AdminStateEnabled {
					if m.holdDownTimer != nil {
						m.holdDownTimer.Stop()
						m.holdDownTimer = nil
					}
					// Clear HA-domain criteria first so svc state computation
					// only reflects service health, not stale HA criteria
					// (e.g. ha_standby). Without this, svc state flaps to
					// failure then back to success when computeAndPushSvcOnly
					// runs in waitForConfig.
					m.haStore.ResetLocalHaState(ctx)

					// Push final states to NX-OS while the switch HA container
					// is still up (ha-ready window after admin disable).
					// Compute svc state from svc-domain criteria rather than
					// hardcoding failure — the service may still be healthy.
					pushSvcToNx := m.deviceStore == nil || m.deviceStore.InServiceState() != ""
					local := m.haStore.Local()
					svcState := types.SvcStateSuccess
					var svcReason types.ReasonString
					if local.Criteria.AllOk() {
						svcReason = types.NewReasonString("all criteria met")
					} else {
						svcState = types.SvcStateFailure
						svcReason = types.NewReasonString(
							fmt.Sprintf("criteria not met: %s", failedLocalCriteria(local)))
					}
					haReason := types.NewReasonString("HA disabled")
					m.haStore.SetLocalDerivedStates(ctx,
						types.HAStateNotReady, svcState,
						haReason, svcReason, pushSvcToNx)
					for _, ip := range m.haStore.PeerIPs() {
						m.haStore.UpdatePeerHaState(ctx, ip, types.PeerHAStateNoHa, haReason)
						m.haStore.UpdatePeerSvcState(ctx, ip, types.SvcStateUnknown, haReason)
					}
					logger.GetLogger().Info("HA disabled, deactivating")
					return false
				}
			case hastore.EventSwitchStateChanged:
				// Switch oper state changed (e.g., ha-ready <-> standalone).
				m.computeAndPushHaConfig()
			case hastore.EventCriterionChanged, hastore.EventCriterionSet, hastore.EventPeerCriteriaUpdated:
				m.recomputeAndApplyState(ctx)
			case hastore.EventLeaderChanged:
				// Immediately push the updated leader status to peers so they can
				// re-evaluate election without waiting for the next adjacency cycle.
				go m.haNotifyPeers(ctx)
			case hastore.EventPeerAdded:
				peerWg.Add(1)
				go func(ip string) {
					defer peerWg.Done()
					if err := m.ConnectPeer(ctx, ip); err != nil {
						logger.GetLogger().Debug("Failed to connect to new peer", logfields.Error, err, "peer", ip)
					}
				}(event.PeerIP)
				// Peer added -- recompute config to include new peer.
				m.computeAndPushHaConfig()
			case hastore.EventPeerRemoved:
				if err := m.DisconnectPeer(event.PeerIP); err != nil {
					logger.GetLogger().Debug("Failed to disconnect peer", logfields.Error, err, "peer", event.PeerIP)
				}
				// Peer removed -- recompute config to exclude removed peer.
				m.computeAndPushHaConfig()
			case hastore.EventHaIPChanged:
				newIP := m.haStore.HaIP()
				m.mu.Lock()
				if newIP != "" {
					m.localIP = newIP
				}
				m.mu.Unlock()
				logger.GetLogger().Info("HA source IP updated", "localIP", newIP)
				m.computeAndPushHaConfig()
			}

		case devEvent := <-deviceCh:
			if devEvent.Type == device.EventInServiceChanged {
				// Update HACritInService based on in-service state.
				// Both value updates ("out-of-service") and path deletions
				// ("") flow through SetInService and arrive here.
				isInService := devEvent.Status == "in-service"
				m.haStore.UpdateLocalCriterion(ctx, types.HACritInService, isInService)
				logger.GetLogger().Info("HACritInService updated", "in-service", isInService)
				// Recompute HA config since inService affects the enabled computation.
				m.computeAndPushHaConfig()

				// Immediately notify peers of service failure so they can
				// transition to HA_TAKEOVER without waiting for adjacency
				// timeout. Mirrors old code: hubble-fgs/pkg/nxos/handler.go:616
				if !isInService {
					m.NotifyServiceFailure(ctx)
				}

				// Service function removed entirely (fwpolicy-items deleted) —
				// deactivate HA. Returns to the outer Run() loop which re-enters
				// waitForConfig() because isConfigReady() returns false when
				// InServiceState == "".
				if devEvent.Status == "" {
					if m.holdDownTimer != nil {
						m.holdDownTimer.Stop()
						m.holdDownTimer = nil
					}
					logger.GetLogger().Info("Service Firewall removed, deactivating HA")
					return false
				}
			}

		case <-m.holdDownChan():
			m.holdDownTimer = nil // timer is spent
			m.checkHoldDown(ctx)

		case <-ticker.C:
			m.checkAdjacencies(ctx)
			m.checkAdjMbrTimeouts(ctx)

		}
	}
}

// disconnectAllPeers writes cleanup gNMI SETs for all peers then closes connections.
func (m *manager) disconnectAllPeers(ctx context.Context) {
	if m.haStore != nil {
		m.haStore.ResetAllPeerStates(ctx, types.NewReasonString("ha deactivated"))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for peer, client := range m.peerClients {
		if err := client.Close(); err != nil {
			logger.GetLogger().Warn("Failed to close peer connection during deactivation", logfields.Error, err, "peer", peer)
		}
	}
	m.peerClients = make(map[string]Client)
	m.lastAdjTime = make(map[string]time.Time)
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
	isDel, isHardFailure, reason := m.validator.ValidateMemberInfo(ctx, peer, info)

	// Update member criteria: only hard failures (model/version/DPU mismatch)
	// affect membership. Soft failures (svc failure, policy mismatch) do not.
	m.haStore.UpdatePeerMemberCriterion(ctx, peer, types.HACritPeerCompatible, !isHardFailure)

	// Clear VRF GID criterion when membership fails
	if isHardFailure {
		m.haStore.UpdatePeerMemberCriterion(ctx, peer, types.HACritPeerVrfGid, false)
	}

	// Update partner svc state to exactly reflect what the peer reports.
	m.validator.UpdatePartner(ctx, peer, info)

	// Update peer service criterion
	svcOk := info.Service == types.SvcStateSuccess
	m.haStore.UpdatePeerServiceCriterion(ctx, peer, types.HACritPeerService, svcOk)

	// Store remote debug flags propagated from peer via adjacency exchange.
	// Only add the criterion when the peer is actively injecting a failure; remove
	// it when no failure is injected so it doesn't appear as [OK] in the show output.
	if info.DebugMembershipFail {
		m.haStore.UpdatePeerMemberCriterion(ctx, peer, types.HACritDebugMembershipFailRemote, false)
	} else {
		m.haStore.RemovePeerMemberCriterion(ctx, peer, types.HACritDebugMembershipFailRemote)
	}
	if info.DebugAdjacencyFail {
		m.haStore.UpdatePeerAdjacencyCriterion(ctx, peer, types.HACritDebugAdjacencyFailRemote, false)
	} else {
		m.haStore.RemovePeerAdjacencyCriterion(ctx, peer, types.HACritDebugAdjacencyFailRemote)
	}

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

// HandleRemoval processes a NO_HA signal from a peer. The peer is intentionally
// removing HA — clear its runtime state (member info, criteria, adjacency) but
// keep it in config so the adjacency loop can reconnect when HA is re-enabled.
func (m *manager) HandleRemoval(ctx context.Context, peer string) {
	logger.GetLogger().Info("HandleRemoval: peer signaled HA removal", "peer", peer)

	// Clear peer member info.
	m.haStore.UpdatePeerMember(ctx, peer, nil)

	// Reset adjacency state.
	m.haStore.UpdatePeerConnected(ctx, peer, false, 0)

	// Set peer service state to unknown (not failure — this isn't a failure).
	m.haStore.UpdatePeerSvcState(ctx, peer, types.SvcStateUnknown, types.NewReasonString("peer removed HA configuration"))

	// Write "adj down" state to NX-OS for this peer.
	if err := m.haStore.SetRemoteStatesAdjDown(ctx, peer); err != nil {
		logger.GetLogger().Warn("Failed to set remote states adj down on removal", "peer", peer, "error", err)
	}

	// Recompute derived HA/SVC state.
	m.recomputeAndApplyState(ctx)
}

// HandleAdjFailureNotify processes an incoming AdjFailureNotify from a peer.
func (m *manager) HandleAdjFailureNotify(ctx context.Context, peer string, reason string) {
	logger.GetLogger().Info("Received AdjFailureNotify", "peer", peer, "reason", reason)
	m.haStore.UpdatePeerSvcState(ctx, peer, types.SvcStateFailure, types.NewReasonString("adj failure notify: "+reason))
	m.recomputeAndApplyState(ctx)
}

// ProcessHaInfo processes an incoming HaInfo from a peer's Notify RPC or adjacency exchange.
// It updates the peer's service criterion, HA state, and leader status, then triggers a
// full state recomputation (which includes standby evaluation via EvaluateStandbyCrit)
// and leader election.
func (m *manager) ProcessHaInfo(ctx context.Context, peer string, haInfo *hav1.HaInfo) {
	if haInfo == nil || m.haStore == nil {
		return
	}

	// Update peer service criterion and svc state from Notify's reported state.
	// This ensures timely propagation without waiting for the next adjacency interval.
	svcOk := haInfo.LocalSvcState == hav1.LOCAL_SVC_STATE_LOCAL_SVC_SUCCESS
	m.haStore.UpdatePeerServiceCriterion(ctx, peer, types.HACritPeerService, svcOk)
	if svcOk {
		m.haStore.UpdatePeerSvcState(ctx, peer, types.SvcStateSuccess, types.NewReasonString("peer service ready"))
	} else {
		m.haStore.UpdatePeerSvcState(ctx, peer, types.SvcStateFailure, types.NewReasonString("peer service not-ready"))
	}

	// Update the peer's MemberInfo.HaState so that EvaluateStandbyCrit (which
	// reads MemberInfo to detect TAKEOVER) sees the updated state immediately.
	// Without this, EvaluateStandbyCrit uses stale MemberInfo from the last
	// adjacency exchange and would remove standby that was just injected.
	peerHaState := protoToHaState(haInfo.Ha)
	if peerHaState != "" {
		m.haStore.UpdatePeerMemberHaState(ctx, peer, peerHaState)
	}

	// Update the peer's self-reported leader status for election deference.
	m.haStore.UpdatePeerIsLeader(ctx, peer, haInfo.IsLeader)

	// Standby injection/removal is handled exclusively by EvaluateStandbyCrit
	// (called from recomputeAndApplyState) to avoid conflicting dual paths.
	// The peer's MemberInfo.HaState was already updated above, so
	// EvaluateStandbyCrit will see the latest TAKEOVER state.
	m.recomputeAndApplyState(ctx)

	// Re-evaluate leader election immediately so deference takes effect
	// without waiting for the next checkAdjacencies cycle.
	m.electLeader(ctx)
}

// buildLocalHaInfo builds the local HaInfo proto for Notify RPCs.
func (m *manager) buildLocalHaInfo() *hav1.HaInfo {
	return buildLocalHaInfoFromStore(m.haStore)
}

// haNotifyPeers sends a Notify RPC to all connected peers to push the local
// HA state immediately. Called asynchronously on state changes by both leader and follower.
func (m *manager) haNotifyPeers(ctx context.Context) {
	haInfo := m.buildLocalHaInfo()

	m.mu.RLock()
	localIP := m.localIP
	clients := make(map[string]Client)
	for ip, c := range m.peerClients {
		if c.IsConnected() {
			clients[ip] = c
		}
	}
	m.mu.RUnlock()

	for ip, client := range clients {
		req := &hav1.NotifyRequest{
			HaIp:   localIP,
			HaInfo: haInfo,
		}
		logger.GetLogger().Debug("Sending Notify to peer", "peer", ip, "haState", haInfo.Ha)
		resp, err := client.Notify(ctx, req)
		if err != nil {
			logger.GetLogger().Error("Failed to send Notify", "peer", ip, "error", err)
			continue
		}
		if resp.HaInfo != nil {
			m.ProcessHaInfo(ctx, ip, resp.HaInfo)
		}
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
		HaIp:   localIP,
		HaInfo: m.buildLocalHaInfo(),
	}

	resp, err := client.Notify(ctx, req)
	if err != nil {
		logger.GetLogger().Warn("AdjFailureNotify failed", "peer", peer, "error", err)
		return
	}

	if resp.Status != hav1.ADJ_RESPONSE_STATUS_ADJ_SUCCESS {
		logger.GetLogger().Warn("AdjFailureNotify rejected", "peer", peer, "details", resp.Details)
	}

	// Process HaInfo from response.
	if resp.HaInfo != nil {
		m.ProcessHaInfo(ctx, peer, resp.HaInfo)
	}
}

// recomputeAndApplyState recalculates CriteriaMet and derived HA/SVC states.
func (m *manager) recomputeAndApplyState(ctx context.Context) {
	if m.stateMachine == nil || m.haStore == nil {
		return
	}

	prev := m.haStore.Local()
	prevHaState := prev.HaState
	prevSvcState := prev.SvcState

	// Recalculate CriteriaMet with anti-flapping
	local := m.haStore.Local()
	updated := m.stateMachine.RecalculateCriteriaMet(local)
	if updated.CriteriaMet != local.CriteriaMet || updated.CriteriaRecoveryPending != local.CriteriaRecoveryPending {
		m.haStore.SetLocalCriteriaMet(ctx, updated)
	}

	// Manage hold-down timer based on recovery-pending state transitions.
	if updated.CriteriaRecoveryPending && m.holdDownTimer == nil {
		// Recovery just started — schedule exact expiry.
		m.holdDownTimer = time.NewTimer(CriteriaMetHoldDown)
	} else if !updated.CriteriaRecoveryPending && m.holdDownTimer != nil {
		// Recovery cancelled (flap or degradation) or promoted — stop timer.
		m.holdDownTimer.Stop()
		m.holdDownTimer = nil
	}

	// Evaluate standby criteria injection/removal before computing derived state.
	// Use SetLocal to avoid firing EventCriterionChanged, which would create an
	// event feedback loop causing redundant gNMI writes.
	local = m.haStore.Local()
	inject, remove := m.stateMachine.EvaluateStandbyCrit(local.HaState, m.haStore.IsLeader())
	if inject {
		logger.GetLogger().Debug("Injecting standby criteria (yielding to peer in TAKEOVER)")
		local.Criteria[types.HACritHaStandby] = false
		m.haStore.SetLocal(ctx, local)
	} else if remove {
		logger.GetLogger().Debug("Removing standby criteria (recovery or convergence)")
		delete(local.Criteria, types.HACritHaStandby)
		m.haStore.SetLocal(ctx, local)
	}

	// Compute derived states.
	// Service state is pushed to NX-OS only when SF is configured (InServiceState != "").
	result := m.stateMachine.ComputeState()
	pushSvcToNx := m.deviceStore == nil || m.deviceStore.InServiceState() != ""
	m.haStore.SetLocalDerivedStates(ctx, result.HaState, result.SvcState, result.HaReason, result.SvcReason, pushSvcToNx)

	// Persist per-peer HA states (also writes to NX-OS via gNMI inline).
	for ip, ps := range result.PeerStates {
		m.haStore.UpdatePeerHaState(ctx, ip, ps.HaState, ps.HaReason)
	}

	// Both leader and follower push state changes to peers via Notify so they learn immediately.
	if result.HaState != prevHaState || result.SvcState != prevSvcState {
		go m.haNotifyPeers(ctx)
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
	} else if updated.CriteriaRecoveryPending != local.CriteriaRecoveryPending || updated.CriteriaFlapCount != local.CriteriaFlapCount {
		// Hold-down expired but criteria no longer pass — persist the cancellation
		// so the store doesn't retain stale CriteriaRecoveryPending/Epoch state.
		m.haStore.SetLocalCriteriaMet(ctx, updated)
	}
}

// checkAdjMbrTimeouts checks for timed out members and adjacencies.
func (m *manager) checkAdjMbrTimeouts(ctx context.Context) {
	if m.haStore == nil {
		return
	}

	now := time.Now().Unix()
	mbrTimeoutSec := int64(HATimeout / time.Second)

	peers := m.haStore.AllPeers()
	for ip, peer := range peers {
		// Check member timeout
		if peer.MemberInfo != nil && peer.MemberCriteriaMetEpoch > 0 && now-peer.MemberCriteriaMetEpoch > mbrTimeoutSec {
			logger.GetLogger().Debug("Member timed out", "ip", ip)
			m.haStore.UpdatePeerMember(ctx, ip, nil)
		}

		// Check adjacency timeout
		if peer.Connected && peer.ConnectedEpoch > 0 && now-peer.ConnectedEpoch > int64(HATimeout/time.Second) {
			logger.GetLogger().Debug("Adjacency timed out", "ip", ip)
			m.haStore.UpdatePeerConnected(ctx, ip, false, 0)
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
		if peer.IpConfigState != hastore.PeerIpCfgStateSuccess {
			logger.GetLogger().Debug("checkAdjacencies: skipping peer, IpConfigState not success", "peer", ip, "state", peer.IpConfigState)
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
		req.MbrInfo.VlanIdRanges = BuildLocalVLANIdRanges(m.vlanStore)
	}

	// Add HA state info
	req.MbrInfo.HaInfo = m.buildLocalHaInfo()

	// Include local debug override flags for this peer so the peer can
	// store them as remote debug overrides in its criteria.
	if peerState, ok := m.haStore.Peer(peer); ok {
		if val, exists := peerState.MemberCriteria[types.HACritDebugMembershipFail]; exists && !val {
			req.MbrInfo.DebugMembershipFail = true
		}
		if val, exists := peerState.AdjacencyCriteria[types.HACritDebugAdjacencyFail]; exists && !val {
			req.MbrInfo.DebugAdjacencyFail = true
		}
	}

	resp, err := client.Adjacency(ctx, req)
	if err != nil {
		return err
	}

	// RPC completed — peer is reachable at the network level. Update adjacency
	// liveness regardless of response status. Validation failures (e.g. local
	// service failure causing ADJ_FAILURE) are tracked via criteria, not via
	// adjacency timeout. Without this, ADJ_FAILURE responses leave the epoch
	// stale and cause spurious "peer adjacency timeout" flapping.
	peerState, _ := m.haStore.Peer(peer)
	wasDisconnected := !peerState.Connected
	m.haStore.UpdatePeerConnected(ctx, peer, true, time.Now().Unix())
	// Re-push DPU aggregate criteria on reconnection.
	// UpdatePeerConnected(false) resets all criteria to false; the adjacency
	// exchange restores peer_compatible, peer_service, and peer_vrf_gid via
	// ProcessMemberInfo, but peer_dpu_keepalive and peer_dpu_bulk_sync are only
	// written by aggregateDPUStatus() which is not triggered during adjacency.
	if wasDisconnected {
		m.aggregateDPUStatus(ctx)
	}
	m.mu.Lock()
	m.lastAdjTime[peer] = time.Now()
	m.mu.Unlock()

	if resp.Status != hav1.ADJ_RESPONSE_STATUS_ADJ_SUCCESS {
		// Process MbrInfo from failure response to detect criteria failures fast
		if resp.MbrInfo != nil {
			peerInfo := convertMbrInfoToPeerMember(resp.MbrInfo)
			m.ProcessMemberInfo(ctx, peer, peerInfo)
			// Also process HaInfo from failure responses so peer leader/svc state
			// is updated without waiting for the next adjacency cycle.
			if resp.MbrInfo.HaInfo != nil {
				m.ProcessHaInfo(ctx, peer, resp.MbrInfo.HaInfo)
			}
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
			m.haStore.UpdatePeerMemberCriterion(ctx, peer, types.HACritPeerVrfGid, ok)
		}

		// Process full HaInfo from the adjacency response, mirroring what the server
		// side does for the incoming request (server.go:194-196). This updates SvcState,
		// service criterion, HA state, and IsLeader — ensuring electLeader (called below
		// by checkAdjacencies) sees current peer state. Without this, only IsLeader was
		// extracted and SvcState stayed stale (UNKNOWN), causing the deference check
		// (peer.IsLeader && peer.SvcState==SUCCESS) to fail and both peers to elect
		// themselves leader.
		if resp.MbrInfo.HaInfo != nil {
			m.ProcessHaInfo(ctx, peer, resp.MbrInfo.HaInfo)
		}
	}

	return nil
}

// handlePeerFailure handles a peer failure.
func (m *manager) handlePeerFailure(ctx context.Context, peer string) {
	m.mu.Lock()
	lastAdj, ok := m.lastAdjTime[peer]
	m.mu.Unlock()

	if ok && time.Since(lastAdj) > HATimeout {
		logger.GetLogger().Warn("Peer adjacency timeout", "peer", peer)
		m.haStore.UpdatePeerSvcState(ctx, peer, types.SvcStateUnknown, types.NewReasonString("peer adjacency timeout"))
		m.DisconnectPeer(peer)
	}
}

// electLeader performs leader election with the following priority:
//  1. No connected peers → preserve current IsLeader state (frozen until reconnect).
//  2. If any peer is leader: if local is not leader, return immediately (no preemption).
//     If both are leader (split-brain), resolve: peer SUCCESS beats local FAILURE;
//     local SUCCESS beats peer FAILURE; same tier → higher IP defers.
//  3. Already leader → stay leader (svc state changes don't trigger re-election).
//  4. Initial election (nobody is leader): prefer SUCCESS svc state, then lowest IP wins.
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

	// Only consider connected peers. Disconnected peers don't participate in
	// election — leader/follower state is frozen until reconnect or new peer.
	allPeers := m.haStore.AllPeers()
	peers := make(map[string]types.HAPeerState, len(allPeers))
	for ip, peer := range allPeers {
		if peer.Connected {
			peers[ip] = peer
		}
	}

	// No connected peers: preserve current IsLeader state (initialized as false).
	if len(peers) == 0 {
		return
	}

	// Step 2: If any peer is leader, handle it.
	for ip, peer := range peers {
		if !peer.IsLeader {
			continue
		}
		// If we're not leader, defer to existing leader (no preemption).
		if !m.haStore.IsLeader() {
			return
		}
		// Split-brain: both are leader. Multi-peer split-brain is unsupported.
		if len(peers) > 1 {
			logger.GetLogger().Warn("Multi-peer split-brain detected; cannot resolve automatically", "peerCount", len(peers))
			return
		}
		local := m.haStore.Local()
		localSvcSuccess := local.CriteriaMet && !local.CriteriaRecoveryPending
		peerSvcSuccess := peer.SvcState == types.SvcStateSuccess
		peerIP := net.ParseIP(ip)
		if peerIP == nil {
			continue
		}
		if peerSvcSuccess && !localSvcSuccess {
			// Peer is functioning, we're not → defer unconditionally.
			logger.GetLogger().Info("Deferring to functioning peer leader in split-brain", "peer", ip)
			m.haStore.SetLeader(ctx, false)
		} else if !peerSvcSuccess && localSvcSuccess {
			// We're functioning, peer isn't → keep leadership.
		} else {
			// Same svc state tier → higher IP defers.
			if compareIPs(peerIP, localIP) < 0 {
				logger.GetLogger().Info("Deferring to lower-IP peer leader in split-brain", "peer", ip)
				m.haStore.SetLeader(ctx, false)
			}
		}
		return
	}

	// Step 3: already leader → stay leader. Svc state changes don't trigger re-election.
	if m.haStore.IsLeader() {
		return
	}

	// Step 4: initial election — nobody is leader yet.
	// Priority: SUCCESS svc state > non-SUCCESS, then lowest IP tiebreaker.
	local := m.haStore.Local()
	localSvcSuccess := local.CriteriaMet && !local.CriteriaRecoveryPending

	isLeader := true
	for ip, peer := range peers {
		peerSvcSuccess := peer.SvcState == types.SvcStateSuccess

		if peerSvcSuccess && !localSvcSuccess {
			// Peer is functioning, we are not: peer wins.
			isLeader = false
			break
		}
		if !peerSvcSuccess && localSvcSuccess {
			// We are functioning, peer is not: we win. Check remaining peers.
			continue
		}
		// Same svc state tier: lowest IP wins.
		peerIP := net.ParseIP(ip)
		if peerIP != nil && compareIPs(peerIP, localIP) < 0 {
			isLeader = false
			break
		}
	}

	currentLeader := m.haStore.IsLeader()
	if isLeader != currentLeader {
		logger.GetLogger().Info("Leader status changed (initial election)", "isLeader", isLeader, "localIP", localIPStr)
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
	if m.dpuStore != nil && m.dpuStore.IsSkipDPU() {
		return
	}
	dpuUid = m.resolveDpuUid(dpuUid)
	m.mu.Lock()
	if _, ok := m.dpuStatuses[dpuUid]; !ok {
		m.dpuStatuses[dpuUid] = &dpuStatus{}
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
	// When keepalive goes down, reset bulk sync status for this DPU.
	// A reconnecting DPU will need a fresh bulk sync.
	if !up {
		s.bulkSyncLocal = false
		s.bulkSyncPeer = false
	}
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

// SetDebugPeerFail injects debug override failure criteria for a specific peer.
// membership=true forces membership criteria to fail (ha-fail).
// adjacency=true forces adjacency criteria to fail (ha-degraded).
func (m *manager) SetDebugPeerFail(ctx context.Context, peer string, membership, adjacency bool) {
	if m.haStore == nil {
		return
	}
	logger.GetLogger().Info("SetDebugPeerFail", "peer", peer, "membership", membership, "adjacency", adjacency)
	if membership {
		m.haStore.UpdatePeerMemberCriterion(ctx, peer, types.HACritDebugMembershipFail, false)
	}
	if adjacency {
		m.haStore.UpdatePeerAdjacencyCriterion(ctx, peer, types.HACritDebugAdjacencyFail, false)
	}
	m.recomputeAndApplyState(ctx)
}

// SetDebugPeerOk clears all debug override failure criteria for a specific peer.
func (m *manager) SetDebugPeerOk(ctx context.Context, peer string) {
	if m.haStore == nil {
		return
	}
	logger.GetLogger().Info("SetDebugPeerOk", "peer", peer)
	m.haStore.RemovePeerMemberCriterion(ctx, peer, types.HACritDebugMembershipFail)
	m.haStore.RemovePeerAdjacencyCriterion(ctx, peer, types.HACritDebugAdjacencyFail)
	m.haStore.RemovePeerMemberCriterion(ctx, peer, types.HACritDebugMembershipFailRemote)
	m.haStore.RemovePeerAdjacencyCriterion(ctx, peer, types.HACritDebugAdjacencyFailRemote)
	m.recomputeAndApplyState(ctx)
}

// SetDebugFail injects or removes the local debug override criterion.
// When fail=true, adds HACritDebug=false causing local service failure.
// When fail=false, removes HACritDebug restoring normal operation.
func (m *manager) SetDebugFail(ctx context.Context, fail bool) {
	if m.haStore == nil {
		return
	}
	logger.GetLogger().Info("SetDebugFail", "fail", fail)
	if fail {
		m.haStore.UpdateLocalCriterion(ctx, types.HACritDebug, false)
	} else {
		m.haStore.RemoveLocalCriterion(ctx, types.HACritDebug)
	}
	m.recomputeAndApplyState(ctx)
}

// NotifyServiceFailure sends the current member info (with SVC_FAILURE) via
// Adjacency RPC to all connected peers. Called when transitioning to
// out-of-service before a graceful restart, so peers can immediately update
// their state (e.g. to HA_TAKEOVER) instead of waiting for adjacency timeout.
func (m *manager) NotifyServiceFailure(ctx context.Context) {
	m.mu.RLock()
	localIP := m.localIP
	clients := make(map[string]Client)
	for ip, c := range m.peerClients {
		if c.IsConnected() {
			clients[ip] = c
		}
	}
	m.mu.RUnlock()

	localInfo := m.buildMemberInfo()
	localInfo.Service = types.SvcStateFailure

	mbrInfo := convertPeerMemberToMbrInfo(localInfo)
	// Include VRF and VLAN info so the peer can also use it.
	if m.vrfStore != nil {
		mbrInfo.VrfInfo = BuildLocalVRFInfo(m.vrfStore)
	}
	if m.vlanStore != nil {
		mbrInfo.VlanInfo = BuildLocalVLANInfo(m.vlanStore)
	}

	for ip, client := range clients {
		req := &hav1.AdjRequest{
			HaIp:    localIP,
			MbrInfo: mbrInfo,
		}
		logger.GetLogger().Debug("Sending service failure notification to peer", "peer", ip)
		_, err := client.Adjacency(ctx, req)
		if err != nil {
			logger.GetLogger().Error("Failed to send service failure notification", "peer", ip, "error", err)
		}
	}
}

// initDPUCriteriaFromStore ensures DPU entries exist in dpuStatuses and
// writes initial (false) criteria to all HA peers at activation time. This
// handles the case where DPUs were loaded into dpuStore via gNMI but no FWA
// has connected yet. All DPU criteria (keepalive, bulkSyncLocal, bulkSyncPeer)
// start as false and only become true when FWA explicitly reports via the
// Update* methods.
func (m *manager) initDPUCriteriaFromStore(ctx context.Context) {
	if m.dpuStore == nil || m.haStore == nil {
		return
	}

	// When DPUs are skipped for testing, return early without adding any
	// DPU criteria to the map. This prevents them from contributing to
	// criteria checks at all.
	if m.dpuStore.IsSkipDPU() {
		return
	}

	dpus := m.dpuStore.List()
	if len(dpus) == 0 {
		return
	}

	m.mu.Lock()
	for _, d := range dpus {
		if _, ok := m.dpuStatuses[d.Name]; !ok {
			m.dpuStatuses[d.Name] = &dpuStatus{}
		}
	}
	m.mu.Unlock()

	m.aggregateDPUStatus(ctx)
}

// allDPUKeepaliveUp returns true if all DPU keepalives are up.
// When DPUs are skipped for testing, returns true (matching old aggregateDpuKeepalive/SkipDpu behavior).
// When no DPUs are registered (and not skipped), returns false.
func (m *manager) allDPUKeepaliveUp() bool {
	if m.dpuStore != nil && m.dpuStore.IsSkipDPU() {
		return true
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.dpuStatuses) == 0 {
		return false
	}
	for _, s := range m.dpuStatuses {
		if !s.keepaliveUp {
			return false
		}
	}
	return true
}

// aggregateDPUStatus computes aggregate keepalive/bulk-sync criteria from all DPUs
// and updates per-peer adjacency criteria and DPU status snapshots in the HA store.
func (m *manager) aggregateDPUStatus(ctx context.Context) {
	if m.haStore == nil {
		return
	}

	// When DPUs are skipped for testing, return early without adding any
	// DPU criteria to the map. This prevents them from contributing to
	// criteria checks at all.
	if m.dpuStore != nil && m.dpuStore.IsSkipDPU() {
		return
	}

	m.mu.RLock()
	n := len(m.dpuStatuses)
	if n == 0 {
		m.mu.RUnlock()
		return
	}
	allKeepaliveUp := true
	allBulkSyncDone := true
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
		m.haStore.UpdatePeerMemberCriterion(ctx, ip, types.HACritPeerDPUKeepalive, allKeepaliveUp)
		m.haStore.UpdatePeerAdjacencyCriterion(ctx, ip, types.HACritPeerDPUBulkSync, allBulkSyncDone)
		m.haStore.UpdatePeerDPUStatuses(ctx, ip, snapshot)
	}

	// Recompute HA config since DPU keepalive affects FlowSync.
	m.computeAndPushHaConfig()
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
