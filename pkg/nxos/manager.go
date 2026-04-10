// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package nxos

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"

	"github.com/isovalent/hubble-fgs/pkg/config/library"
	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
	"github.com/isovalent/hubble-fgs/pkg/nxos/storage"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/device"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/dpu"
	hastore "github.com/isovalent/hubble-fgs/pkg/nxos/store/ha"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/vlan"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/vrf"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
	"github.com/isovalent/hubble-fgs/pkg/shutdown"
	"github.com/isovalent/hubble-fgs/pkg/token"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
	"google.golang.org/protobuf/proto"
)

// fwState represents the firewall readiness dimension of systemState.
type fwState int

const (
	fwStateDisabled   fwState = iota // neither DpuPending nor FwReady
	fwStateDpuPending                // SysStDpuPending — waiting for DPU inventory/health
	fwStateFwReady                   // SysStFwReady — DPUs healthy and in-service
)

// DpuInSyncSettlingWindow is the settling window for DPU out-of-sync transitions.
// When a DPU reports out-of-sync, the HACritDpuInSync criterion stays true for
// this duration before the degradation is applied. This dampens transient mismatches
// during policy deployments.
const DpuInSyncSettlingWindow = 60 * time.Second

// Status represents the current status of the NXOS manager.
type Status struct {
	Phase     Phase
	Ready     bool
	VRFCount  int
	VLANCount int
	DPUCount  int
	HAEnabled bool
	HALeader  bool
	Connected bool
}

// manager implements the Manager interface.
type manager struct {
	// SystemState bits — all guarded by stateMu.
	// ConnPending is managed by the device store (SetConnectionStatus), not here.
	stateMu         sync.Mutex
	fwStatus        fwState // disabled / dpuPending / fwReady
	redirDone       bool    // true = SysStRedirDone set
	lastSystemState int     // last written composite state; -1 = never written
	redirPending    bool    // true = in-service but redirects deferred (awaiting FwReady)

	// Domain stores
	vrfStore    vrf.Store
	vlanStore   vlan.Store
	dpuStore    dpu.Store
	haStore     hastore.Store
	deviceStore device.Store

	// Storage backend for persistence
	storage storage.Storage

	// gNMI handler
	gnmiHandler gnmi.GnmiHandler

	// Configuration
	opts *managerOptions

	// Internal state
	closed atomic.Bool

	// dpuInSyncSettlingStart is the time when DPU first reported out-of-sync in the
	// current episode. Zero when not settling. Written only from the agw.DpuHealthCheck
	// goroutine; no synchronization needed.
	dpuInSyncSettlingStart  time.Time
	dpuInSyncSettlingWindow time.Duration // defaults to DpuInSyncSettlingWindow; overridable in tests
}

// NewManager creates a new Manager with the given options.
func NewManager(ctx context.Context, opts ...Option) Manager {
	options := defaultOptions()
	for _, opt := range opts {
		opt(options)
	}

	// Create storage backend - use MemoryStorage by default
	var storageBackend storage.Storage
	if options.storage != nil {
		storageBackend = options.storage
	} else {
		storageBackend = storage.NewMemoryStorage()
	}

	// Ensure storage is ready
	if err := storageBackend.EnsureReady(ctx); err != nil {
		logger.GetLogger().Warn("Failed to initialize storage", "error", err)
	}

	// Create the device store first so VRF/VLAN stores can seed from its LbMode.
	devStore := device.NewStore(ctx, device.WithStorage(storageBackend), device.WithAgentTokenProvider(token.GetAgentToken()))
	dpuSt := dpu.NewStore(ctx, dpu.WithStorage(storageBackend))
	// Pre-create haStore so the isLeader closure can reference it.
	haSt := hastore.NewStore(ctx, hastore.WithStorage(storageBackend))

	m := &manager{
		fwStatus:                fwStateDisabled, // starts disabled
		redirDone:               false,           // no redirects yet
		lastSystemState:         -1,              // not yet written
		dpuInSyncSettlingWindow: DpuInSyncSettlingWindow,
		// Create stores with integrated storage - they load persisted state automatically
		vrfStore: vrf.NewStore(ctx,
			vrf.WithStorage(storageBackend),
			vrf.WithPreSeededGIDs(options.vrfGIDs),
			vrf.WithLbModePinning(devStore.LbMode() == "pinning"),
		),
		vlanStore: vlan.NewStore(ctx,
			vlan.WithStorage(storageBackend),
			vlan.WithLbModePinning(devStore.LbMode() == "pinning"),
		),
		dpuStore:    dpuSt,
		haStore:     haSt,
		deviceStore: devStore,
		storage:     storageBackend,
		opts:        options,
	}

	return m
}

// Setup initializes the NXOS Manager and starts operations.
func (m *manager) Setup(ctx context.Context) error {
	logger.GetLogger().Info("NXOS Manager Setup starting")

	// Initialize gNMI handler
	isMock := m.opts.gnmiHandler != nil
	if isMock {
		// Use provided handler (mock or custom)
		m.gnmiHandler = m.opts.gnmiHandler
		logger.GetLogger().Info("Using provided gNMI handler")
	} else {
		// No handler provided - connect to NXOS hardware
		handler, err := gnmi.NewNxosGnmiHandler(ctx, &gnmi.HandlerConfig{
			Address:    m.opts.gnmiAddress,
			Username:   m.opts.gnmiUsername,
			Password:   m.opts.gnmiPassword,
			TLSCA:      m.opts.gnmiCAFile,
			TLSCert:    m.opts.gnmiCertFile,
			TLSKey:     m.opts.gnmiKeyFile,
			SkipVerify: true,
		})
		if err != nil {
			logger.GetLogger().Error("Failed to connect gNMI handler", logfields.Error, err)
			return err
		}
		m.gnmiHandler = handler
	}

	// Wire gNMI handler into all domain stores before any store operations
	// that write state to the switch. This must happen before setDpuPending,
	// SetConnectionStatus, and any subscription callbacks that may trigger writes.
	if m.gnmiHandler != nil {
		m.deviceStore.SetGnmiHandler(m.gnmiHandler)
		m.vrfStore.SetGnmiHandler(m.gnmiHandler)
		m.vlanStore.SetGnmiHandler(m.gnmiHandler)
		m.dpuStore.SetGnmiHandler(m.gnmiHandler)
		m.haStore.SetGnmiHandler(m.gnmiHandler)
	}

	// In mock mode, simulate a successful connection/admission status.
	if isMock {
		m.deviceStore.SetConnectionStatus(ctx, device.ControllerStateSuccess, "mock")
		m.deviceStore.SetAdmissionStatus(ctx, device.ControllerStateSuccess, "mock")
	}

	// Seed DPU count from gNMI GET before starting subscriptions.
	// This ensures programSharedRedirects has the correct count if the
	// in-service notification arrives before WaitForInventory completes.
	if !m.dpuStore.IsSkipDPU() {
		if strs, err := m.gnmiHandler.Get(ctx, paths.DPUStoreNumDPUs); err != nil {
			logger.GetLogger().Warn("Failed to GET DPU count, will rely on subscription", logfields.Error, err)
		} else if len(strs) > 0 {
			if count, err := strconv.Atoi(strs[0]); err == nil && count > 0 {
				m.dpuStore.SetExpectedCount(ctx, count)
				m.vrfStore.SetDPUCount(uint16(count))
				m.vlanStore.SetDPUCount(uint16(count))
				logger.GetLogger().Info("Seeded DPU count from gNMI GET", "count", count)
			}
		}
	}

	// Seed LbMode from gNMI GET before starting subscriptions.
	// This ensures isPinningActive() returns the correct value when
	// VRFs/VLANs are activated from gNMI subscription notifications.
	if strs, err := m.gnmiHandler.Get(ctx, paths.DeviceStoreLoadBalancingMode); err != nil {
		logger.GetLogger().Warn("Failed to GET LbMode, will rely on subscription", logfields.Error, err)
	} else if len(strs) > 0 && strs[0] != "" {
		m.deviceStore.SetLbMode(ctx, strs[0])
		pinning := strs[0] == "pinning"
		m.vrfStore.SetLbModePinning(pinning)
		m.vlanStore.SetLbModePinning(pinning)
		logger.GetLogger().Info("Seeded LbMode from gNMI GET", "lbMode", strs[0])
	}

	// Re-evaluate DPU pinning for VRFs/VLANs loaded from storage.
	// On restart, stored DPUPinned values may be stale (e.g. 65535/all from a
	// previous symmetric-hash run) while the current LB mode is pinning.
	// The LbMode watcher is not yet registered, and subscriptions won't fire
	// EventLbModeChanged if the value is unchanged, so RepinAll must be called
	// explicitly. Redirect programming is gated on inService (false here), so
	// only in-memory state and persistence are updated.
	m.vrfStore.RepinAll(ctx)
	m.vlanStore.RepinAll(ctx)

	// Register VRF change watcher to keep policyHandler and config library in sync.
	m.setupVRFPolicyWatcher()

	// Register LB mode watcher to repin VRFs/VLANs when mode changes.
	m.setupLbModeWatcher()

	// Set dpuPending — signals to NXOS that we are waiting for DPU inventory.
	m.setDpuPending(ctx)

	// Register hooks BEFORE starting subscriptions so hooks are in place before
	// any in-service notifications arrive.
	m.setupInServiceHooks()

	// Start gNMI subscriptions
	if err := m.setupGnmiSubscriptions(ctx); err != nil {
		logger.GetLogger().Error("Failed to setup gNMI subscriptions", logfields.Error, err)
		return err
	}

	// Start notification liveness check
	go m.checkNotificationLiveness(ctx)

	// Wait for DPU inventory to complete and all expected DPUs to be discovered.
	if err := m.dpuStore.WaitForInventory(ctx); err != nil {
		logger.GetLogger().Error("Failed waiting for DPU inventory readiness", logfields.Error, err)
		return fmt.Errorf("wait for DPU inventory readiness: %w", err)
	}

	// Update VRF and VLAN stores with discovered DPU count for hash-based pinning.
	m.vrfStore.SetDPUCount(uint16(m.dpuStore.DpuCount()))
	m.vlanStore.SetDPUCount(uint16(m.dpuStore.DpuCount()))

	// Re-evaluate DPU pinning with the definitive DPU count from inventory.
	// VRFs/VLANs with Affinity=0 use FNV-1a hash which depends on dpuCount.
	// The earlier RepinAll used the GET-seeded count which may have been 0 if
	// the GET failed; this corrects those entries with the confirmed count.
	m.vrfStore.RepinAll(ctx)
	m.vlanStore.RepinAll(ctx)

	return nil
}

// Close performs comprehensive cleanup and resource release.
// This method is idempotent - multiple calls are safe and will only clean up once.
// Close respects the context deadline - if it expires, remaining cleanup is forced.
func (m *manager) Close(ctx context.Context) error {
	// Idempotency check
	if m.closed.Swap(true) {
		logger.GetLogger().Debug("NXOS Manager already closed")
		return nil
	}

	logger.GetLogger().Info("NXOS Manager close starting")

	// Track if context is cancelled for forced cleanup
	forcedClose := false
	checkContext := func() bool {
		select {
		case <-ctx.Done():
			if !forcedClose {
				logger.GetLogger().Warn("Context cancelled, forcing remaining cleanup")
				forcedClose = true
			}
			return true
		default:
			return false
		}
	}

	// 1. Stop subscriptions (stops gNMI subscription processing)
	if m.gnmiHandler != nil {
		logger.GetLogger().Debug("Stopping subscriptions")
		m.gnmiHandler.StopSubscriptions()
	}
	checkContext()

	// 2. Signal to switch that the agent is departing before removing state.
	if m.gnmiHandler != nil && !forcedClose {
		logger.GetLogger().Info("Setting local service state to not-ready")
		if err := m.haStore.SetLocalSvcStateToFailure(ctx, types.NewReasonString("agent shutdown")); err != nil {
			logger.GetLogger().Warn("Failed to set local svc state to failure", "error", err)
		}
		m.deviceStore.SetConnectionStatus(ctx, device.ControllerStateUnknown, "")
	}

	// 3. Clean up per-VRF/VLAN fwPolicyState and service redirect items
	if m.gnmiHandler != nil && !forcedClose {
		logger.GetLogger().Info("Cleaning up service redirect state")
		m.vrfStore.CleanupAllFwPolicyState(ctx)
		m.vlanStore.CleanupAllFwPolicyState(ctx)
		if err := m.gnmiHandler.Delete(ctx, "/System/serviceredir-items"); err != nil {
			logger.GetLogger().Warn("Failed to delete service redirect items", "error", err)
		}
	}
	checkContext()

	// 4. Persist all state synchronously (skip if context cancelled)
	if m.storage != nil && !forcedClose {
		logger.GetLogger().Info("Flushing state to storage")
		if err := m.storage.FlushAll(ctx); err != nil {
			logger.GetLogger().Warn("Failed to flush storage", logfields.Error, err)
		}
	} else if forcedClose {
		logger.GetLogger().Warn("Skipping storage flush due to timeout")
	}

	// 5. Clean up DPU port ranges and system state (before closing gNMI handler)
	if !forcedClose {
		m.cleanupDPUPortRanges(ctx)
	}
	if err := m.deviceStore.DeleteSystemState(ctx); err != nil {
		logger.GetLogger().Warn("Failed to delete system state", logfields.Error, err)
	}
	checkContext()

	// 6. Close gNMI handler (this also stops subscriptions)
	if m.gnmiHandler != nil {
		logger.GetLogger().Info("Closing gNMI handler")
		if err := m.gnmiHandler.Close(); err != nil {
			logger.GetLogger().Warn("Failed to close gNMI handler", logfields.Error, err)
		}
	}

	if forcedClose {
		logger.GetLogger().Warn("NXOS Manager close completed (forced)")
	} else {
		logger.GetLogger().Info("NXOS Manager close completed")
	}
	return nil
}

// setupGnmiSubscriptions initializes gNMI subscriptions and notification handling.
func (m *manager) setupGnmiSubscriptions(ctx context.Context) error {
	if m.gnmiHandler == nil {
		logger.GetLogger().Warn("gNMI handler not initialized, skipping subscriptions")
		return nil
	}

	// Register store handlers with the gNMI handler, including subscription paths.
	// Each handler is registered with subscription paths that determine both what
	// gNMI paths to subscribe to and which notifications get routed to the handler.

	// VRF store: global VRF list, service VRF list (list-entry subscriptions)
	m.gnmiHandler.RegisterHandler(
		func(path string, update *gnmiproto.Update, isDelete bool) {
			m.vrfStore.HandleGnmiNotification(ctx, path, update, isDelete)
		},
		paths.VrfStoreGlobalVrf,
		paths.VrfStoreServiceVrf,
	)

	// VLAN store: global VLAN list, service VLAN list (list-entry subscriptions)
	m.gnmiHandler.RegisterHandler(
		func(path string, update *gnmiproto.Update, isDelete bool) {
			m.vlanStore.HandleGnmiNotification(ctx, path, update, isDelete)
		},
		paths.VlanStoreGlobalVlan,
		paths.VlanStoreServiceVlan,
	)

	// DPU store: DPU inventory and discovery
	m.gnmiHandler.RegisterHandler(
		func(path string, update *gnmiproto.Update, isDelete bool) {
			m.dpuStore.HandleGnmiNotification(ctx, path, update, isDelete)
		},
		paths.DPUStoreInitState,
		paths.DPUStoreNumDPUs,
		paths.DPUStoreIP,
		paths.DPUStoreState,
		paths.DPUStoreVersion,
	)

	// Device store subscriptions
	m.gnmiHandler.RegisterHandler(
		func(path string, update *gnmiproto.Update, isDelete bool) {
			m.deviceStore.HandleGnmiNotification(ctx, path, update, isDelete)
		},
		paths.DeviceStoreConnToken,
		paths.DeviceStoreProxyServer,
		paths.DeviceStoreProxyPort,
		paths.DeviceStoreInService,
		paths.DeviceStoreModel,
		paths.DeviceStoreSerialNumber,
		paths.DeviceStoreServiceIP,
		paths.DeviceStoreSupervisorType,
		paths.DeviceStoreLoadBalancingMode,
	)

	// HA store: HA admin state, oper state, and peers
	m.gnmiHandler.RegisterHandler(
		func(path string, update *gnmiproto.Update, isDelete bool) {
			m.haStore.HandleGnmiNotification(ctx, path, update, isDelete)
		},
		paths.HAStoreEnabled,
		paths.HAStoreHaIp,
		paths.HAStoreSwitchState,
		paths.HAStorePeers,
	)

	// Manager-level: service instance and firewall policy deletes trigger restart.
	// These are cross-cutting events that span multiple stores, so they are
	// handled at the manager level rather than in any single domain store.
	m.gnmiHandler.RegisterHandler(
		func(path string, update *gnmiproto.Update, isDelete bool) {
			m.handleServiceLifecycleNotification(ctx, path, isDelete)
		},
		paths.SvcInstancePath,
		paths.SvcFwPolicyPath,
	)

	// Start subscriptions -- paths are gathered from registrations
	m.gnmiHandler.StartSubscriptions(ctx)

	logger.GetLogger().Info("gNMI subscriptions established")
	return nil
}

// checkNotificationLiveness periodically checks that gNMI notifications are
// still being received. Logs an error if the last notification was too long ago.
func (m *manager) checkNotificationLiveness(ctx context.Context) {
	const notifTimeout = 120 * time.Second
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if m.gnmiHandler == nil {
				continue
			}
			lastNotif := m.gnmiHandler.LastNotificationTime()
			if lastNotif.IsZero() {
				continue // No notifications received yet
			}
			if elapsed := time.Since(lastNotif); elapsed > notifTimeout {
				logger.GetLogger().Debug("gNMI notification liveness check failed",
					"lastNotification", lastNotif,
					"elapsed", elapsed)
			}
		}
	}
}

// programSharedRedirects programs the shared redirect infrastructure that must
// be in place before any per-VRF or per-VLAN redirects can be programmed:
// 1. IPv4 and IPv6 ACLs referenced by all policy maps
// 2. Per-DPU BD service endpoints (Type=dpu_bridge)
// 3. Per-DPU BD policy maps
func (m *manager) programSharedRedirects(ctx context.Context) error {
	if m.gnmiHandler == nil {
		return nil
	}

	dpuCount := uint16(m.dpuStore.DpuCount())
	if dpuCount == 0 && !m.dpuStore.IsSkipDPU() {
		return fmt.Errorf("no DPUs discovered: shared redirect programming requires DPU count")
	}

	// 1. Program ACLs (required by all policy maps)
	if err := vrf.ProgramAccessLists(ctx, m.gnmiHandler); err != nil {
		return fmt.Errorf("program access lists: %w", err)
	}

	// 2. Program BD service endpoints
	if err := m.vlanStore.ProgramBDServiceEndpoints(ctx, dpuCount); err != nil {
		return fmt.Errorf("program BD service endpoints: %w", err)
	}

	// 3. Program BD policy maps
	if err := m.vlanStore.ProgramBDPolicyMaps(ctx, dpuCount); err != nil {
		return fmt.Errorf("program BD policy maps: %w", err)
	}

	logger.GetLogger().Info("Shared redirect infrastructure programmed", "dpuCount", dpuCount)
	return nil
}

// setupInServiceHooks registers pre/post hooks on the device store that
// manage redirect programming around in-service state transitions.
//
// Going in-service: reprogram shared infrastructure, program all redirects,
// then enable the reactive gate.
// Going out-of-service: signal failure to switch, disable the reactive gate,
// clean up fwPolicyState, bulk-delete service redirects, delete system state.
func (m *manager) setupInServiceHooks() {
	m.deviceStore.SetPreInServiceHook(func(ctx context.Context, newState string) {
		if newState == device.InServiceStateInService {
			// Restore GIDs from switch state. On first boot this populates GIDs;
			// on return-to-in-service (no restart) the switch has no redirect state
			// so this is effectively a no-op.
			if err := m.vrfStore.RestoreGIDsFromGnmi(ctx); err != nil {
				logger.GetLogger().Warn("Failed to restore GIDs from gNMI", "error", err)
			}
			if err := m.vlanStore.RestorePinningFromGnmi(ctx); err != nil {
				logger.GetLogger().Warn("Failed to restore VLAN pinning from gNMI", "error", err)
			}

			// Sync policy handler and network config with current VRF state.
			// Needed for VRFs loaded from storage whose gNMI notifications
			// matched stored values (no change events fired).
			m.updateVRFPolicyMap()

			if m.dpuStore.IsHealthy() {
				// DPUs are healthy: program redirects now and signal readiness.
				if err := m.programSharedRedirects(ctx); err != nil {
					logger.GetLogger().Error("Failed to reprogram shared redirects on in-service", "error", err)
				}
				m.vrfStore.ProgramAllRedirects(ctx)
				m.vlanStore.ProgramAllRedirects(ctx)
				m.vrfStore.SetInService(true)
				m.vlanStore.SetInService(true)
				m.setFwReady(ctx)
				m.setRedirDone(ctx, true)
			} else {
				// DPUs are unhealthy: defer redirect programming until FwReady.
				m.setDpuPending(ctx)
				m.stateMu.Lock()
				m.redirPending = true
				m.stateMu.Unlock()
			}
		}
	})

	m.deviceStore.SetPostInServiceHook(func(ctx context.Context, oldState string) {
		if oldState == device.InServiceStateInService {
			logger.GetLogger().Info("Out-of-service transition, removing redirects")
			m.removeAllRedirects(ctx)
			m.setFwDisabled(ctx)
		}
	})
}

// setupLbModeWatcher registers a watcher on the device store that re-pins all
// active VRFs and VLANs when the load balancing mode changes.
func (m *manager) setupLbModeWatcher() {
	m.deviceStore.Watch(func(event device.Event) {
		if event.Type == device.EventLbModeChanged {
			ctx := context.Background()
			pinning := event.Status == "pinning"
			m.vrfStore.SetLbModePinning(pinning)
			m.vlanStore.SetLbModePinning(pinning)
			m.vrfStore.RepinAll(ctx)
			m.vlanStore.RepinAll(ctx)
		}
	})
}

// setupVRFPolicyWatcher registers a watcher on the VRF store that keeps the
// policyHandler's L3 network map and the config library's NetworkConfig in
// sync whenever active VRFs change. This mirrors the old doVRFPolicyMapUpdate.
func (m *manager) setupVRFPolicyWatcher() {
	if m.opts.policyHandler == nil {
		return
	}

	m.vrfStore.Watch(func(event vrf.Event) {
		oldActive := event.OldVRF != nil && event.OldVRF.Active
		newActive := event.VRF.Active
		if !oldActive && !newActive {
			return
		}
		m.updateVRFPolicyMap()
	})
}

// updateVRFPolicyMap rebuilds the L3Networks map from the current set of
// active VRFs and pushes it to the policyHandler and config library.
func (m *manager) updateVRFPolicyMap() {
	handler := m.opts.policyHandler
	if handler == nil {
		return
	}

	activeVRFs := m.vrfStore.ListActive()

	vrfMap := switchpolicy.NewL3Networks()
	vrfs := make([]*v1alpha.Vrf, 0, len(activeVRFs))
	for _, v := range activeVRFs {
		if v.GID == 0 {
			continue
		}
		vrfName := switchpolicy.VrfName(v.Name)
		vrfGID := switchpolicy.VrfGID(v.GID)
		if err := vrfMap.Add(vrfName, vrfGID); err != nil {
			logger.GetLogger().Error("vrfMap add failed", "vrf", v.Name, "gid", v.GID, logfields.Error, err)
			continue
		}
		vrfs = append(vrfs, &v1alpha.Vrf{
			Name: v.Name,
			Id:   uint32(v.GID),
		})
	}

	if err := handler.SetL3Networks(vrfMap); err != nil {
		logger.GetLogger().Error("Failed to set L3 networks", logfields.Error, err)
		return
	}

	// Update the network config in the repository
	err := library.GetRepository().UpdateConfig(v1alpha.ConfigType_CONFIG_TYPE_NETWORK, func(existing *v1alpha.ConfigObject) (*v1alpha.ConfigObject, error) {
		networkConfig := &v1alpha.NetworkConfig{}
		if existing != nil && existing.GetNetworkConfig() != nil {
			networkConfig = proto.Clone(existing.GetNetworkConfig()).(*v1alpha.NetworkConfig)
		}
		networkConfig.Vrfs = vrfs
		return &v1alpha.ConfigObject{
			Type:   v1alpha.ConfigType_CONFIG_TYPE_NETWORK,
			Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
			Config: &v1alpha.ConfigObject_NetworkConfig{NetworkConfig: networkConfig},
		}, nil
	})
	if err != nil {
		logger.GetLogger().Error("Failed to update network config", logfields.Error, err)
	}
}

// removeAllRedirects cleans up redirect state without tearing down the manager.
// Called on out-of-service transitions so the process keeps running.
func (m *manager) removeAllRedirects(ctx context.Context) {
	// Signal local svc state to not-ready BEFORE removing any redirects.
	// Skip when InServiceState is "" — the service firewall has been deleted and
	// the gNMI path no longer exists, so the SET would be rejected by NX-OS.
	if m.gnmiHandler != nil && m.deviceStore.InServiceState() != "" {
		if err := m.haStore.SetLocalSvcStateToFailure(ctx, types.NewReasonString("out-of-service")); err != nil {
			logger.GetLogger().Warn("Failed to set local svc state to failure", logfields.Error, err)
		}
	}

	// Disarm any deferred redirect programming.
	m.stateMu.Lock()
	m.redirPending = false
	m.stateMu.Unlock()

	// Disable reactive gate (stops new redirects from being programmed).
	m.vrfStore.SetInService(false)
	m.vlanStore.SetInService(false)

	// Clean up per-VRF/VLAN fwPolicyState.
	m.vrfStore.CleanupAllFwPolicyState(ctx)
	m.vlanStore.CleanupAllFwPolicyState(ctx)

	// Delete agent-managed service redirect items individually rather than
	// bulk-deleting the entire /System/serviceredir-items container, which
	// would destroy MOs the agent did not create.

	// Per-VRF redirects: dom-items bindings, per-VRF policy maps and service endpoints.
	m.vrfStore.CleanupAllRedirects(ctx)

	// Per-VLAN redirects: bd-items bindings.
	m.vlanStore.CleanupAllRedirects(ctx)

	// Shared BD policy maps and service endpoints. Policy maps must be deleted
	// first because they reference service endpoints.
	dpuCount := uint16(m.dpuStore.DpuCount())
	m.vlanStore.CleanupBDPolicyMaps(ctx, dpuCount)
	m.vlanStore.CleanupBDServiceEndpoints(ctx, dpuCount)

	// Redirect ACLs.
	if m.gnmiHandler != nil {
		if err := vrf.DeleteAccessLists(ctx, m.gnmiHandler); err != nil {
			logger.GetLogger().Warn("Failed to delete redirect ACLs", logfields.Error, err)
		}
	}

	// Clear redirDone — redirects removed.
	m.setRedirDone(ctx, false)
}

// writeSystemStateLocked computes the composite systemState from fwStatus,
// redirDone, and connPending, then writes it to the device store.
// Must be called with stateMu held.
func (m *manager) writeSystemStateLocked(ctx context.Context) {
	state := 0
	switch m.fwStatus {
	case fwStateDpuPending:
		state |= SysStDpuPending
	case fwStateFwReady:
		state |= SysStFwReady
	} // fwStateDisabled: neither bit set
	if m.redirDone {
		state |= SysStRedirDone
	}
	if state == m.lastSystemState {
		return
	}
	m.lastSystemState = state
	logger.GetLogger().Info("SystemState update", "state", fmt.Sprintf("0x%X", state),
		"fwStatus", m.fwStatus, "redirDone", m.redirDone)
	// Use UpdateSystemState to preserve the ConnPending bit owned by the device store.
	m.deviceStore.UpdateSystemState(ctx, state)
}

// setFwDisabled sets fwStatus to disabled (neither DpuPending nor FwReady) and writes systemState.
func (m *manager) setFwDisabled(ctx context.Context) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	m.fwStatus = fwStateDisabled
	m.writeSystemStateLocked(ctx)
}

// setDpuPending sets fwStatus to dpuPending and writes systemState.
// No-op if fwStatus is already fwReady — the disabled→dpuPending→fwReady
// transition is one-way within an in-service window.
func (m *manager) setDpuPending(ctx context.Context) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	if m.fwStatus == fwStateFwReady {
		return
	}
	m.fwStatus = fwStateDpuPending
	m.writeSystemStateLocked(ctx)
}

// setFwReady sets fwStatus to fwReady and writes systemState.
func (m *manager) setFwReady(ctx context.Context) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	m.fwStatus = fwStateFwReady
	m.writeSystemStateLocked(ctx)
}

// programDeferredRedirects programs redirects that were deferred because DPUs
// were unhealthy at in-service time. Called after setFwReady to complete the
// work that was skipped in the pre-in-service hook.
func (m *manager) programDeferredRedirects(ctx context.Context) {
	m.stateMu.Lock()
	if !m.redirPending || m.fwStatus != fwStateFwReady {
		m.stateMu.Unlock()
		return
	}
	m.redirPending = false
	m.stateMu.Unlock()

	if err := m.programSharedRedirects(ctx); err != nil {
		logger.GetLogger().Error("Failed to reprogram shared redirects on deferred", "error", err)
	}

	m.vrfStore.ProgramAllRedirects(ctx)
	m.vlanStore.ProgramAllRedirects(ctx)

	m.vrfStore.SetInService(true)
	m.vlanStore.SetInService(true)

	m.setRedirDone(ctx, true)
}

// setRedirDone sets the redirDone bit and writes systemState.
func (m *manager) setRedirDone(ctx context.Context, done bool) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	m.redirDone = done
	m.writeSystemStateLocked(ctx)
}

// Phase returns the current phase as a composite bitmask read from the device store.
func (m *manager) Phase() Phase {
	return Phase(m.deviceStore.SystemState())
}

// DeviceStore returns the device store.
func (m *manager) DeviceStore() device.Store {
	return m.deviceStore
}

// HAStore returns the HA store.
func (m *manager) HAStore() hastore.Store {
	return m.haStore
}

// VRFStore returns the VRF store.
func (m *manager) VRFStore() vrf.Store {
	return m.vrfStore
}

// VLANStore returns the VLAN store.
func (m *manager) VLANStore() vlan.Store {
	return m.vlanStore
}

// DPUStore returns the DPU store.
func (m *manager) DPUStore() dpu.Store {
	return m.dpuStore
}

// DeviceWatcher returns the device store watcher for subscribing to token changes.
func (m *manager) DeviceWatcher() device.Watcher {
	return m.deviceStore
}

// IsInService returns true if the service is in service.
func (m *manager) IsInService(ctx context.Context) bool {
	return m.deviceStore.IsInService()
}

// IsLbModePinning returns true if in pinning load balancing mode.
func (m *manager) IsLbModePinning(ctx context.Context) bool {
	return m.deviceStore.LbMode() == "pinning"
}

// GetToken returns the Kubernetes controller authentication token.
func (m *manager) GetToken() string {
	return m.deviceStore.Token()
}

// SetToken parses and sets the Kubernetes controller authentication token.
func (m *manager) SetToken(ctx context.Context, token string) (bool, error) {
	return m.deviceStore.SetToken(ctx, token)
}

// GetControllerConnectionStatus returns the device connection status.
func (m *manager) GetControllerConnectionStatus() string {
	return m.deviceStore.ConnectionStatus()
}

// GetSerialNum returns the serial number from the controller store.
func (m *manager) GetSerialNum(ctx context.Context) string {
	return m.deviceStore.SerialNumber()
}

// SetRegFail sets the registration failure status.
// State synchronization to gNMI is handled by the controller store.
// When reason is RegFailK8sAuth, also sets SkipReg so callers can gate on it.
func (m *manager) SetRegFail(ctx context.Context, reason string) {
	logger.GetLogger().Debug("SetRegFail", "reason", reason)
	m.deviceStore.SetAdmissionStatus(ctx, device.ControllerStateFailure, reason)
	if reason == RegFailK8sAuth {
		m.deviceStore.SetSkipReg(ctx, true, reason)
	}
}

// SetRegOk sets the registration success status.
// State synchronization to gNMI is handled by the controller store.
func (m *manager) SetRegOk(ctx context.Context, reason string) {
	logger.GetLogger().Debug("SetRegOk", "reason", reason)
	m.deviceStore.SetAdmissionStatus(ctx, device.ControllerStateSuccess, reason)
}

// SetConnFail sets the connection failure status.
// ConnPending bit is managed atomically by SetConnectionStatus in the device store.
func (m *manager) SetConnFail(ctx context.Context, reason string) {
	logger.GetLogger().Debug("SetConnFail", "reason", reason)
	m.deviceStore.SetConnectionStatus(ctx, device.ControllerStateFailure, reason)
}

// SetConnOk sets the connection success status.
// ConnPending bit is managed atomically by SetConnectionStatus in the device store.
func (m *manager) SetConnOk(ctx context.Context, reason string) {
	logger.GetLogger().Debug("SetConnOk", "reason", reason)
	m.deviceStore.SetConnectionStatus(ctx, device.ControllerStateSuccess, reason)
}

// ResetReg resets the registration status.
func (m *manager) ResetReg(ctx context.Context) {
	m.deviceStore.ResetRegistration(ctx)
}

// ResetConn resets the connection status.
func (m *manager) ResetConn(ctx context.Context) {
	m.deviceStore.ResetConnection(ctx)
}

// IsPeerOk returns true if the peer is configured and OK.
func (m *manager) IsPeerOk(ctx context.Context, peer string) bool {
	peerInfo, ok := m.haStore.Peer(peer)
	if !ok {
		return false
	}
	return peerInfo.SvcState == types.SvcStateSuccess
}

// NotifyPolicyCheck notifies the HA system about policy check status.
func (m *manager) NotifyPolicyCheck(ctx context.Context, check bool) {
	m.haStore.SetLocalPolicyCheck(ctx, check)
}

// GetExitCodeForSignal returns the appropriate exit code.
// During upgrades or on SIGTERM, returns TerminateExitCode to prevent restart.
// Otherwise returns RestartExitCode so the init script restarts the agent.
func (m *manager) GetExitCodeForSignal(sig os.Signal, inUpgrade bool) int {
	if inUpgrade || sig == syscall.SIGTERM {
		return shutdown.TerminateExitCode
	}
	return shutdown.RestartExitCode
}

// GracefulRestart triggers a graceful agent restart. If cleanup is true,
// Close() is called first to clean up switch state (service redirects,
// fwPolicyState, storage, port ranges, system state, gNMI handler).
func (m *manager) GracefulRestart(ctx context.Context, cleanup bool) {
	if cleanup {
		m.Close(ctx)
	}
	shutdown.TriggerShutdown(shutdown.RestartExitCode)
}

// ShowStatus returns the operational status.
func (m *manager) ShowStatus(ctx context.Context) string {
	buf := new(bytes.Buffer)
	w := tabwriter.NewWriter(buf, 0, 0, 3, ' ', 0)

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "=== NXOS Manager Status ===")
	fmt.Fprintf(w, "Phase:\t%s\n", m.Phase())
	fmt.Fprintf(w, "Ready:\t%v\n", m.dpuStore.IsReady() || m.dpuStore.IsSkipDPU())
	if m.dpuStore.IsSkipDPU() {
		fmt.Fprintf(w, "DPU Mode:\tDPUless mode\n")
	}
	fmt.Fprintf(w, "VRF Count:\t%d\n", len(m.vrfStore.List()))
	fmt.Fprintf(w, "VLAN Count:\t%d\n", len(m.vlanStore.List()))
	fmt.Fprintf(w, "DPU Count:\t%d\n", m.dpuStore.Count())
	fmt.Fprintf(w, "HA Enabled:\t%v\n", m.haStore.Enabled() == "enabled")
	fmt.Fprintf(w, "HA Leader:\t%v\n", m.haStore.IsLeader())
	fmt.Fprintf(w, "Connected:\t%v\n", m.deviceStore.ConnectionStatus() == device.ControllerStateSuccess)
	fmt.Fprintf(w, "Serial:\t%s\n", m.deviceStore.SerialNumber())
	fmt.Fprintf(w, "Model:\t%s\n", m.deviceStore.Model())
	fmt.Fprintf(w, "SW Version:\t%s\n", m.deviceStore.SoftwareVersion())

	w.Flush()
	return buf.String()
}

// ShowHa returns the HA status.
func (m *manager) ShowHa(ctx context.Context) string {
	buf := new(bytes.Buffer)
	w := tabwriter.NewWriter(buf, 0, 0, 3, ' ', 0)

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "=== HA Status ===")
	fmt.Fprintf(w, "Admin State:\t%s\n", m.haStore.Enabled())
	fmt.Fprintf(w, "Oper State:\t%s\n", m.haStore.SwitchState())
	fmt.Fprintf(w, "Leader:\t%v\n", m.haStore.IsLeader())
	fmt.Fprintf(w, "Local IP:\t%s\n", m.haStore.HaIP())
	local := m.haStore.Local()
	fmt.Fprintf(w, "HA State:\t%s\n", local.HaState)
	fmt.Fprintf(w, "SVC State:\t%s\n", local.SvcState)
	fmt.Fprintf(w, "Criteria Met:\t%v\n", local.CriteriaMet)

	peers := m.haStore.AllPeers()
	fmt.Fprintf(w, "\nPeers (%d):\n", len(peers))
	for ip, peer := range peers {
		fmt.Fprintf(w, "  %s:\tSvcState=%s, IpConfigState=%s\n", ip, peer.SvcState, peer.IpConfigState)
	}

	if len(local.Criteria) > 0 {
		fmt.Fprintf(w, "\nLocal Criteria:\n")
		for name, value := range local.Criteria {
			fmt.Fprintf(w, "  %s:\t%v\n", name, value)
		}
	}

	w.Flush()
	return buf.String()
}

// ShowAdj returns the HA adjacencies.
func (m *manager) ShowAdj(ctx context.Context) string {
	buf := new(bytes.Buffer)
	w := tabwriter.NewWriter(buf, 0, 0, 3, ' ', 0)

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "=== HA Adjacencies ===")

	peers := m.haStore.AllPeers()
	for ip, peer := range peers {
		fmt.Fprintf(w, "Peer:\t%s\n", ip)
		fmt.Fprintf(w, "  Connected:\t%v\n", peer.Connected)
		if peer.ConnectedEpoch > 0 {
			fmt.Fprintf(w, "  Last Adj:\t%d\n", peer.ConnectedEpoch)
		}
	}

	w.Flush()
	return buf.String()
}

// ShowMbr returns the HA members.
func (m *manager) ShowMbr(ctx context.Context) string {
	buf := new(bytes.Buffer)
	w := tabwriter.NewWriter(buf, 0, 0, 3, ' ', 0)

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "=== HA Members ===")

	peers := m.haStore.AllPeers()
	for ip, peer := range peers {
		if peer.MemberInfo == nil {
			continue
		}
		fmt.Fprintf(w, "Member:\t%s\n", ip)
		fmt.Fprintf(w, "  Serial:\t%s\n", peer.MemberInfo.SerialNum)
		fmt.Fprintf(w, "  Model:\t%s\n", peer.MemberInfo.Model)
		fmt.Fprintf(w, "  SW Version:\t%s\n", peer.MemberInfo.SWVersion)
	}

	w.Flush()
	return buf.String()
}

// DelTokens deletes the authentication tokens.
func (m *manager) DelTokens(ctx context.Context) string {
	// Clear the token
	m.deviceStore.SetToken(ctx, "")

	// Try to delete the token file
	if err := os.Remove(TokenFile); err != nil && !os.IsNotExist(err) {
		return fmt.Sprintf("Failed to delete token file: %v", err)
	}

	return "Tokens deleted"
}

// Status returns the current status.
func (m *manager) Status() Status {
	return Status{
		Phase:     m.Phase(),
		Ready:     m.dpuStore.IsReady() || m.dpuStore.IsSkipDPU(),
		VRFCount:  len(m.vrfStore.List()),
		VLANCount: len(m.vlanStore.List()),
		DPUCount:  m.dpuStore.Count(),
		HAEnabled: m.haStore.Enabled() == "enabled",
		HALeader:  m.haStore.IsLeader(),
		Connected: m.deviceStore.ConnectionStatus() == device.ControllerStateSuccess,
	}
}

// String returns a string representation of the status.
func (s Status) String() string {
	return fmt.Sprintf("Phase: %s, Ready: %v, VRFs: %d, VLANs: %d, DPUs: %d, HA: %v (Leader: %v), Connected: %v",
		s.Phase, s.Ready, s.VRFCount, s.VLANCount, s.DPUCount, s.HAEnabled, s.HALeader, s.Connected)
}

// DpuInSync updates the DPU in-sync status with a settling window.
// No-op when skipDPU is enabled (DPUless mode).
// When inSync transitions from true→false, the HACritDpuInSync criterion is held
// at true for up to dpuInSyncSettlingWindow before applying the degradation. This
// dampens transient mismatches during policy deployments (~60s).
func (m *manager) DpuInSync(ctx context.Context, inSync bool) {
	if m.dpuStore.IsSkipDPU() {
		return
	}
	m.dpuStore.SetInSync(inSync)

	if inSync {
		// Recovered — clear settling, update criterion immediately.
		m.dpuInSyncSettlingStart = time.Time{}
		m.haStore.UpdateLocalCriterion(ctx, types.HACritDpuInSync, true)
		return
	}

	// Already degraded — no settling needed.
	local := m.haStore.Local()
	if !local.Criteria[types.HACritDpuInSync] {
		return
	}

	// Out-of-sync — dampen the true→false transition.
	now := time.Now()
	if m.dpuInSyncSettlingStart.IsZero() {
		// First failure in this episode — start settling window.
		m.dpuInSyncSettlingStart = now
		logger.GetLogger().Info("DPU out-of-sync settling started",
			"window", m.dpuInSyncSettlingWindow)
		return // suppress
	}

	elapsed := now.Sub(m.dpuInSyncSettlingStart)
	if elapsed < m.dpuInSyncSettlingWindow {
		logger.GetLogger().Debug("DPU out-of-sync settling in progress",
			"elapsed", elapsed, "remaining", m.dpuInSyncSettlingWindow-elapsed)
		return // within window — suppress
	}

	// Window expired — apply degradation.
	m.dpuInSyncSettlingStart = time.Time{}
	m.haStore.UpdateLocalCriterion(ctx, types.HACritDpuInSync, false)
}

// GnmiHandler returns the underlying gNMI handler.
func (m *manager) GnmiHandler() gnmi.GnmiHandler {
	return m.gnmiHandler
}

// cleanupDPUPortRanges deletes the TCP/UDP port range allocations for all discovered DPUs.
// Used during Close() and handleSvcInstanceDelete().
func (m *manager) cleanupDPUPortRanges(ctx context.Context) {
	if m.dpuStore.IsSkipDPU() {
		return
	}
	logger.GetLogger().Info("Cleaning up DPU port ranges")
	for _, d := range m.dpuStore.List() {
		if err := m.dpuStore.DeleteDpuPortRange(ctx, d.ModuleNum); err != nil {
			logger.GetLogger().Warn("Failed to delete DPU port range", "module", d.ModuleNum, logfields.Error, err)
		}
	}
}

// handleServiceLifecycleNotification handles delete notifications for
// SvcInstance-list and fwpolicy-items paths that require manager-level
// actions (HA cleanup, graceful restart). Updates are ignored — they are
// handled by individual domain stores.
func (m *manager) handleServiceLifecycleNotification(ctx context.Context, path string, isDelete bool) {
	if !isDelete {
		return
	}

	switch {
	case paths.PathMatches(path, paths.SvcFwPolicyPath):
		m.handleSvcFwPolicyDelete(ctx)
	case paths.PathMatches(path, paths.SvcInstancePath):
		m.handleSvcInstanceDelete(ctx, path)
	}
}

// handleSvcInstanceDelete handles deletion of the hypershield service instance.
// Mirrors the old delSvcInstance: clean HA config, DPU port ranges, then
// graceful restart without cleanup.
func (m *manager) handleSvcInstanceDelete(ctx context.Context, path string) {
	if !strings.Contains(path, "name=hypershield") {
		logger.GetLogger().Debug("SvcInstance delete for non-hypershield service, ignored", "path", path)
		return
	}

	logger.GetLogger().Info("SvcInstance delete detected, cleaning up and restarting")

	// Delete HA config from repository to notify DPUs before restart.
	if err := library.GetRepository().DeleteConfig(v1alpha.ConfigType_CONFIG_TYPE_HA); err != nil {
		logger.GetLogger().Error("Failed to delete HA config from repository", logfields.Error, err)
	}

	// Clean DPU port ranges.
	m.cleanupDPUPortRanges(ctx)

	// Graceful restart WITHOUT cleanup (service redirects left for NX-OS to clean).
	m.GracefulRestart(ctx, false)
}

// handleSvcFwPolicyDelete handles deletion of the firewall policy.
// Clears the in-service state so HA deactivates gracefully without restarting.
// Individual service VRF/VLAN child deletes arrive before this parent delete,
// so redirect cleanup is already handled reactively by those stores.
func (m *manager) handleSvcFwPolicyDelete(ctx context.Context) {
	logger.GetLogger().Info("SvcFwPolicy delete detected, clearing in-service state")
	m.deviceStore.SetInService(ctx, "")
}

// DpuHealth updates the DPU health status and reports system state to NXOS.
// No-op when skipDPU is enabled (DPUless mode).
func (m *manager) DpuHealth(ctx context.Context, healthy bool, count int) {
	if m.dpuStore.IsSkipDPU() {
		return
	}
	m.dpuStore.SetHealth(healthy, count)
	m.haStore.UpdateLocalCriterion(ctx, types.HACritDpuHealth, m.dpuStore.IsHealthy())

	// Update fw status: gate on in-service so DpuHealth during out-of-service
	// doesn't change the disabled state.
	if !m.deviceStore.IsInService() {
		return
	}
	if m.dpuStore.IsHealthy() {
		m.setFwReady(ctx)
		m.programDeferredRedirects(ctx)
	} else {
		m.setDpuPending(ctx)
	}
}
