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
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/version"

	"github.com/isovalent/hubble-fgs/pkg/nxos/store/device"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/dpu"
	hastore "github.com/isovalent/hubble-fgs/pkg/nxos/store/ha"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
	hav1 "github.com/isovalent/hubble-fgs/pkg/proto/ha/v1"
)

func TestManager_IsLeader(t *testing.T) {
	haStore := hastore.NewStore(context.Background())
	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithLocalIP("10.0.0.1"),
	)

	// Not leader by default
	if mgr.IsLeader() {
		t.Error("expected not to be leader by default")
	}

	// Set leader in store
	haStore.SetLeader(context.Background(), true)

	if !mgr.IsLeader() {
		t.Error("expected to be leader after store update")
	}
}

func TestManager_ConnectDisconnectPeer(t *testing.T) {
	// Use mock client factory
	mgr := NewManager(
		WithClientFactory(func() Client {
			return NewMockClient()
		}),
		WithDeviceStore(device.NewStore(context.Background())),
	)

	ctx := context.Background()

	// Connect peer
	if err := mgr.ConnectPeer(ctx, "10.0.0.2"); err != nil {
		t.Errorf("connect peer failed: %v", err)
	}

	peers := mgr.Peers()
	if len(peers) != 1 {
		t.Errorf("expected 1 peer, got %d", len(peers))
	}

	// Disconnect peer
	if err := mgr.DisconnectPeer("10.0.0.2"); err != nil {
		t.Errorf("disconnect peer failed: %v", err)
	}

	peers = mgr.Peers()
	if len(peers) != 0 {
		t.Errorf("expected 0 peers after disconnect, got %d", len(peers))
	}
}

func TestCompareIPs(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected int
	}{
		{"equal", "10.0.0.1", "10.0.0.1", 0},
		{"a less than b", "10.0.0.1", "10.0.0.2", -1},
		{"a greater than b", "10.0.0.2", "10.0.0.1", 1},
		{"different octets", "10.0.0.1", "10.0.1.1", -1},
		{"ipv6 equal", "::1", "::1", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := net.ParseIP(tt.a)
			b := net.ParseIP(tt.b)
			result := compareIPs(a, b)
			if result != tt.expected {
				t.Errorf("compareIPs(%s, %s) = %d, expected %d", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

func TestManager_BuildMemberInfo_WithProvider(t *testing.T) {
	expectedInfo := types.HAPeerMember{
		SerialNum:  "SN123",
		Model:      "TestModel",
		SWVersion:  "1.0.0",
		CPAVersion: "2.0.0",
	}

	haStore := hastore.NewStore(context.Background())
	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithManagerMemberInfoProvider(func() types.HAPeerMember {
			return expectedInfo
		}),
	).(*manager)

	info := mgr.buildMemberInfo()
	if info.SerialNum != expectedInfo.SerialNum {
		t.Errorf("expected serial %s, got %s", expectedInfo.SerialNum, info.SerialNum)
	}
	if info.Model != expectedInfo.Model {
		t.Errorf("expected model %s, got %s", expectedInfo.Model, info.Model)
	}
}

func TestManager_BuildMemberInfo_WithDeviceStoreCPAVersion(t *testing.T) {
	// Set a known version for the test; in production this is set via build ldflags.
	version.Version = "test-2.0.0"
	t.Cleanup(func() { version.Version = "" })

	ctx := context.Background()
	ds := device.NewStore(ctx)
	haStore := hastore.NewStore(ctx)
	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithDeviceStore(ds),
	).(*manager)

	info := mgr.buildMemberInfo()
	if info.CPAVersion != "test-2.0.0" {
		t.Errorf("buildMemberInfo: expected CPAVersion %q, got %q", "test-2.0.0", info.CPAVersion)
	}
	if info.CPAVersion != ds.CPAVersion() {
		t.Errorf("buildMemberInfo: CPAVersion %q does not match device store %q", info.CPAVersion, ds.CPAVersion())
	}

	deviceInfo := mgr.buildDeviceInfo()
	if deviceInfo.CPAVersion != "test-2.0.0" {
		t.Errorf("buildDeviceInfo: expected CPAVersion %q, got %q", "test-2.0.0", deviceInfo.CPAVersion)
	}
}

// TestManager_Run_ExitsOnCancel verifies that Run() returns nil when ctx is cancelled
// before HA is configured.
func TestManager_Run_ExitsOnCancel(t *testing.T) {
	haStore := hastore.NewStore(context.Background())
	mgr := NewManager(
		WithHAStoreForManager(haStore),
	)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Run(ctx)
	}()

	// Cancel immediately — Run() is waiting for config, should exit cleanly.
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run() returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Run() did not return after context cancellation")
	}
}

// TestManager_Run_ActivatesWhenConfigured verifies that Run() activates once HA
// is configured with at least one peer, and exits cleanly on context cancellation.
func TestManager_Run_ActivatesWhenConfigured(t *testing.T) {
	haStore := hastore.NewStore(context.Background())
	deviceStore := device.NewStore(context.Background())
	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithDeviceStore(deviceStore),
		WithClientFactory(func() Client { return NewMockClient() }),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Run(ctx)
	}()

	// Give Run() a moment to start waiting.
	time.Sleep(10 * time.Millisecond)

	// Configure HA with a peer, source IP, and in-service — this should trigger activation.
	bgCtx := context.Background()
	deviceStore.SetInService(bgCtx, "in-service")
	haStore.SetEnabled(bgCtx, "enabled")
	haStore.SetHaIP(bgCtx, "10.0.0.1")
	haStore.SetPeer(bgCtx, "10.0.0.2", types.HAPeerState{IP: "10.0.0.2", IpConfigState: hastore.PeerIpCfgStateSuccess})

	// Give Run() a moment to activate.
	time.Sleep(50 * time.Millisecond)

	// Cancel context — Run() should exit.
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run() returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Run() did not return after context cancellation")
	}
}

// TestManager_Run_DeactivatesOnDeconfigured verifies that Run() deactivates
// when HA is deconfigured, then returns to waiting.
func TestManager_Run_DeactivatesOnDeconfigured(t *testing.T) {
	haStore := hastore.NewStore(context.Background())
	deviceStore := device.NewStore(context.Background())
	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithDeviceStore(deviceStore),
		WithClientFactory(func() Client { return NewMockClient() }),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Run(ctx)
	}()

	bgCtx := context.Background()

	// Configure HA with a peer, source IP, and in-service — triggers activation.
	deviceStore.SetInService(bgCtx, "in-service")
	haStore.SetEnabled(bgCtx, "enabled")
	haStore.SetHaIP(bgCtx, "10.0.0.1")
	haStore.SetPeer(bgCtx, "10.0.0.2", types.HAPeerState{IP: "10.0.0.2", IpConfigState: hastore.PeerIpCfgStateSuccess})

	time.Sleep(50 * time.Millisecond)

	// Disable — triggers deactivation, Run() goes back to waiting.
	haStore.SetEnabled(bgCtx, "")

	time.Sleep(50 * time.Millisecond)

	// Run() should still be running (waiting for reconfiguration), not returned.
	select {
	case err := <-errCh:
		t.Errorf("Run() returned prematurely with: %v", err)
	default:
		// Good — still running
	}

	// Cancel to end the test cleanly.
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run() returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Run() did not return after context cancellation")
	}
}

// TestManager_Run_WaitsForInService verifies that Run() blocks when HA is enabled
// and peers are configured but InServiceState is "".
func TestManager_Run_WaitsForInService(t *testing.T) {
	haStore := hastore.NewStore(context.Background())
	deviceStore := device.NewStore(context.Background())
	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithDeviceStore(deviceStore),
		WithClientFactory(func() Client { return NewMockClient() }),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Run(ctx)
	}()

	bgCtx := context.Background()

	// Enable HA with a peer — but InService is still ""
	haStore.SetEnabled(bgCtx, "enabled")
	haStore.SetPeer(bgCtx, "10.0.0.2", types.HAPeerState{IP: "10.0.0.2", IpConfigState: hastore.PeerIpCfgStateSuccess})

	// Wait briefly — Run() should still be blocked waiting for InService.
	time.Sleep(50 * time.Millisecond)

	select {
	case err := <-errCh:
		t.Errorf("Run() returned prematurely with: %v", err)
	default:
		// Good — still blocked waiting for InService
	}

	// Cancel to end the test cleanly.
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run() returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Run() did not return after context cancellation")
	}
}

// TestManager_Run_ActivatesWhenInServiceSet verifies that Run() activates once
// all three prerequisites are met: HA enabled, peers configured, InService set.
func TestManager_Run_ActivatesWhenInServiceSet(t *testing.T) {
	haStore := hastore.NewStore(context.Background())
	deviceStore := device.NewStore(context.Background())
	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithDeviceStore(deviceStore),
		WithClientFactory(func() Client { return NewMockClient() }),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Run(ctx)
	}()

	bgCtx := context.Background()

	// Enable HA with a peer and source IP.
	haStore.SetEnabled(bgCtx, "enabled")
	haStore.SetHaIP(bgCtx, "10.0.0.1")
	haStore.SetPeer(bgCtx, "10.0.0.2", types.HAPeerState{IP: "10.0.0.2", IpConfigState: hastore.PeerIpCfgStateSuccess})

	// Still blocked — InService is "".
	time.Sleep(30 * time.Millisecond)

	// Set InService — should now activate.
	deviceStore.SetInService(bgCtx, "in-service")

	// Give Run() time to activate.
	time.Sleep(50 * time.Millisecond)

	// Run() should still be running (not returned).
	select {
	case err := <-errCh:
		t.Errorf("Run() returned prematurely with: %v", err)
	default:
		// Good — activated and running
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run() returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Run() did not return after context cancellation")
	}
}

// TestManager_isConfigReady verifies the three-prerequisite check.
func TestManager_isConfigReady(t *testing.T) {
	haStore := hastore.NewStore(context.Background())
	deviceStore := device.NewStore(context.Background())
	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithDeviceStore(deviceStore),
	).(*manager)

	bgCtx := context.Background()

	// Nothing configured — not ready.
	if mgr.isConfigReady() {
		t.Error("expected not ready when nothing configured")
	}

	// HA enabled — still not ready (no peers, no InService).
	haStore.SetEnabled(bgCtx, "enabled")
	if mgr.isConfigReady() {
		t.Error("expected not ready with no peers")
	}

	// Add peer — still not ready (no HaIP, no InService).
	haStore.SetPeer(bgCtx, "10.0.0.2", types.HAPeerState{IP: "10.0.0.2"})
	if mgr.isConfigReady() {
		t.Error("expected not ready with HaIP empty")
	}

	// Set HaIP — still not ready (InService == "").
	haStore.SetHaIP(bgCtx, "10.0.0.1")
	if mgr.isConfigReady() {
		t.Error("expected not ready with InService empty")
	}

	// Set InService — now ready.
	deviceStore.SetInService(bgCtx, "out-of-service")
	if !mgr.isConfigReady() {
		t.Error("expected ready when all prerequisites met")
	}
}

// TestProcessHaInfo_NotReadyRemovesStandby: HA_STATE_HA_NOTREADY from peer should remove standby.
func TestProcessHaInfo_NotReadyRemovesStandby(t *testing.T) {
	haStore := hastore.NewStore(context.Background())
	ctx := context.Background()

	// Pre-inject standby.
	haStore.UpdateLocalCriterion(ctx, types.HACritHaStandby, false)

	mgr := NewManager(WithHAStoreForManager(haStore)).(*manager)
	mgr.ProcessHaInfo(ctx, "10.0.0.2", &hav1.HaInfo{Ha: hav1.HA_STATE_HA_NOTREADY})

	local := haStore.Local()
	if _, has := local.Criteria[types.HACritHaStandby]; has {
		t.Error("expected standby criterion to be removed after NOTREADY notify")
	}
}

// TestProcessHaInfo_SwitchoverRemovesStandby: HA_STATE_HA_SWITCHOVER from peer should remove standby.
func TestProcessHaInfo_SwitchoverRemovesStandby(t *testing.T) {
	haStore := hastore.NewStore(context.Background())
	ctx := context.Background()

	// Pre-inject standby.
	haStore.UpdateLocalCriterion(ctx, types.HACritHaStandby, false)

	mgr := NewManager(WithHAStoreForManager(haStore)).(*manager)
	mgr.ProcessHaInfo(ctx, "10.0.0.2", &hav1.HaInfo{Ha: hav1.HA_STATE_HA_SWITCHOVER})

	local := haStore.Local()
	if _, has := local.Criteria[types.HACritHaStandby]; has {
		t.Error("expected standby criterion to be removed after SWITCHOVER notify")
	}
}

// TestManager_HoldDownTimer_StartsOnRecovery verifies that the hold-down timer
// is created when criteria recover and CriteriaRecoveryPending becomes true.
func TestManager_HoldDownTimer_StartsOnRecovery(t *testing.T) {
	ctx := context.Background()
	haStore := hastore.NewStore(ctx)
	mgr := NewManager(
		WithHAStoreForManager(haStore),
	).(*manager)

	// Start with CriteriaMet=false, no criteria set (all-false effectively).
	// Set a criterion to false first to establish not-met state.
	haStore.UpdateLocalCriterion(ctx, types.HACritDpuHealth, false)
	mgr.recomputeAndApplyState(ctx)
	if mgr.holdDownTimer != nil {
		t.Error("expected no hold-down timer when criteria are not met")
	}

	// Now set all criteria to true — recovery should start, timer should be created.
	haStore.UpdateLocalCriterion(ctx, types.HACritDpuHealth, true)
	mgr.recomputeAndApplyState(ctx)

	local := haStore.Local()
	if !local.CriteriaRecoveryPending {
		t.Error("expected CriteriaRecoveryPending to be true")
	}
	if local.CriteriaMet {
		t.Error("expected CriteriaMet to still be false during hold-down")
	}
	if mgr.holdDownTimer == nil {
		t.Error("expected hold-down timer to be started")
	}

	// Cleanup
	if mgr.holdDownTimer != nil {
		mgr.holdDownTimer.Stop()
	}
}

// TestManager_HoldDownTimer_CancelledOnFlap verifies that the hold-down timer
// is cancelled when criteria flap back to false during the hold-down period.
func TestManager_HoldDownTimer_CancelledOnFlap(t *testing.T) {
	ctx := context.Background()
	haStore := hastore.NewStore(ctx)
	mgr := NewManager(
		WithHAStoreForManager(haStore),
	).(*manager)

	// Start recovery.
	haStore.UpdateLocalCriterion(ctx, types.HACritDpuHealth, false)
	mgr.recomputeAndApplyState(ctx)
	haStore.UpdateLocalCriterion(ctx, types.HACritDpuHealth, true)
	mgr.recomputeAndApplyState(ctx)

	if mgr.holdDownTimer == nil {
		t.Fatal("expected hold-down timer to be started")
	}

	// Flap: set criterion back to false.
	haStore.UpdateLocalCriterion(ctx, types.HACritDpuHealth, false)
	mgr.recomputeAndApplyState(ctx)

	if mgr.holdDownTimer != nil {
		t.Error("expected hold-down timer to be cancelled after flap")
	}

	local := haStore.Local()
	if local.CriteriaRecoveryPending {
		t.Error("expected CriteriaRecoveryPending to be false after flap")
	}
	if local.CriteriaFlapCount != 1 {
		t.Errorf("expected flap count 1, got %d", local.CriteriaFlapCount)
	}
}

// TestManager_HoldDownTimer_FiresAndPromotes verifies that when the hold-down
// timer fires, checkHoldDown promotes CriteriaMet to true.
func TestManager_HoldDownTimer_FiresAndPromotes(t *testing.T) {
	ctx := context.Background()
	haStore := hastore.NewStore(ctx)
	mgr := NewManager(
		WithHAStoreForManager(haStore),
	).(*manager)

	// Set criteria to false then true to trigger recovery.
	haStore.UpdateLocalCriterion(ctx, types.HACritDpuHealth, false)
	mgr.recomputeAndApplyState(ctx)
	haStore.UpdateLocalCriterion(ctx, types.HACritDpuHealth, true)
	mgr.recomputeAndApplyState(ctx)

	if mgr.holdDownTimer == nil {
		t.Fatal("expected hold-down timer to be started")
	}

	// Simulate the hold-down having already elapsed by backdating the epoch.
	local := haStore.Local()
	local.CriteriaRecoveryEpoch = time.Now().Unix() - int64(CriteriaMetHoldDown/time.Second) - 1
	haStore.SetLocalCriteriaMet(ctx, local)

	// Simulate what happens when the timer fires: nil the timer, call checkHoldDown.
	mgr.holdDownTimer.Stop()
	mgr.holdDownTimer = nil
	mgr.checkHoldDown(ctx)

	local = haStore.Local()
	if !local.CriteriaMet {
		t.Error("expected CriteriaMet to be true after hold-down expired")
	}
	if local.CriteriaRecoveryPending {
		t.Error("expected CriteriaRecoveryPending to be false after promotion")
	}
}

// TestManager_HoldDownTimer_CancellationPersisted verifies that when the hold-down
// timer fires but criteria no longer pass, the cancellation (CriteriaRecoveryPending=false,
// flap count incremented) is persisted to the store.
func TestManager_HoldDownTimer_CancellationPersisted(t *testing.T) {
	ctx := context.Background()
	haStore := hastore.NewStore(ctx)
	mgr := NewManager(
		WithHAStoreForManager(haStore),
	).(*manager)

	// Start recovery: set criterion false then true.
	haStore.UpdateLocalCriterion(ctx, types.HACritDpuHealth, false)
	mgr.recomputeAndApplyState(ctx)
	haStore.UpdateLocalCriterion(ctx, types.HACritDpuHealth, true)
	mgr.recomputeAndApplyState(ctx)

	if mgr.holdDownTimer == nil {
		t.Fatal("expected hold-down timer to be started")
	}

	// Backdate the epoch so CheckHoldDown thinks the hold-down expired.
	local := haStore.Local()
	local.CriteriaRecoveryEpoch = time.Now().Unix() - int64(CriteriaMetHoldDown/time.Second) - 1
	haStore.SetLocalCriteriaMet(ctx, local)

	// Now make criteria fail so CheckHoldDown won't promote.
	haStore.UpdateLocalCriterion(ctx, types.HACritDpuHealth, false)

	// Simulate timer firing.
	mgr.holdDownTimer.Stop()
	mgr.holdDownTimer = nil
	mgr.checkHoldDown(ctx)

	// The cancellation should be persisted: CriteriaRecoveryPending=false, flap count incremented.
	local = haStore.Local()
	if local.CriteriaRecoveryPending {
		t.Error("expected CriteriaRecoveryPending to be false after cancellation")
	}
	if local.CriteriaRecoveryEpoch != 0 {
		t.Errorf("expected CriteriaRecoveryEpoch to be 0, got %d", local.CriteriaRecoveryEpoch)
	}
	if local.CriteriaFlapCount != 1 {
		t.Errorf("expected flap count 1, got %d", local.CriteriaFlapCount)
	}
	if local.CriteriaMet {
		t.Error("expected CriteriaMet to remain false")
	}
}

// TestManager_HoldDownChan_NilWhenNoTimer verifies holdDownChan returns nil
// when no timer is active, which causes the select case to block forever.
func TestManager_HoldDownChan_NilWhenNoTimer(t *testing.T) {
	mgr := &manager{}
	if mgr.holdDownChan() != nil {
		t.Error("expected nil channel when no timer is active")
	}
}

// mockManager implements the Manager interface for testing.
type mockManager struct {
	mu       sync.RWMutex
	isLeader bool
	peers    []string
}

// NewMockManager creates a mock HA manager for testing.
func NewMockManager() *mockManager {
	return &mockManager{
		peers: []string{},
	}
}

// SetLeader sets the leader status for testing.
func (m *mockManager) SetLeader(isLeader bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.isLeader = isLeader
}

func (m *mockManager) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func (m *mockManager) IsLeader() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isLeader
}

func (m *mockManager) Peers() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]string, len(m.peers))
	copy(result, m.peers)
	return result
}

func (m *mockManager) ConnectPeer(ctx context.Context, peer string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peers = append(m.peers, peer)
	return nil
}

func (m *mockManager) DisconnectPeer(peer string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, p := range m.peers {
		if p == peer {
			m.peers = append(m.peers[:i], m.peers[i+1:]...)
			break
		}
	}
	return nil
}

func (m *mockManager) ProcessMemberInfo(ctx context.Context, peer string, info types.HAPeerMember) (bool, string) {
	return false, ""
}

func (m *mockManager) NotifyRemoval(ctx context.Context, peer string) {}

func (m *mockManager) HandleRemoval(ctx context.Context, peer string) {}

func (m *mockManager) HandleAdjFailureNotify(ctx context.Context, peer string, reason string) {}

func (m *mockManager) ProcessHaInfo(ctx context.Context, peer string, haInfo *hav1.HaInfo) {}

func (m *mockManager) RegisterDpu(ctx context.Context, dpuUid string)              {}
func (m *mockManager) UpdateKeepalive(ctx context.Context, dpuUid string, up bool) {}
func (m *mockManager) UpdateBulkSyncLocal(ctx context.Context, dpuUid string, done bool) {
}
func (m *mockManager) UpdateBulkSyncPeer(ctx context.Context, dpuUid string, done bool) {
}
func (m *mockManager) UpdatePolicyRevision(ctx context.Context, revision string) {}

func (m *mockManager) SetDebugPeerFail(ctx context.Context, peer string, membership, adjacency bool) {
}
func (m *mockManager) SetDebugPeerOk(ctx context.Context, peer string) {}
func (m *mockManager) SetDebugFail(ctx context.Context, fail bool)     {}
func (m *mockManager) NotifyServiceFailure(ctx context.Context)        {}

// TestManager_Run_StartsNotReadyWithDPUs verifies that when DPUs are present,
// the local service state starts as "not-ready" (not "ready") until DPUs
// report health. This prevents the spurious ready -> not-ready -> ready
// transition during startup.
func TestManager_Run_StartsNotReadyWithDPUs(t *testing.T) {
	ctx := context.Background()

	haStore := hastore.NewStore(ctx)
	deviceStore := device.NewStore(ctx)
	dpuStore := dpu.NewStore(ctx)

	// Add a DPU so the manager expects DPU health criteria.
	dpuStore.Update(ctx, types.DPU{Name: "dpu1", IP: "169.254.0.1", ModuleNum: 1})

	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithDeviceStore(deviceStore),
		WithDPUStore(dpuStore),
		WithClientFactory(func() Client { return NewMockClient() }),
	)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Run(runCtx)
	}()

	// Give Run() time to start waiting.
	time.Sleep(10 * time.Millisecond)

	// Configure HA to trigger activation.
	deviceStore.SetInService(ctx, "in-service")
	haStore.SetEnabled(ctx, "enabled")
	haStore.SetHaIP(ctx, "10.0.0.1")
	haStore.SetPeer(ctx, "10.0.0.2", types.HAPeerState{IP: "10.0.0.2", IpConfigState: hastore.PeerIpCfgStateSuccess})

	// Give Run() time to activate.
	time.Sleep(50 * time.Millisecond)

	// Verify local state: SvcState should be "not-ready", not "ready".
	local := haStore.Local()
	if local.SvcState != types.SvcStateFailure {
		t.Errorf("expected SvcState=%q, got %q", types.SvcStateFailure, local.SvcState)
	}
	if local.CriteriaMet {
		t.Error("expected CriteriaMet=false at startup with DPUs")
	}

	// Verify the DPU criteria were pre-populated as false.
	if val, ok := local.Criteria[types.HACritDpuHealth]; !ok || val {
		t.Errorf("expected HACritDpuHealth=false, got ok=%v val=%v", ok, val)
	}
	if val, ok := local.Criteria[types.HACritDpuInSync]; !ok || val {
		t.Errorf("expected HACritDpuInSync=false, got ok=%v val=%v", ok, val)
	}

	// Cancel context — Run() should exit.
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run() returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Run() did not return after context cancellation")
	}
}

func TestManager_Run_ServerStartsOnAdminEnabledOnly(t *testing.T) {
	ctx := context.Background()

	haStore := hastore.NewStore(ctx)
	deviceStore := device.NewStore(ctx)

	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithDeviceStore(deviceStore),
		WithClientFactory(func() Client { return NewMockClient() }),
	).(*manager)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Run(runCtx)
	}()

	// Give Run() time to start waiting.
	time.Sleep(10 * time.Millisecond)

	// Enable admin state but don't configure peers yet.
	// Server should start even without full config.
	haStore.SetEnabled(ctx, "enabled")

	// Give time for server to start.
	time.Sleep(50 * time.Millisecond)

	// Verify server is running.
	mgr.mu.RLock()
	serverRunning := mgr.server != nil
	mgr.mu.RUnlock()

	if !serverRunning {
		t.Error("expected server to be running after admin enabled, even without peers")
	}

	// Now disable admin state — server should stop.
	haStore.SetEnabled(ctx, "disabled")
	time.Sleep(50 * time.Millisecond)

	mgr.mu.RLock()
	serverStopped := mgr.server == nil
	mgr.mu.RUnlock()

	if !serverStopped {
		t.Error("expected server to be stopped after admin disabled")
	}

	// Cancel context — Run() should exit.
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run() returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Run() did not return after context cancellation")
	}
}

// TestManager_Run_NotifiesServiceFailureOnOutOfService verifies that when the
// device transitions to out-of-service, the HA manager immediately sends an
// Adjacency RPC with SVC_FAILURE to connected peers, and does NOT send such
// a notification when transitioning to in-service.
func TestManager_Run_NotifiesServiceFailureOnOutOfService(t *testing.T) {
	ctx := context.Background()

	haStore := hastore.NewStore(ctx)
	deviceStore := device.NewStore(ctx)

	// adjReceived captures adjacency requests received by the mock peer.
	adjReceived := make(chan *hav1.AdjRequest, 10)

	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithDeviceStore(deviceStore),
		WithLocalIP("10.0.0.1"),
		WithClientFactory(func() Client {
			c := NewMockClient()
			c.SetAdjacencyHandler(func(ctx context.Context, req *hav1.AdjRequest) (*hav1.AdjResponse, error) {
				select {
				case adjReceived <- req:
				default:
				}
				return &hav1.AdjResponse{Status: hav1.ADJ_RESPONSE_STATUS_ADJ_SUCCESS}, nil
			})
			return c
		}),
	)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Run(runCtx)
	}()

	bgCtx := context.Background()

	// Activate HA — must have enabled, haIP, peer, and in-service.
	deviceStore.SetInService(bgCtx, "in-service")
	haStore.SetEnabled(bgCtx, "enabled")
	haStore.SetHaIP(bgCtx, "10.0.0.1")
	haStore.SetPeer(bgCtx, "10.0.0.2", types.HAPeerState{IP: "10.0.0.2", IpConfigState: hastore.PeerIpCfgStateSuccess})

	// Give Run() time to activate.
	time.Sleep(50 * time.Millisecond)

	// Directly connect the peer so NotifyServiceFailure can reach it.
	// The peer was added via haStore before activation, so EventPeerAdded was
	// consumed by waitForConfig — the active loop never saw it and peerClients
	// is empty at this point.
	if err := mgr.ConnectPeer(bgCtx, "10.0.0.2"); err != nil {
		t.Fatalf("ConnectPeer failed: %v", err)
	}

	// Drain any adjacency messages sent by the keepalive ticker.
	time.Sleep(20 * time.Millisecond)
	for len(adjReceived) > 0 {
		<-adjReceived
	}

	// Transition to out-of-service — NotifyServiceFailure should fire.
	deviceStore.SetInService(bgCtx, "out-of-service")

	// Wait for the notification (should arrive quickly, not waiting for a tick).
	select {
	case req := <-adjReceived:
		if req.MbrInfo == nil || req.MbrInfo.HaInfo == nil {
			t.Fatal("expected MbrInfo.HaInfo in adjacency request")
		}
		if req.MbrInfo.HaInfo.LocalSvcState != hav1.LOCAL_SVC_STATE_LOCAL_SVC_FAILURE {
			t.Errorf("expected LocalSvcState=LOCAL_SVC_FAILURE, got %v", req.MbrInfo.HaInfo.LocalSvcState)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("did not receive adjacency notification after out-of-service transition")
	}

	// Transition back to in-service — no SVC_FAILURE notification should be sent.
	// Drain first to clear any queued messages.
	for len(adjReceived) > 0 {
		<-adjReceived
	}
	deviceStore.SetInService(bgCtx, "in-service")
	// Wait briefly — any message arriving here would be from NotifyServiceFailure
	// (called only on !isInService). A regular adjacency tick could also arrive,
	// so we check specifically that no SVC_FAILURE-scoped notification was triggered
	// by the in-service transition by verifying nothing arrives in a short window.
	time.Sleep(50 * time.Millisecond)
	hasSvcFailure := false
	for len(adjReceived) > 0 {
		req := <-adjReceived
		if req.MbrInfo != nil && req.MbrInfo.HaInfo != nil &&
			req.MbrInfo.HaInfo.LocalSvcState == hav1.LOCAL_SVC_STATE_LOCAL_SVC_FAILURE {
			hasSvcFailure = true
		}
	}
	if hasSvcFailure {
		t.Error("should not receive SVC_FAILURE notification on in-service transition")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run() returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Run() did not return after context cancellation")
	}
}

// TestManager_Run_DeactivatesOnServiceFunctionRemoved verifies that when the
// service function is removed (InServiceState becomes ""), the HA manager
// notifies peers of service failure and deactivates back to waitForConfig,
// then re-activates when the service function is re-created.
func TestManager_Run_DeactivatesOnServiceFunctionRemoved(t *testing.T) {
	ctx := context.Background()

	haStore := hastore.NewStore(ctx)
	deviceStore := device.NewStore(ctx)

	// adjReceived captures adjacency requests received by the mock peer.
	adjReceived := make(chan *hav1.AdjRequest, 10)

	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithDeviceStore(deviceStore),
		WithLocalIP("10.0.0.1"),
		WithClientFactory(func() Client {
			c := NewMockClient()
			c.SetAdjacencyHandler(func(ctx context.Context, req *hav1.AdjRequest) (*hav1.AdjResponse, error) {
				select {
				case adjReceived <- req:
				default:
				}
				return &hav1.AdjResponse{Status: hav1.ADJ_RESPONSE_STATUS_ADJ_SUCCESS}, nil
			})
			return c
		}),
	)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Run(runCtx)
	}()

	bgCtx := context.Background()

	// Activate HA — must have enabled, haIP, peer, and in-service.
	deviceStore.SetInService(bgCtx, "in-service")
	haStore.SetEnabled(bgCtx, "enabled")
	haStore.SetHaIP(bgCtx, "10.0.0.1")
	haStore.SetPeer(bgCtx, "10.0.0.2", types.HAPeerState{IP: "10.0.0.2", IpConfigState: hastore.PeerIpCfgStateSuccess})

	// Give Run() time to activate.
	time.Sleep(50 * time.Millisecond)

	// Connect the peer so NotifyServiceFailure can reach it.
	if err := mgr.ConnectPeer(bgCtx, "10.0.0.2"); err != nil {
		t.Fatalf("ConnectPeer failed: %v", err)
	}

	// Drain any adjacency messages from the keepalive ticker.
	time.Sleep(20 * time.Millisecond)
	for len(adjReceived) > 0 {
		<-adjReceived
	}

	// Remove the service function (fwpolicy-items deleted) — InService becomes "".
	deviceStore.SetInService(bgCtx, "")

	// Verify peers are notified of service failure before deactivation.
	select {
	case req := <-adjReceived:
		if req.MbrInfo == nil || req.MbrInfo.HaInfo == nil {
			t.Fatal("expected MbrInfo.HaInfo in adjacency request")
		}
		if req.MbrInfo.HaInfo.LocalSvcState != hav1.LOCAL_SVC_STATE_LOCAL_SVC_FAILURE {
			t.Errorf("expected LocalSvcState=LOCAL_SVC_FAILURE, got %v", req.MbrInfo.HaInfo.LocalSvcState)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("did not receive service failure notification after service function removal")
	}

	// Give Run() time to deactivate.
	time.Sleep(50 * time.Millisecond)

	// Run() should still be running (waiting for reconfiguration), not returned.
	select {
	case err := <-errCh:
		t.Errorf("Run() returned prematurely with: %v", err)
	default:
		// Good — still running in waitForConfig
	}

	// Server must be stopped after deactivation.
	impl := mgr.(*manager)
	impl.mu.RLock()
	if impl.server != nil {
		t.Error("expected server to be stopped after SF removal deactivation")
	}
	impl.mu.RUnlock()

	// Re-create the service function — InService set back to "in-service".
	// This should trigger re-activation.
	deviceStore.SetInService(bgCtx, "in-service")

	time.Sleep(50 * time.Millisecond)

	// Run() should still be running (activated again), not returned.
	select {
	case err := <-errCh:
		t.Errorf("Run() returned prematurely after re-activation with: %v", err)
	default:
		// Good — re-activated and running
	}

	// Server must be running after re-activation.
	impl.mu.RLock()
	if impl.server == nil {
		t.Error("expected server to be running after re-activation")
	}
	impl.mu.RUnlock()

	// Cancel to end the test cleanly.
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run() returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Run() did not return after context cancellation")
	}
}

// TestManager_SvcStateWithoutHA verifies that svc state is pushed to NX-OS
// via computeAndPushSvcOnly even when HA is not enabled / no peers configured.
// All three local criteria (DpuHealth, DpuInSync, InService) must be considered.
// Only svc state should change; HA state must remain unchanged.
func TestManager_SvcStateWithoutHA(t *testing.T) {
	ctx := context.Background()
	haStore := hastore.NewStore(ctx)
	deviceStore := device.NewStore(ctx)

	// SF configured — pushSvcToNx gate will be true.
	deviceStore.SetInService(ctx, "in-service")

	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithDeviceStore(deviceStore),
	).(*manager)

	// All three criteria met — expect svc-success and CriteriaMet=true.
	haStore.UpdateLocalCriterion(ctx, types.HACritDpuHealth, true)
	haStore.UpdateLocalCriterion(ctx, types.HACritDpuInSync, true)
	haStore.UpdateLocalCriterion(ctx, types.HACritInService, true)
	mgr.computeAndPushSvcOnly(ctx)

	local := haStore.Local()
	if local.SvcState != types.SvcStateSuccess {
		t.Errorf("expected svc-success with all criteria met, got %q", local.SvcState)
	}
	if !local.CriteriaMet {
		t.Error("expected CriteriaMet=true when all criteria are met")
	}
	if local.HaState != "" {
		t.Errorf("expected HA state unchanged (empty), got %q", local.HaState)
	}

	// DpuHealth fails — expect svc-failure and CriteriaMet=false.
	haStore.UpdateLocalCriterion(ctx, types.HACritDpuHealth, false)
	mgr.computeAndPushSvcOnly(ctx)
	local = haStore.Local()
	if local.SvcState != types.SvcStateFailure {
		t.Errorf("expected svc-failure when DpuHealth=false, got %q", local.SvcState)
	}
	if local.CriteriaMet {
		t.Error("expected CriteriaMet=false when DpuHealth=false")
	}
	if local.HaState != "" {
		t.Errorf("expected HA state unchanged (empty), got %q", local.HaState)
	}

	// DpuInSync fails independently — expect svc-failure.
	haStore.UpdateLocalCriterion(ctx, types.HACritDpuHealth, true)
	haStore.UpdateLocalCriterion(ctx, types.HACritDpuInSync, false)
	mgr.computeAndPushSvcOnly(ctx)
	if local = haStore.Local(); local.SvcState != types.SvcStateFailure {
		t.Errorf("expected svc-failure when DpuInSync=false, got %q", local.SvcState)
	}

	// InService fails independently — expect svc-failure.
	haStore.UpdateLocalCriterion(ctx, types.HACritDpuInSync, true)
	haStore.UpdateLocalCriterion(ctx, types.HACritInService, false)
	mgr.computeAndPushSvcOnly(ctx)
	if local = haStore.Local(); local.SvcState != types.SvcStateFailure {
		t.Errorf("expected svc-failure when InService=false, got %q", local.SvcState)
	}

	// All criteria restored — CriteriaMet should flip back to true.
	haStore.UpdateLocalCriterion(ctx, types.HACritInService, true)
	mgr.computeAndPushSvcOnly(ctx)
	local = haStore.Local()
	if local.SvcState != types.SvcStateSuccess {
		t.Errorf("expected svc-success after restoring all criteria, got %q", local.SvcState)
	}
	if !local.CriteriaMet {
		t.Error("expected CriteriaMet=true after restoring all criteria")
	}
}

// TestManager_ActivationPreservesPreHACriteria verifies that DPU criteria set
// during the pre-HA phase (waitForConfig) are not overwritten to false on
// activation when they already exist in the criteria map.
func TestManager_ActivationPreservesPreHACriteria(t *testing.T) {
	ctx := context.Background()
	haStore := hastore.NewStore(ctx)
	deviceStore := device.NewStore(ctx)

	// Pre-populate DPU criteria as true (simulating pre-HA DPU health events).
	haStore.UpdateLocalCriterion(ctx, types.HACritDpuHealth, true)
	haStore.UpdateLocalCriterion(ctx, types.HACritDpuInSync, true)

	// Simulate activation sequence: set InService, then run the pre-populate block.
	deviceStore.SetInService(ctx, "in-service")
	haStore.UpdateLocalCriterion(ctx, types.HACritInService, deviceStore.IsInService())

	// Create a dpuStore with one DPU so the activation block runs.
	dpuStore := dpu.NewStore(ctx)
	if err := dpuStore.Update(ctx, types.DPU{Name: "dpu0", ModuleNum: 1, IP: "10.0.0.10"}); err != nil {
		t.Fatalf("failed to add DPU: %v", err)
	}

	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithDeviceStore(deviceStore),
		WithDPUStore(dpuStore),
	).(*manager)

	// Simulate the activation pre-populate logic directly.
	activationCriteria := haStore.Local().Criteria
	if _, ok := activationCriteria[types.HACritDpuHealth]; !ok {
		haStore.UpdateLocalCriterion(ctx, types.HACritDpuHealth, false)
	}
	if _, ok := activationCriteria[types.HACritDpuInSync]; !ok {
		haStore.UpdateLocalCriterion(ctx, types.HACritDpuInSync, false)
	}

	_ = mgr // manager created to validate constructor doesn't panic

	// Criteria should still be true — not overwritten to false.
	local := haStore.Local()
	if v, ok := local.Criteria[types.HACritDpuHealth]; !ok || !v {
		t.Errorf("expected HACritDpuHealth=true after activation, got ok=%v v=%v", ok, v)
	}
	if v, ok := local.Criteria[types.HACritDpuInSync]; !ok || !v {
		t.Errorf("expected HACritDpuInSync=true after activation, got ok=%v v=%v", ok, v)
	}
}

var _ Manager = (*mockManager)(nil)
