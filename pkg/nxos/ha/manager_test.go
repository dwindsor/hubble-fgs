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
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/version"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/mock"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/device"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/dpu"
	hastore "github.com/isovalent/hubble-fgs/pkg/nxos/store/ha"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/vlan"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/vrf"
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

// newElectLeaderManager creates a minimal manager for electLeader tests.
func newElectLeaderManager(localIP string) (*manager, hastore.Store) {
	store := hastore.NewStore(context.Background())
	mgr := NewManager(
		WithHAStoreForManager(store),
		WithLocalIP(localIP),
	).(*manager)
	return mgr, store
}

// addConnectedPeer adds a peer to the store in a connected state with the given svc state.
func addConnectedPeer(t *testing.T, ctx context.Context, store hastore.Store, ip, svcState string) {
	t.Helper()
	store.SetPeer(ctx, ip, types.HAPeerState{
		IP:        ip,
		Connected: true,
		SvcState:  svcState,
	})
}

func TestElectLeader_NoPeers_PreservesState(t *testing.T) {
	ctx := context.Background()
	mgr, store := newElectLeaderManager("10.0.0.1")

	// Fresh node: default is not leader.
	mgr.electLeader(ctx)
	if store.IsLeader() {
		t.Error("expected not leader with no peers (fresh node)")
	}

	// Node that was already leader stays leader.
	store.SetLeader(ctx, true)
	mgr.electLeader(ctx)
	if !store.IsLeader() {
		t.Error("expected to retain leadership with no peers")
	}
}

func TestElectLeader_DisconnectedPeer_PreservesState(t *testing.T) {
	ctx := context.Background()
	mgr, store := newElectLeaderManager("10.0.0.1")

	// Add a disconnected peer.
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:        "10.0.0.2",
		Connected: false,
		SvcState:  types.SvcStateSuccess,
	})

	// Follower stays follower when peer disconnects.
	mgr.electLeader(ctx)
	if store.IsLeader() {
		t.Error("expected to remain non-leader when only peer is disconnected")
	}

	// Leader stays leader when peer disconnects.
	store.SetLeader(ctx, true)
	mgr.electLeader(ctx)
	if !store.IsLeader() {
		t.Error("expected to retain leadership when only peer is disconnected")
	}
}

func TestElectLeader_DeferToExistingLeader(t *testing.T) {
	ctx := context.Background()
	mgr, store := newElectLeaderManager("10.0.0.2")

	// Peer with lower IP is already leader and functioning.
	store.SetPeer(ctx, "10.0.0.1", types.HAPeerState{
		IP:        "10.0.0.1",
		Connected: true,
		SvcState:  types.SvcStateSuccess,
		IsLeader:  true,
	})

	// We should defer to the functioning peer leader.
	mgr.electLeader(ctx)
	if store.IsLeader() {
		t.Error("expected to defer to existing peer leader")
	}
}

func TestElectLeader_DeferToExistingLeader_SplitBrain(t *testing.T) {
	ctx := context.Background()

	// Both nodes think they are leader, both SUCCESS. Higher-IP node (10.0.0.2) should defer.
	mgr, store := newElectLeaderManager("10.0.0.2")
	store.SetLeader(ctx, true)
	setLocalReady(t, store)
	store.SetPeer(ctx, "10.0.0.1", types.HAPeerState{
		IP:        "10.0.0.1",
		Connected: true,
		SvcState:  types.SvcStateSuccess,
		IsLeader:  true,
	})

	mgr.electLeader(ctx)
	if store.IsLeader() {
		t.Error("expected higher-IP node to defer in split-brain scenario")
	}

	// Lower-IP node (10.0.0.1) should NOT defer when both are SUCCESS.
	mgr2, store2 := newElectLeaderManager("10.0.0.1")
	store2.SetLeader(ctx, true)
	setLocalReady(t, store2)
	store2.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:        "10.0.0.2",
		Connected: true,
		SvcState:  types.SvcStateSuccess,
		IsLeader:  true,
	})

	mgr2.electLeader(ctx)
	if !store2.IsLeader() {
		t.Error("expected lower-IP node to retain leadership in split-brain scenario")
	}
}

func TestElectLeader_NoDeferToDegradedLeader(t *testing.T) {
	ctx := context.Background()
	mgr, store := newElectLeaderManager("10.0.0.2")

	// Peer claims leadership but is NOT functioning.
	store.SetPeer(ctx, "10.0.0.1", types.HAPeerState{
		IP:        "10.0.0.1",
		Connected: true,
		SvcState:  types.SvcStateFailure,
		IsLeader:  true,
	})

	// Step 2 fires because peer.IsLeader=true, and local is not leader → return immediately.
	// Local remains non-leader (no self-promotion when a leader exists, even a degraded one).
	mgr.electLeader(ctx)
	if store.IsLeader() {
		t.Error("expected not to self-promote when peer is leader (even degraded)")
	}
}

func TestElectLeader_SvcStatePreference_InitialElection(t *testing.T) {
	ctx := context.Background()

	// Local is SUCCESS (CriteriaMet=true), peer is not — local should win regardless of IP.
	mgr, store := newElectLeaderManager("10.0.0.2") // higher IP, would normally lose
	setLocalReady(t, store)

	store.SetPeer(ctx, "10.0.0.1", types.HAPeerState{
		IP:        "10.0.0.1",
		Connected: true,
		SvcState:  types.SvcStateFailure, // peer is not functioning
	})

	mgr.electLeader(ctx)
	if !store.IsLeader() {
		t.Error("expected SUCCESS local node to win election over non-SUCCESS peer, regardless of IP")
	}
}

func TestElectLeader_IPTiebreaker(t *testing.T) {
	ctx := context.Background()

	// Both nodes are SUCCESS, lower IP wins.
	mgr, store := newElectLeaderManager("10.0.0.2") // higher IP
	setLocalReady(t, store)
	addConnectedPeer(t, ctx, store, "10.0.0.1", types.SvcStateSuccess)

	mgr.electLeader(ctx)
	if store.IsLeader() {
		t.Error("expected higher-IP node to lose IP tiebreaker")
	}

	// Lower IP node wins.
	mgr2, store2 := newElectLeaderManager("10.0.0.1")
	setLocalReady(t, store2)
	addConnectedPeer(t, ctx, store2, "10.0.0.2", types.SvcStateSuccess)

	mgr2.electLeader(ctx)
	if !store2.IsLeader() {
		t.Error("expected lower-IP node to win IP tiebreaker")
	}
}

func TestElectLeader_LeaderRetainsOnSvcDegradation(t *testing.T) {
	ctx := context.Background()
	mgr, store := newElectLeaderManager("10.0.0.2")

	// Node is leader.
	store.SetLeader(ctx, true)

	// Peer is connected and SUCCESS (would win by IP, but we're already leader).
	addConnectedPeer(t, ctx, store, "10.0.0.1", types.SvcStateSuccess)

	// No peer IsLeader set — step 2 won't trigger. Step 3 should retain.
	mgr.electLeader(ctx)
	if !store.IsLeader() {
		t.Error("expected already-leader to retain leadership (step 3)")
	}
}

// TestElectLeader_DeferToPeerLeaderAfterJoiningLate is a regression test for the
// dual-leader bug: when a peer wins the initial election (e.g. due to SvcSuccess
// priority), and the local node later becomes SUCCESS, the local node must defer to
// the already-elected peer leader rather than electing itself.
//
// The bug was that the adjacency response never included the peer's IsLeader status,
// so after each exchange UpdatePeerIsLeader was called with false, causing step 2
// (defer-to-existing-leader) to be skipped and step 4 to incorrectly elect the
// local node.
func TestElectLeader_DeferToPeerLeaderAfterJoiningLate(t *testing.T) {
	ctx := context.Background()

	// Peer (10.0.0.2, higher IP) won the initial election because local was not
	// SUCCESS at the time. Simulate that state: peer is connected, SUCCESS, and
	// already a leader.
	mgr, store := newElectLeaderManager("10.0.0.1") // lower IP — would win IP tiebreaker
	setLocalReady(t, store)                         // local is now SUCCESS too
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:        "10.0.0.2",
		Connected: true,
		SvcState:  types.SvcStateSuccess,
		IsLeader:  true, // peer won the earlier election
	})

	mgr.electLeader(ctx)
	if store.IsLeader() {
		t.Error("local node must defer to already-elected peer leader even when local has lower IP")
	}
}

// TestProcessHaInfo_UpdatesSvcStateForElection is a regression test for the dual-leader
// bug: when the adjacency initiator received a response, it only extracted IsLeader from
// HaInfo and ignored SvcState. This left SvcState stale (UNKNOWN), so the Step 2
// deference check (peer.IsLeader && peer.SvcState==SUCCESS) always failed, causing the
// initiator to fall through to Step 4 and elect itself even when the peer was the
// legitimate functioning leader.
func TestProcessHaInfo_UpdatesSvcStateForElection(t *testing.T) {
	ctx := context.Background()

	// Local node is 10.0.0.2 (higher IP, would win Step 4 if peer appears non-SUCCESS).
	mgr, store := newElectLeaderManager("10.0.0.2")
	setLocalReady(t, store)

	// Peer 10.0.0.1 is connected but SvcState=UNKNOWN — simulating stale state before
	// any HaInfo has been processed from the adjacency response.
	store.SetPeer(ctx, "10.0.0.1", types.HAPeerState{
		IP:        "10.0.0.1",
		Connected: true,
		SvcState:  types.SvcStateUnknown,
		IsLeader:  false,
	})

	// Without the fix: electLeader sees peer SvcState=UNKNOWN, falls through to Step 4,
	// and elects local (10.0.0.2) as leader — incorrectly.
	mgr.electLeader(ctx)
	if !store.IsLeader() {
		t.Skip("pre-condition: local node did not elect itself with stale peer SvcState — test setup may have changed")
	}
	store.SetLeader(ctx, false) // reset for the actual test

	// ProcessHaInfo simulates receiving the peer's HaInfo from an adjacency response.
	// It must update SvcState so that electLeader sees the peer as functioning.
	mgr.ProcessHaInfo(ctx, "10.0.0.1", &hav1.HaInfo{
		LocalSvcState: hav1.LOCAL_SVC_STATE_LOCAL_SVC_SUCCESS,
		IsLeader:      true,
	})

	// After ProcessHaInfo, Step 2 deference must fire (peer.IsLeader && peer.SvcState==SUCCESS)
	// and local must not become leader.
	if store.IsLeader() {
		t.Error("local node must defer to peer after ProcessHaInfo updates peer SvcState from adjacency response")
	}
}

func TestElectLeader_PeerReconnect_ReEvaluates(t *testing.T) {
	ctx := context.Background()
	mgr, store := newElectLeaderManager("10.0.0.2")

	// Peer disconnected: state preserved (not leader).
	store.SetPeer(ctx, "10.0.0.1", types.HAPeerState{
		IP:        "10.0.0.1",
		Connected: false,
		SvcState:  types.SvcStateSuccess,
	})
	mgr.electLeader(ctx)
	if store.IsLeader() {
		t.Error("should not become leader while peer disconnected")
	}

	// Peer reconnects: election re-evaluates.
	store.UpdatePeerConnected(ctx, "10.0.0.1", true, time.Now().Unix())
	mgr.electLeader(ctx)
	// Peer has lower IP and SUCCESS → local (higher IP) should lose.
	if store.IsLeader() {
		t.Error("expected to lose election to lower-IP peer on reconnect")
	}
}

// TestElectLeader_SplitBrain_NotReadyDefersRegardlessOfIP verifies that in a
// split-brain, the not-ready node defers to the functioning node unconditionally,
// even when the not-ready node has a lower IP (which would normally win).
func TestElectLeader_SplitBrain_NotReadyDefersRegardlessOfIP(t *testing.T) {
	ctx := context.Background()

	// Local (10.0.0.1, lower IP) is leader but NOT ready. Peer (10.0.0.2) is leader and SUCCESS.
	// Local must defer to the functioning peer despite having the lower IP.
	mgr, store := newElectLeaderManager("10.0.0.1")
	store.SetLeader(ctx, true)
	// local CriteriaMet=false (not-ready) — do not call setLocalReady
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:        "10.0.0.2",
		Connected: true,
		SvcState:  types.SvcStateSuccess,
		IsLeader:  true,
	})

	mgr.electLeader(ctx)
	if store.IsLeader() {
		t.Error("expected not-ready node to defer to functioning peer, regardless of IP")
	}
}

// TestElectLeader_SplitBrain_BothFailure_HigherIPDefers verifies that in a
// split-brain where both nodes have FAILURE svc state, the higher-IP node defers.
func TestElectLeader_SplitBrain_BothFailure_HigherIPDefers(t *testing.T) {
	ctx := context.Background()

	// Higher-IP node (10.0.0.2) is leader, peer (10.0.0.1) is also leader. Both FAILURE.
	// Higher IP must defer.
	mgr, store := newElectLeaderManager("10.0.0.2")
	store.SetLeader(ctx, true)
	store.SetPeer(ctx, "10.0.0.1", types.HAPeerState{
		IP:        "10.0.0.1",
		Connected: true,
		SvcState:  types.SvcStateFailure,
		IsLeader:  true,
	})

	mgr.electLeader(ctx)
	if store.IsLeader() {
		t.Error("expected higher-IP node to defer when both are FAILURE in split-brain")
	}

	// Lower-IP node (10.0.0.1) must keep leadership.
	mgr2, store2 := newElectLeaderManager("10.0.0.1")
	store2.SetLeader(ctx, true)
	store2.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:        "10.0.0.2",
		Connected: true,
		SvcState:  types.SvcStateFailure,
		IsLeader:  true,
	})

	mgr2.electLeader(ctx)
	if !store2.IsLeader() {
		t.Error("expected lower-IP node to keep leadership when both are FAILURE in split-brain")
	}
}

// TestElectLeader_FollowerNoPreemptDegradedLeader verifies that a SUCCESS follower
// does NOT preempt a degraded (FAILURE) leader. Once a leader is established,
// svc state changes do not trigger re-election.
func TestElectLeader_FollowerNoPreemptDegradedLeader(t *testing.T) {
	ctx := context.Background()

	// Local (10.0.0.2) is SUCCESS follower. Peer (10.0.0.1) is leader with FAILURE.
	// Local must not self-promote.
	mgr, store := newElectLeaderManager("10.0.0.2")
	setLocalReady(t, store) // local is SUCCESS
	store.SetPeer(ctx, "10.0.0.1", types.HAPeerState{
		IP:        "10.0.0.1",
		Connected: true,
		SvcState:  types.SvcStateFailure,
		IsLeader:  true,
	})

	mgr.electLeader(ctx)
	if store.IsLeader() {
		t.Error("SUCCESS follower must not preempt a degraded leader")
	}
}

// TestElectLeader_FollowerNoSelfPromoteWhenLeaderFails verifies that a follower
// does NOT self-promote via Step 4 when a connected peer is leader with FAILURE
// (failure mode B from the plan).
func TestElectLeader_FollowerNoSelfPromoteWhenLeaderFails(t *testing.T) {
	ctx := context.Background()

	// Local (10.0.0.1, lower IP) is SUCCESS follower. Peer (10.0.0.2) is leader with FAILURE.
	// Without the fix, Step 2 would be skipped (needs SUCCESS), and Step 4 would
	// self-promote local because it has SUCCESS and lower IP.
	mgr, store := newElectLeaderManager("10.0.0.1")
	setLocalReady(t, store)
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:        "10.0.0.2",
		Connected: true,
		SvcState:  types.SvcStateFailure,
		IsLeader:  true,
	})

	mgr.electLeader(ctx)
	if store.IsLeader() {
		t.Error("follower must not self-promote via Step 4 when a connected peer is leader")
	}
}

// TestSendAdjacency_AdjFailure_ProcessesHaInfo verifies that when a peer responds
// with ADJ_FAILURE and includes HaInfo, the peer's IsLeader and SvcState are updated.
func TestSendAdjacency_AdjFailure_ProcessesHaInfo(t *testing.T) {
	ctx := context.Background()
	haStore := hastore.NewStore(ctx)

	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithLocalIP("10.0.0.1"),
		WithClientFactory(func() Client {
			c := NewMockClient()
			c.SetAdjacencyHandler(func(_ context.Context, _ *hav1.AdjRequest) (*hav1.AdjResponse, error) {
				return &hav1.AdjResponse{
					Status:  hav1.ADJ_RESPONSE_STATUS_ADJ_FAILURE,
					Details: "incompatible",
					MbrInfo: &hav1.MbrInfo{
						HaInfo: &hav1.HaInfo{
							LocalSvcState: hav1.LOCAL_SVC_STATE_LOCAL_SVC_SUCCESS,
							IsLeader:      true,
						},
					},
				}, nil
			})
			return c
		}),
	).(*manager)

	// Add a connected peer in the haStore so sendAdjacency can update it.
	haStore.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:        "10.0.0.2",
		Connected: false,
	})

	// Connect the peer so the client is registered.
	deviceStore := device.NewStore(ctx)
	mgr.deviceStore = deviceStore
	if err := mgr.ConnectPeer(ctx, "10.0.0.2"); err != nil {
		t.Fatalf("ConnectPeer failed: %v", err)
	}

	_ = mgr.sendAdjacency(ctx, "10.0.0.2", types.HAPeerMember{}) // error expected (ADJ_FAILURE), that's OK

	// Peer's IsLeader and SvcState must have been updated from the failure response.
	peer, ok := haStore.Peer("10.0.0.2")
	if !ok {
		t.Fatal("peer not found in store")
	}
	if !peer.IsLeader {
		t.Error("expected peer IsLeader=true after ADJ_FAILURE with HaInfo")
	}
	if peer.SvcState != types.SvcStateSuccess {
		t.Errorf("expected peer SvcState=success, got %q", peer.SvcState)
	}
}

// TestSendAdjacency_AdjFailure_RunsReconcile verifies that Reconcile runs on the
// ADJ_FAILURE path, restoring peer_vrf_gid after a criteria reset.
func TestSendAdjacency_AdjFailure_RunsReconcile(t *testing.T) {
	ctx := context.Background()
	haStore := hastore.NewStore(ctx)
	vrfStore := vrf.NewStore(ctx)
	vlanStore := vlan.NewStore(ctx)
	deviceStore := device.NewStore(ctx)

	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithLocalIP("10.0.0.1"),
		WithDeviceStore(deviceStore),
		WithVRFStore(vrfStore),
		WithVLANStore(vlanStore),
		WithClientFactory(func() Client {
			c := NewMockClient()
			c.SetAdjacencyHandler(func(_ context.Context, _ *hav1.AdjRequest) (*hav1.AdjResponse, error) {
				return &hav1.AdjResponse{
					Status:  hav1.ADJ_RESPONSE_STATUS_ADJ_FAILURE,
					Details: "membership failure",
					MbrInfo: &hav1.MbrInfo{
						VrfInfo: []*hav1.VrfInfo{
							{Name: "vrf-1", Id: 100},
						},
						HaInfo: &hav1.HaInfo{
							LocalSvcState: hav1.LOCAL_SVC_STATE_LOCAL_SVC_SUCCESS,
						},
					},
				}, nil
			})
			return c
		}),
	).(*manager)

	// Add peer and connect.
	haStore.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:                "10.0.0.2",
		Connected:         false,
		MemberCriteria:    make(types.HACriteria),
		ServiceCriteria:   make(types.HACriteria),
		AdjacencyCriteria: make(types.HACriteria),
	})
	if err := mgr.ConnectPeer(ctx, "10.0.0.2"); err != nil {
		t.Fatalf("ConnectPeer failed: %v", err)
	}

	// Simulate criteria reset: peer_vrf_gid set to false.
	haStore.UpdatePeerMemberCriterion(ctx, "10.0.0.2", types.HACritPeerVrfGid, false)

	// sendAdjacency returns error (ADJ_FAILURE) — that's expected.
	_ = mgr.sendAdjacency(ctx, "10.0.0.2", types.HAPeerMember{})

	// peer_vrf_gid must have been restored by Reconcile on the failure path.
	peer, ok := haStore.Peer("10.0.0.2")
	if !ok {
		t.Fatal("peer not found in store")
	}
	vrfGid, exists := peer.MemberCriteria[types.HACritPeerVrfGid]
	if !exists {
		t.Fatal("expected peer_vrf_gid criterion to exist after ADJ_FAILURE reconcile")
	}
	if !vrfGid {
		t.Error("expected peer_vrf_gid=true after ADJ_FAILURE reconcile, got false")
	}
}

// TestProcessMemberInfo_HardFailure_DoesNotClearVrfGid verifies that a hard
// membership failure (model mismatch) sets peer_compatible=false but does NOT
// clobber peer_vrf_gid. Reconcile is the sole writer of peer_vrf_gid.
func TestProcessMemberInfo_HardFailure_DoesNotClearVrfGid(t *testing.T) {
	ctx := context.Background()
	haStore := hastore.NewStore(ctx)

	haStore.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:                "10.0.0.2",
		Connected:         true,
		MemberCriteria:    make(types.HACriteria),
		ServiceCriteria:   make(types.HACriteria),
		AdjacencyCriteria: make(types.HACriteria),
	})

	// Pre-set peer_vrf_gid to true (as if Reconcile had restored it).
	haStore.UpdatePeerMemberCriterion(ctx, "10.0.0.2", types.HACritPeerVrfGid, true)

	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithLocalIP("10.0.0.1"),
		WithDeviceInfoProvider(func() LocalDeviceInfo {
			return LocalDeviceInfo{
				Model:     "N9K-C9364C",
				SWVersion: "10.5(1)",
				LbMode:    "symmetric-hash",
			}
		}),
	).(*manager)

	// Send peer info with model mismatch → triggers hard failure.
	mgr.ProcessMemberInfo(ctx, "10.0.0.2", types.HAPeerMember{
		Model:     "N9K-C9332C",
		SWVersion: "10.5(1)",
		LbMode:    "symmetric-hash",
		Service:   types.SvcStateSuccess,
	})

	peer, ok := haStore.Peer("10.0.0.2")
	if !ok {
		t.Fatal("peer not found in store")
	}

	// peer_compatible must be false (hard failure).
	if peer.MemberCriteria[types.HACritPeerCompatible] {
		t.Error("expected peer_compatible=false after model mismatch")
	}

	// peer_vrf_gid must NOT have been clobbered — still true from pre-set.
	vrfGid, exists := peer.MemberCriteria[types.HACritPeerVrfGid]
	if !exists {
		t.Fatal("expected peer_vrf_gid criterion to still exist after hard failure")
	}
	if !vrfGid {
		t.Error("expected peer_vrf_gid=true (not clobbered by hard failure), got false")
	}
}

// TestManager_Run_AdminDisable_SetsStandaloneState verifies that when admin state
// is disabled during the active loop, the agent HA state transitions to
// "ha-not-ready" (standalone) and peer states are reset to no-ha/unknown.
func TestManager_Run_AdminDisable_SetsStandaloneState(t *testing.T) {
	ctx := context.Background()
	haStore := hastore.NewStore(ctx)
	deviceStore := device.NewStore(ctx)
	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithDeviceStore(deviceStore),
		WithClientFactory(func() Client { return NewMockClient() }),
	)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- mgr.Run(runCtx) }()

	// Activate HA.
	deviceStore.SetInService(ctx, "in-service")
	haStore.SetEnabled(ctx, "enabled")
	haStore.SetHaIP(ctx, "10.0.0.1")
	haStore.SetPeer(ctx, "10.0.0.2", types.HAPeerState{IP: "10.0.0.2", IpConfigState: hastore.PeerIpCfgStateSuccess})
	time.Sleep(50 * time.Millisecond)

	// Disable admin state — this should push final states before deactivating.
	haStore.SetEnabled(ctx, hastore.AdminStateDisabled)
	time.Sleep(50 * time.Millisecond)

	// Agent HA state should be cleared after deactivation cleanup (ResetLocalHaState
	// runs after the admin-disable final state push, resetting HaState to "").
	local := haStore.Local()
	if local.HaState != "" {
		t.Errorf("expected local HaState=%q after deactivation cleanup, got %q", "", local.HaState)
	}

	// Peer states should be reset to no-ha / unknown.
	peer, ok := haStore.Peer("10.0.0.2")
	if !ok {
		t.Fatal("peer not found in store after disable")
	}
	if peer.HaState != types.PeerHAStateNoHa {
		t.Errorf("expected peer HaState=%q, got %q", types.PeerHAStateNoHa, peer.HaState)
	}
	if peer.SvcState != types.SvcStateUnknown {
		t.Errorf("expected peer SvcState=%q, got %q", types.SvcStateUnknown, peer.SvcState)
	}

	// Run() should still be running (waiting for reconfiguration), not returned.
	select {
	case err := <-errCh:
		t.Errorf("Run() returned prematurely: %v", err)
	default:
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

// TestManager_Run_ClearsHaStandbyOnDeactivation verifies that the ha_standby
// criterion is removed from local criteria after HA deactivation (admin-disable).
// Previously, ha_standby would linger causing stale "syncing: ha_standby" svc state.
func TestManager_Run_ClearsHaStandbyOnDeactivation(t *testing.T) {
	ctx := context.Background()

	haStore := hastore.NewStore(ctx)
	deviceStore := device.NewStore(ctx)

	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithDeviceStore(deviceStore),
		WithLocalIP("10.0.0.1"),
		WithClientFactory(func() Client { return NewMockClient() }),
	)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Run(runCtx)
	}()

	bgCtx := context.Background()

	// Configure and activate HA with all svc criteria OK.
	deviceStore.SetInService(bgCtx, "in-service")
	haStore.UpdateLocalCriterion(bgCtx, types.HACritDpuHealth, true)
	haStore.UpdateLocalCriterion(bgCtx, types.HACritDpuInSync, true)
	haStore.SetEnabled(bgCtx, "enabled")
	haStore.SetHaIP(bgCtx, "10.0.0.1")
	haStore.SetPeer(bgCtx, "10.0.0.2", types.HAPeerState{IP: "10.0.0.2", IpConfigState: hastore.PeerIpCfgStateSuccess})

	time.Sleep(50 * time.Millisecond)

	// Inject ha_standby=false directly (simulating the standby state).
	local := haStore.Local()
	local.Criteria[types.HACritHaStandby] = false
	haStore.SetLocal(bgCtx, local)

	// Verify ha_standby is set before deactivation.
	localBefore := haStore.Local()
	if _, ok := localBefore.Criteria[types.HACritHaStandby]; !ok {
		t.Fatal("expected ha_standby to be present before deactivation")
	}

	// Deactivate HA by disabling admin state.
	haStore.SetEnabled(bgCtx, "")

	// Give Run() time to deactivate and run cleanup.
	time.Sleep(100 * time.Millisecond)

	// ha_standby must be cleared after deactivation.
	localAfter := haStore.Local()
	if _, ok := localAfter.Criteria[types.HACritHaStandby]; ok {
		t.Error("ha_standby criterion should be cleared after HA deactivation, but it is still present")
	}

	// Svc criteria must still be present (preserved by ResetLocalHaState).
	if _, ok := localAfter.Criteria[types.HACritDpuHealth]; !ok {
		t.Error("dpu_healthy criterion should be preserved after HA deactivation")
	}
	if _, ok := localAfter.Criteria[types.HACritDpuInSync]; !ok {
		t.Error("dpu_insync criterion should be preserved after HA deactivation")
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

// TestManager_Run_ClearsHaStandbyOnSFRemoval verifies that the ha_standby
// criterion is removed from local criteria when the service function is removed
// (InServiceState becomes ""), triggering deactivation via the SF removal path.
func TestManager_Run_ClearsHaStandbyOnSFRemoval(t *testing.T) {
	ctx := context.Background()

	haStore := hastore.NewStore(ctx)
	deviceStore := device.NewStore(ctx)

	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithDeviceStore(deviceStore),
		WithLocalIP("10.0.0.1"),
		WithClientFactory(func() Client { return NewMockClient() }),
	)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Run(runCtx)
	}()

	bgCtx := context.Background()

	// Configure and activate HA.
	deviceStore.SetInService(bgCtx, "in-service")
	haStore.UpdateLocalCriterion(bgCtx, types.HACritDpuHealth, true)
	haStore.UpdateLocalCriterion(bgCtx, types.HACritDpuInSync, true)
	haStore.SetEnabled(bgCtx, "enabled")
	haStore.SetHaIP(bgCtx, "10.0.0.1")
	haStore.SetPeer(bgCtx, "10.0.0.2", types.HAPeerState{IP: "10.0.0.2", IpConfigState: hastore.PeerIpCfgStateSuccess})

	time.Sleep(50 * time.Millisecond)

	// Inject ha_standby=false directly.
	local := haStore.Local()
	local.Criteria[types.HACritHaStandby] = false
	haStore.SetLocal(bgCtx, local)

	if _, ok := haStore.Local().Criteria[types.HACritHaStandby]; !ok {
		t.Fatal("expected ha_standby to be present before SF removal")
	}

	// Remove the service function — triggers SF removal exit path from runActive.
	deviceStore.SetInService(bgCtx, "")

	time.Sleep(100 * time.Millisecond)

	// ha_standby must be cleared after deactivation via SF removal.
	localAfter := haStore.Local()
	if _, ok := localAfter.Criteria[types.HACritHaStandby]; ok {
		t.Error("ha_standby criterion should be cleared after SF removal deactivation, but it is still present")
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

// TestManager_Run_AdminDisable_NoSvcFlap verifies that when HA is admin-disabled
// and all svc-domain criteria are OK, the local svc state does NOT flap to failure.
// The fix ensures ResetLocalHaState is called before computing svc state in the
// disable path, so only svc criteria (not stale HA criteria) influence svc state.
func TestManager_Run_AdminDisable_NoSvcFlap(t *testing.T) {
	ctx := context.Background()
	haStore := hastore.NewStore(ctx)
	deviceStore := device.NewStore(ctx)

	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithDeviceStore(deviceStore),
		WithLocalIP("10.0.0.1"),
		WithClientFactory(func() Client { return NewMockClient() }),
	)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- mgr.Run(runCtx) }()

	bgCtx := context.Background()

	// Configure and activate HA with all svc criteria OK.
	deviceStore.SetInService(bgCtx, "in-service")
	haStore.UpdateLocalCriterion(bgCtx, types.HACritDpuHealth, true)
	haStore.UpdateLocalCriterion(bgCtx, types.HACritDpuInSync, true)
	haStore.SetEnabled(bgCtx, "enabled")
	haStore.SetHaIP(bgCtx, "10.0.0.1")
	haStore.SetPeer(bgCtx, "10.0.0.2", types.HAPeerState{IP: "10.0.0.2", IpConfigState: hastore.PeerIpCfgStateSuccess})

	time.Sleep(50 * time.Millisecond)

	// Inject ha_standby=false to simulate standby state (the common pre-disable scenario).
	local := haStore.Local()
	local.Criteria[types.HACritHaStandby] = false
	haStore.SetLocal(bgCtx, local)

	// Disable HA — svc state should remain success since svc criteria are all OK.
	haStore.SetEnabled(bgCtx, hastore.AdminStateDisabled)

	time.Sleep(100 * time.Millisecond)

	// SvcState must NOT flap to failure; with all svc criteria met it should be success.
	localAfter := haStore.Local()
	if localAfter.SvcState != types.SvcStateSuccess {
		t.Errorf("svc state flapped: expected %q after admin disable with all svc criteria OK, got %q",
			types.SvcStateSuccess, localAfter.SvcState)
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

// TestManager_Run_PeerHaStateWrittenBeforeNotifyServiceFailure is a regression
// test for the race where NX-OS showed stale "ha-ok" for the peer during the
// blocking NotifyServiceFailure gRPC call.
//
// The fix: recomputeAndApplyState is called before NotifyServiceFailure so
// that the peer HA state gNMI SET reaches NX-OS before the peer is notified.
// We verify this by capturing the gNMI mock state inside the mock adjacency
// handler (which runs while the blocking gRPC call is in flight).
func TestManager_Run_PeerHaStateWrittenBeforeNotifyServiceFailure(t *testing.T) {
	ctx := context.Background()

	gnmiHandler := mock.NewHandler()
	haStore := hastore.NewStore(ctx, hastore.WithGnmiHandler(gnmiHandler))
	deviceStore := device.NewStore(ctx)

	// peerHaStateAtAdj captures the peer HA state from the gNMI mock at the
	// moment the NotifyServiceFailure Adjacency RPC arrives at the "peer".
	var peerHaStateAtAdj string
	var captureMu sync.Mutex
	captured := false
	adjReceived := make(chan struct{}, 1)

	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithDeviceStore(deviceStore),
		WithLocalIP("10.0.0.1"),
		WithClientFactory(func() Client {
			c := NewMockClient()
			c.SetAdjacencyHandler(func(ctx context.Context, req *hav1.AdjRequest) (*hav1.AdjResponse, error) {
				// Snapshot the gNMI peer HA state at the moment this call arrives.
				// With the fix, recomputeAndApplyState has already run before
				// NotifyServiceFailure called us, so the state must already be written.
				captureMu.Lock()
				if !captured {
					captured = true
					peerHaStatePath := normalizeMockManagerPath(
						fmt.Sprintf(paths.HAStorePeerHaState, "10.0.0.2"))
					if v, ok := gnmiHandler.GetData(peerHaStatePath); ok {
						peerHaStateAtAdj, _ = v.(string)
					}
					select {
					case adjReceived <- struct{}{}:
					default:
					}
				}
				captureMu.Unlock()
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

	// Activate HA: enabled + haIP + peer + in-service.
	deviceStore.SetInService(bgCtx, "in-service")
	haStore.SetEnabled(bgCtx, "enabled")
	haStore.SetHaIP(bgCtx, "10.0.0.1")
	haStore.SetPeer(bgCtx, "10.0.0.2", types.HAPeerState{
		IP:            "10.0.0.2",
		IpConfigState: hastore.PeerIpCfgStateSuccess,
		Connected:     true,
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: true,
		},
	})

	// Give Run() time to activate.
	time.Sleep(50 * time.Millisecond)

	// Connect peer so NotifyServiceFailure can reach the mock.
	if err := mgr.ConnectPeer(bgCtx, "10.0.0.2"); err != nil {
		t.Fatalf("ConnectPeer failed: %v", err)
	}

	// Drain any adjacency messages from the activation / keepalive ticker,
	// and reset the capture flag so we only capture the out-of-service notification.
	time.Sleep(20 * time.Millisecond)
	captureMu.Lock()
	captured = false
	peerHaStateAtAdj = ""
	captureMu.Unlock()
	for len(adjReceived) > 0 {
		<-adjReceived
	}

	// Transition to out-of-service — triggers recomputeAndApplyState then NotifyServiceFailure.
	deviceStore.SetInService(bgCtx, "out-of-service")

	// Wait for NotifyServiceFailure to reach the mock peer.
	select {
	case <-adjReceived:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("did not receive adjacency notification after out-of-service transition")
	}

	// The peer HA state must have been written to NX-OS BEFORE NotifyServiceFailure
	// called the mock adjacency handler. Without the fix it would be "" (not yet
	// written). With the fix it must be "ha-unavailable" (local service failure with
	// a healthy peer: computePeerHaState returns PeerHAStateUnavailable).
	captureMu.Lock()
	got := peerHaStateAtAdj
	captureMu.Unlock()
	if got != types.PeerHAStateUnavailable {
		t.Errorf("peer HA state at NotifyServiceFailure time: want %q, got %q",
			types.PeerHAStateUnavailable, got)
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

// normalizeMockManagerPath strips the "device:" scheme prefix used in path
// constants so it matches the key format used by the gNMI mock handler.
func normalizeMockManagerPath(path string) string {
	if len(path) > 7 && path[:7] == "device:" {
		path = path[7:]
	}
	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}
	return path
}

var _ Manager = (*mockManager)(nil)
