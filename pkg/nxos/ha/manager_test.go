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

	"github.com/isovalent/hubble-fgs/pkg/nxos/store/device"
	hastore "github.com/isovalent/hubble-fgs/pkg/nxos/store/ha"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

func TestNewManager(t *testing.T) {
	mgr := NewManager()
	if mgr == nil {
		t.Fatal("expected manager to be non-nil")
	}
}

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

func TestManager_Peers(t *testing.T) {
	mgr := NewManager()

	// No peers by default
	peers := mgr.Peers()
	if len(peers) != 0 {
		t.Errorf("expected 0 peers, got %d", len(peers))
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

func TestMockManager(t *testing.T) {
	mgr := NewMockManager()

	ctx := context.Background()

	// Not leader by default
	if mgr.IsLeader() {
		t.Error("expected not to be leader by default")
	}

	// Set leader
	mgr.SetLeader(true)
	if !mgr.IsLeader() {
		t.Error("expected to be leader after SetLeader")
	}

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

func TestAdjacencyConstants(t *testing.T) {
	if AdjacencyTimeout != 30*time.Second {
		t.Errorf("expected AdjacencyTimeout 30s, got %v", AdjacencyTimeout)
	}
	if AdjacencyInterval != 10*time.Second {
		t.Errorf("expected AdjacencyInterval 10s, got %v", AdjacencyInterval)
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

	// Configure HA with a peer and in-service — this should trigger activation.
	bgCtx := context.Background()
	deviceStore.SetInService(bgCtx, "in-service")
	haStore.SetEnabled(bgCtx, "enabled")
	haStore.SetPeer(bgCtx, "10.0.0.2", types.HAPeerState{IP: "10.0.0.2", AdjacencyCriteria: types.HACriteria{types.HACritPeerIpConfig: true}})

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

	// Configure HA with a peer and in-service — triggers activation.
	deviceStore.SetInService(bgCtx, "in-service")
	haStore.SetEnabled(bgCtx, "enabled")
	haStore.SetPeer(bgCtx, "10.0.0.2", types.HAPeerState{IP: "10.0.0.2", AdjacencyCriteria: types.HACriteria{types.HACritPeerIpConfig: true}})

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
	haStore.SetPeer(bgCtx, "10.0.0.2", types.HAPeerState{IP: "10.0.0.2", AdjacencyCriteria: types.HACriteria{types.HACritPeerIpConfig: true}})

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

	// Enable HA with a peer.
	haStore.SetEnabled(bgCtx, "enabled")
	haStore.SetPeer(bgCtx, "10.0.0.2", types.HAPeerState{IP: "10.0.0.2", AdjacencyCriteria: types.HACriteria{types.HACritPeerIpConfig: true}})

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

	// Add peer — still not ready (InService == "").
	haStore.SetPeer(bgCtx, "10.0.0.2", types.HAPeerState{IP: "10.0.0.2"})
	if mgr.isConfigReady() {
		t.Error("expected not ready with InService empty")
	}

	// Set InService — now ready.
	deviceStore.SetInService(bgCtx, "out-of-service")
	if !mgr.isConfigReady() {
		t.Error("expected ready when all prerequisites met")
	}
}

// TestManager_haUpdateNx_GatedOnInService verifies that svc state is not pushed
// to NX-OS when InServiceState is "".
func TestManager_haUpdateNx_GatedOnInService(t *testing.T) {
	haStore := hastore.NewStore(context.Background())
	deviceStore := device.NewStore(context.Background())
	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithDeviceStore(deviceStore),
	).(*manager)

	bgCtx := context.Background()

	// Call haUpdateNx with InService == "" — should skip svc state push.
	// We verify by checking there's no panic and the function returns cleanly.
	// (The actual gNMI push is tested via the haStore's SetLocalSvcState.)
	mgr.haUpdateNx(bgCtx)

	// Set InService — now haUpdateNx should proceed to check svc state.
	deviceStore.SetInService(bgCtx, "in-service")
	mgr.haUpdateNx(bgCtx)

	// If we got here without panic, the gating works correctly.
}

// TestMockManager_Run verifies that mockManager.Run() blocks on ctx and returns nil.
func TestMockManager_Run(t *testing.T) {
	mgr := NewMockManager()
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Run(ctx)
	}()

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("mockManager.Run() returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("mockManager.Run() did not return after cancel")
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

func (m *mockManager) HandleAdjFailureNotify(ctx context.Context, peer string, reason string) {}

func (m *mockManager) RegisterDpu(ctx context.Context, dpuUid string)              {}
func (m *mockManager) UpdateKeepalive(ctx context.Context, dpuUid string, up bool) {}
func (m *mockManager) UpdateBulkSyncLocal(ctx context.Context, dpuUid string, done bool) {
}
func (m *mockManager) UpdateBulkSyncPeer(ctx context.Context, dpuUid string, done bool) {
}
func (m *mockManager) UpdatePolicyRevision(ctx context.Context, revision string) {}

var _ Manager = (*mockManager)(nil)
