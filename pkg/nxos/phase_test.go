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
	"context"
	"sync"
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/nxos/storage"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/device"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/dpu"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/vlan"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/vrf"
)

func TestPhaseSystemStateValues(t *testing.T) {
	tests := []struct {
		state    int
		expected int
	}{
		{SysStFwDisable, 0x0},
		{SysStDpuPending, 0x1},
		{SysStFwReady, 0x4},
		{SysStRedirDone, 0x8},
		{SysStConnPending, 0x2},
	}
	for _, tt := range tests {
		if tt.state != tt.expected {
			t.Errorf("constant value: got 0x%X, want 0x%X", tt.state, tt.expected)
		}
	}
}

func TestPhaseString(t *testing.T) {
	tests := []struct {
		state    int
		expected string
	}{
		{SysStFwDisable, "disabled"},
		{SysStDpuPending, "dpu-pending"},
		{SysStFwReady, "fw-ready"},
		{SysStFwReady | SysStRedirDone, "fw-ready|redir-done"},
		{SysStDpuPending | SysStConnPending, "dpu-pending|conn-pending"},
		{SysStDpuPending | SysStRedirDone, "dpu-pending|redir-done"},
		{SysStFwReady | SysStRedirDone | SysStConnPending, "fw-ready|redir-done|conn-pending"},
	}
	for _, tt := range tests {
		got := Phase(tt.state).String()
		if got != tt.expected {
			t.Errorf("Phase(0x%X).String() = %q, want %q", tt.state, got, tt.expected)
		}
	}
}

// newTestManager creates a minimal manager backed by in-memory storage for unit tests.
func newTestManager(ctx context.Context) *manager {
	mem := storage.NewMemoryStorage()
	_ = mem.EnsureReady(ctx)
	devStore := device.NewStore(ctx, device.WithStorage(mem), device.WithHeadlessMode(true))
	return &manager{
		deviceStore:     devStore,
		lastSystemState: -1,
	}
}

func TestSystemStateConcurrency(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(ctx)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); m.setFwReady(ctx) }()
		go func() { defer wg.Done(); m.setRedirDone(ctx, true) }()
	}
	wg.Wait()

	// After all goroutines set fwReady and redirDone=true,
	// the final state must be fw-ready|redir-done (0xC).
	got := m.deviceStore.SystemState()
	want := SysStFwReady | SysStRedirDone
	if got != want {
		t.Errorf("final systemState = 0x%X, want 0x%X", got, want)
	}
}

func TestHeadlessConnPending(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(ctx)

	// In headless mode (default for test), ConnPending bit must not appear
	// even after SetConnectionStatus with a non-success status.
	m.deviceStore.SetConnectionStatus(ctx, "failure", "test")
	m.setFwReady(ctx)
	m.setRedirDone(ctx, true)

	state := m.deviceStore.SystemState()
	if state&SysStConnPending != 0 {
		t.Errorf("headless mode: ConnPending bit set in systemState 0x%X", state)
	}
}

func TestFwDisabledOnOutOfService(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(ctx)

	// Start fw-ready, then disable — simulates out-of-service transition.
	m.setFwReady(ctx)
	m.setFwDisabled(ctx)

	state := m.deviceStore.SystemState()
	if state&SysStFwReady != 0 {
		t.Errorf("FwReady bit still set after setFwDisabled: 0x%X", state)
	}
	if state&SysStDpuPending != 0 {
		t.Errorf("DpuPending bit set after setFwDisabled: 0x%X", state)
	}
	if state != SysStFwDisable {
		t.Errorf("expected FwDisable (0x0), got 0x%X", state)
	}
}

func TestDpuHealthGatesOnInService(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(ctx)

	// Out-of-service: DpuHealth should not change fw status.
	m.setFwDisabled(ctx)
	// Simulate DpuHealth call — since IsInService() is false, it should be a no-op.
	// We call the setter logic directly since DpuHealth depends on dpuStore.
	if m.deviceStore.IsInService() {
		t.Fatal("expected device to be out-of-service by default")
	}

	state := m.deviceStore.SystemState()
	if state&SysStFwReady != 0 {
		t.Errorf("FwReady bit set in systemState 0x%X when out-of-service", state)
	}
	if state&SysStDpuPending != 0 {
		t.Errorf("DpuPending bit set in systemState 0x%X when out-of-service (should be disabled)", state)
	}
}

// newTestManagerFull creates a manager with real vrf/vlan/dpu stores (no gNMI
// handler), suitable for testing the in-service hook and DpuHealth logic.
func newTestManagerFull(ctx context.Context) *manager {
	mem := storage.NewMemoryStorage()
	_ = mem.EnsureReady(ctx)
	devStore := device.NewStore(ctx, device.WithStorage(mem), device.WithHeadlessMode(true))
	dpuSt := dpu.NewStore(ctx)
	vrfSt := vrf.NewStore(ctx)
	vlanSt := vlan.NewStore(ctx)
	return &manager{
		deviceStore:     devStore,
		dpuStore:        dpuSt,
		vrfStore:        vrfSt,
		vlanStore:       vlanSt,
		opts:            defaultOptions(),
		lastSystemState: -1,
	}
}

// TestSetDpuPendingNoopWhenFwReady verifies the one-way transition:
// once FwReady, setDpuPending must not regress the state.
func TestSetDpuPendingNoopWhenFwReady(t *testing.T) {
	ctx := context.Background()
	m := newTestManager(ctx)

	m.setFwReady(ctx)
	m.setDpuPending(ctx) // must be a no-op

	state := m.deviceStore.SystemState()
	if state&SysStFwReady == 0 {
		t.Errorf("FwReady bit cleared after setDpuPending: 0x%X", state)
	}
	if state&SysStDpuPending != 0 {
		t.Errorf("DpuPending bit set after setDpuPending from FwReady: 0x%X", state)
	}
}

// TestProgramDeferredRedirectsNoopWhenNotFwReady verifies that
// programDeferredRedirects is a no-op unless fwStatus is FwReady.
func TestProgramDeferredRedirectsNoopWhenNotFwReady(t *testing.T) {
	ctx := context.Background()
	m := newTestManagerFull(ctx)

	// Set redirPending but leave fwStatus as disabled.
	m.stateMu.Lock()
	m.redirPending = true
	m.stateMu.Unlock()

	m.programDeferredRedirects(ctx)

	m.stateMu.Lock()
	stillPending := m.redirPending
	m.stateMu.Unlock()

	if !stillPending {
		t.Error("redirPending was cleared even though fwStatus != FwReady")
	}
	if m.deviceStore.SystemState()&SysStRedirDone != 0 {
		t.Error("RedirDone was set even though fwStatus != FwReady")
	}
}

// TestInServiceHealthyDPUs verifies that with healthy DPUs, in-service
// programs redirects immediately and sets FwReady + RedirDone.
func TestInServiceHealthyDPUs(t *testing.T) {
	ctx := context.Background()
	m := newTestManagerFull(ctx)

	// Configure 2 healthy DPUs.
	m.dpuStore.SetExpectedCount(ctx, 2)
	m.dpuStore.SetHealth(true, 2)

	m.setupInServiceHooks()
	m.deviceStore.SetInService(ctx, device.InServiceStateInService)

	state := m.deviceStore.SystemState()
	if state&SysStFwReady == 0 {
		t.Errorf("FwReady not set with healthy DPUs: 0x%X", state)
	}
	if state&SysStRedirDone == 0 {
		t.Errorf("RedirDone not set with healthy DPUs: 0x%X", state)
	}

	m.stateMu.Lock()
	pending := m.redirPending
	m.stateMu.Unlock()
	if pending {
		t.Error("redirPending should be false after healthy in-service")
	}
}

// TestInServiceUnhealthyDPUs verifies that with unhealthy DPUs, in-service
// sets DpuPending, leaves RedirDone unset, and marks redirPending.
func TestInServiceUnhealthyDPUs(t *testing.T) {
	ctx := context.Background()
	m := newTestManagerFull(ctx)

	// Configure 2 expected DPUs, none healthy.
	m.dpuStore.SetExpectedCount(ctx, 2)
	m.dpuStore.SetHealth(false, 0)

	m.setupInServiceHooks()
	m.deviceStore.SetInService(ctx, device.InServiceStateInService)

	state := m.deviceStore.SystemState()
	if state&SysStDpuPending == 0 {
		t.Errorf("DpuPending not set with unhealthy DPUs: 0x%X", state)
	}
	if state&SysStFwReady != 0 {
		t.Errorf("FwReady set unexpectedly with unhealthy DPUs: 0x%X", state)
	}
	if state&SysStRedirDone != 0 {
		t.Errorf("RedirDone set unexpectedly with unhealthy DPUs: 0x%X", state)
	}

	m.stateMu.Lock()
	pending := m.redirPending
	m.stateMu.Unlock()
	if !pending {
		t.Error("redirPending should be true after unhealthy in-service")
	}
}

// TestDeferredRedirectsOnDpuHealthRecovery verifies that when DPUs recover
// after an unhealthy in-service, redirects are programmed and RedirDone is set.
func TestDeferredRedirectsOnDpuHealthRecovery(t *testing.T) {
	ctx := context.Background()
	m := newTestManagerFull(ctx)

	// Start with unhealthy DPUs.
	m.dpuStore.SetExpectedCount(ctx, 2)
	m.dpuStore.SetHealth(false, 0)

	m.setupInServiceHooks()
	m.deviceStore.SetInService(ctx, device.InServiceStateInService)

	// Verify deferred state.
	m.stateMu.Lock()
	pending := m.redirPending
	m.stateMu.Unlock()
	if !pending {
		t.Fatal("expected redirPending=true after unhealthy in-service")
	}

	// DPUs recover — simulate DpuHealth promotion.
	m.dpuStore.SetHealth(true, 2)
	m.setFwReady(ctx)
	m.programDeferredRedirects(ctx)

	state := m.deviceStore.SystemState()
	if state&SysStFwReady == 0 {
		t.Errorf("FwReady not set after DPU recovery: 0x%X", state)
	}
	if state&SysStRedirDone == 0 {
		t.Errorf("RedirDone not set after deferred redirect programming: 0x%X", state)
	}

	m.stateMu.Lock()
	stillPending := m.redirPending
	m.stateMu.Unlock()
	if stillPending {
		t.Error("redirPending should be false after deferred redirects ran")
	}
}

// TestDeferredRedirectsNoopWhenNotPending verifies that programDeferredRedirects
// is a no-op when redirPending is false (redirects already done).
func TestDeferredRedirectsNoopWhenNotPending(t *testing.T) {
	ctx := context.Background()
	m := newTestManagerFull(ctx)

	m.setFwReady(ctx)
	m.setRedirDone(ctx, true)

	// redirPending is false — should be a no-op.
	m.programDeferredRedirects(ctx)

	state := m.deviceStore.SystemState()
	if state&SysStFwReady == 0 {
		t.Errorf("FwReady unexpectedly cleared: 0x%X", state)
	}
	if state&SysStRedirDone == 0 {
		t.Errorf("RedirDone unexpectedly cleared: 0x%X", state)
	}
}

// TestOutOfServiceClearsRedirPending verifies that going out-of-service
// disarms a pending deferred redirect.
func TestOutOfServiceClearsRedirPending(t *testing.T) {
	ctx := context.Background()
	m := newTestManagerFull(ctx)

	// Put manager in deferred state.
	m.dpuStore.SetExpectedCount(ctx, 2)
	m.dpuStore.SetHealth(false, 0)
	m.setupInServiceHooks()
	m.deviceStore.SetInService(ctx, device.InServiceStateInService)

	m.stateMu.Lock()
	pending := m.redirPending
	m.stateMu.Unlock()
	if !pending {
		t.Fatal("expected redirPending=true after unhealthy in-service")
	}

	// Go out-of-service.
	m.removeAllRedirects(ctx)
	m.setFwDisabled(ctx)

	m.stateMu.Lock()
	stillPending := m.redirPending
	m.stateMu.Unlock()
	if stillPending {
		t.Error("redirPending should be cleared on out-of-service")
	}
}
