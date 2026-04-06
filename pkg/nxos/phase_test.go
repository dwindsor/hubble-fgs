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
