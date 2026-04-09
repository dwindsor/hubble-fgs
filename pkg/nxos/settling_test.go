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
	"testing"
	"time"

	"github.com/isovalent/hubble-fgs/pkg/nxos/store/dpu"
	hastore "github.com/isovalent/hubble-fgs/pkg/nxos/store/ha"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

// newDpuInSyncTestManager creates a manager with a small settling window for tests.
// DpuInSync is only active when skipDPU=false, so the dpuStore is initialized without skip.
func newDpuInSyncTestManager(ctx context.Context) *manager {
	haStore := hastore.NewStore(ctx)
	dpuStore := dpu.NewStore(ctx)
	m := &manager{
		lastSystemState:         -1,
		dpuStore:                dpuStore,
		haStore:                 haStore,
		dpuInSyncSettlingWindow: 10 * time.Millisecond,
	}
	// Seed HACritDpuInSync as true so settling can guard the true→false transition.
	haStore.UpdateLocalCriterion(ctx, types.HACritDpuInSync, true)
	return m
}

// TestDpuInSyncSettling_SuppressesDegradation verifies that HACritDpuInSync stays
// true during the settling window when DpuInSync(false) is called.
func TestDpuInSyncSettling_SuppressesDegradation(t *testing.T) {
	ctx := context.Background()
	m := newDpuInSyncTestManager(ctx)

	// First out-of-sync call — should start settling and suppress the criterion update.
	m.DpuInSync(ctx, false)

	local := m.haStore.Local()
	if !local.Criteria[types.HACritDpuInSync] {
		t.Error("expected HACritDpuInSync=true during settling window, got false")
	}
	if m.dpuInSyncSettlingStart.IsZero() {
		t.Error("expected settling start to be set after first out-of-sync call")
	}
}

// TestDpuInSyncSettling_AppliesAfterExpiry verifies that HACritDpuInSync goes
// false after the settling window expires with a persistent out-of-sync.
func TestDpuInSyncSettling_AppliesAfterExpiry(t *testing.T) {
	ctx := context.Background()
	m := newDpuInSyncTestManager(ctx)

	// First call — starts settling.
	m.DpuInSync(ctx, false)

	// Wait for window to expire.
	time.Sleep(20 * time.Millisecond)

	// Second call — window expired, degradation should be applied.
	m.DpuInSync(ctx, false)

	local := m.haStore.Local()
	if local.Criteria[types.HACritDpuInSync] {
		t.Error("expected HACritDpuInSync=false after settling window expired, got true")
	}
	if !m.dpuInSyncSettlingStart.IsZero() {
		t.Error("expected settling start to be cleared after expiry")
	}
}

// TestDpuInSyncSettling_ClearsOnRecovery verifies that DpuInSync(true) clears
// the settling window immediately and updates the criterion to true.
func TestDpuInSyncSettling_ClearsOnRecovery(t *testing.T) {
	ctx := context.Background()
	m := newDpuInSyncTestManager(ctx)

	// Start settling.
	m.DpuInSync(ctx, false)
	if m.dpuInSyncSettlingStart.IsZero() {
		t.Fatal("expected settling to be active")
	}

	// Recovery — settling should clear and criterion stay true.
	m.DpuInSync(ctx, true)

	if !m.dpuInSyncSettlingStart.IsZero() {
		t.Error("expected settling start to be cleared on recovery")
	}
	local := m.haStore.Local()
	if !local.Criteria[types.HACritDpuInSync] {
		t.Error("expected HACritDpuInSync=true after recovery, got false")
	}
}

// TestDpuInSyncSettling_SkipsWhenAlreadyFalse verifies that no settling starts
// when HACritDpuInSync is already false in the haStore.
func TestDpuInSyncSettling_SkipsWhenAlreadyFalse(t *testing.T) {
	ctx := context.Background()
	m := newDpuInSyncTestManager(ctx)

	// Drive the criterion to false first (simulating a previous degradation).
	m.haStore.UpdateLocalCriterion(ctx, types.HACritDpuInSync, false)

	// Out-of-sync call — criterion already false, no settling should start.
	m.DpuInSync(ctx, false)

	if !m.dpuInSyncSettlingStart.IsZero() {
		t.Error("expected no settling when criterion is already false")
	}
}

// TestDpuInSyncSettling_InteractionWithExistingRetry verifies that settling works
// correctly when DpuInSync(false) is called after the agw retry threshold —
// i.e. the settling window is an additional layer on top of the existing retry.
func TestDpuInSyncSettling_InteractionWithExistingRetry(t *testing.T) {
	ctx := context.Background()
	m := newDpuInSyncTestManager(ctx)

	// Simulate that the agw retry threshold has been reached by calling DpuInSync(false)
	// multiple times. The settling window should still suppress the first call.
	for i := 0; i < 3; i++ {
		m.DpuInSync(ctx, false)
	}

	local := m.haStore.Local()
	if !local.Criteria[types.HACritDpuInSync] {
		t.Error("expected HACritDpuInSync=true during settling window regardless of call count")
	}

	// Wait for window to expire, then one more call should apply degradation.
	time.Sleep(20 * time.Millisecond)
	m.DpuInSync(ctx, false)

	local = m.haStore.Local()
	if local.Criteria[types.HACritDpuInSync] {
		t.Error("expected HACritDpuInSync=false after settling window expired")
	}
}
