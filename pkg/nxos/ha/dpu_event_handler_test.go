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
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/nxos/store/dpu"
	hastore "github.com/isovalent/hubble-fgs/pkg/nxos/store/ha"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

// newTestManager creates a manager with an HA store and a peer pre-configured.
func newTestManager(ctx context.Context) (*manager, hastore.Store) {
	hs := hastore.NewStore(ctx)
	hs.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		AdjacencyCriteria: make(types.HACriteria),
	})
	m := NewManager(
		WithHAStoreForManager(hs),
		WithLocalIP("10.0.0.1"),
	).(*manager)
	return m, hs
}

func TestRegisterDpu_AddsEntry(t *testing.T) {
	ctx := context.Background()
	m, _ := newTestManager(ctx)

	m.RegisterDpu(ctx, "dpu-1")
	m.RegisterDpu(ctx, "dpu-2")

	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.dpuStatuses["dpu-1"]; !ok {
		t.Error("expected dpu-1 to be registered")
	}
	if _, ok := m.dpuStatuses["dpu-2"]; !ok {
		t.Error("expected dpu-2 to be registered")
	}
	// Default values should be false
	if m.dpuStatuses["dpu-1"].keepaliveUp {
		t.Error("expected keepaliveUp to be false for new dpu")
	}
}

func TestRegisterDpu_Idempotent(t *testing.T) {
	ctx := context.Background()
	m, _ := newTestManager(ctx)

	m.RegisterDpu(ctx, "dpu-1")
	m.mu.Lock()
	m.dpuStatuses["dpu-1"].keepaliveUp = true
	m.mu.Unlock()

	// Re-registering should not overwrite existing state.
	m.RegisterDpu(ctx, "dpu-1")

	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.dpuStatuses["dpu-1"].keepaliveUp {
		t.Error("expected keepaliveUp to be preserved on re-register")
	}
}

func TestKeepaliveAggregation_AllUpBecomesTrue(t *testing.T) {
	ctx := context.Background()
	m, hs := newTestManager(ctx)

	m.RegisterDpu(ctx, "dpu-1")
	m.RegisterDpu(ctx, "dpu-2")

	// One up, one still down — criterion should be false.
	m.UpdateKeepalive(ctx, "dpu-1", true)
	peer, ok := hs.Peer("10.0.0.2")
	if !ok {
		t.Fatal("peer not found")
	}
	if peer.AdjacencyCriteria[types.HACritPeerDPUKeepalive] {
		t.Error("expected keepalive criterion false when only one DPU is up")
	}

	// Both up — criterion should be true.
	m.UpdateKeepalive(ctx, "dpu-2", true)
	peer, _ = hs.Peer("10.0.0.2")
	if !peer.AdjacencyCriteria[types.HACritPeerDPUKeepalive] {
		t.Error("expected keepalive criterion true when all DPUs are up")
	}

	// One goes down — criterion should revert to false.
	m.UpdateKeepalive(ctx, "dpu-1", false)
	peer, _ = hs.Peer("10.0.0.2")
	if peer.AdjacencyCriteria[types.HACritPeerDPUKeepalive] {
		t.Error("expected keepalive criterion false after one DPU goes down")
	}
}

func TestBulkSyncAggregation_RequiresBothLocalAndPeer(t *testing.T) {
	ctx := context.Background()
	m, hs := newTestManager(ctx)

	m.RegisterDpu(ctx, "dpu-1")

	// Only local done — criterion false.
	m.UpdateBulkSyncLocal(ctx, "dpu-1", true)
	peer, _ := hs.Peer("10.0.0.2")
	if peer.AdjacencyCriteria[types.HACritPeerDPUBulkSync] {
		t.Error("expected bulk_sync criterion false with only local done")
	}

	// Both local and peer done — criterion true.
	m.UpdateBulkSyncPeer(ctx, "dpu-1", true)
	peer, _ = hs.Peer("10.0.0.2")
	if !peer.AdjacencyCriteria[types.HACritPeerDPUBulkSync] {
		t.Error("expected bulk_sync criterion true when both local and peer are done")
	}
}

func TestBulkSyncAggregation_MultipleDPUs_AllMustComplete(t *testing.T) {
	ctx := context.Background()
	m, hs := newTestManager(ctx)

	m.RegisterDpu(ctx, "dpu-1")
	m.RegisterDpu(ctx, "dpu-2")

	m.UpdateBulkSyncLocal(ctx, "dpu-1", true)
	m.UpdateBulkSyncPeer(ctx, "dpu-1", true)

	// dpu-2 not done — criterion false.
	peer, _ := hs.Peer("10.0.0.2")
	if peer.AdjacencyCriteria[types.HACritPeerDPUBulkSync] {
		t.Error("expected bulk_sync criterion false when dpu-2 not done")
	}

	m.UpdateBulkSyncLocal(ctx, "dpu-2", true)
	m.UpdateBulkSyncPeer(ctx, "dpu-2", true)

	peer, _ = hs.Peer("10.0.0.2")
	if !peer.AdjacencyCriteria[types.HACritPeerDPUBulkSync] {
		t.Error("expected bulk_sync criterion true when all DPUs complete")
	}
}

func TestNoDPUs_CriteriaFalse(t *testing.T) {
	ctx := context.Background()
	m, hs := newTestManager(ctx)

	// No DPUs registered — aggregate should be false (len == 0 case).
	m.aggregateDPUStatus(ctx)
	peer, _ := hs.Peer("10.0.0.2")
	if peer.AdjacencyCriteria[types.HACritPeerDPUKeepalive] {
		t.Error("expected keepalive criterion false with no DPUs")
	}
	if peer.AdjacencyCriteria[types.HACritPeerDPUBulkSync] {
		t.Error("expected bulk_sync criterion false with no DPUs")
	}
}

func TestPolicyRevision_StoredInHAStore(t *testing.T) {
	ctx := context.Background()
	m, hs := newTestManager(ctx)

	m.UpdatePolicyRevision(ctx, "rev-abc123")

	local := hs.Local()
	if local.PolicyRev != "rev-abc123" {
		t.Errorf("expected PolicyRev %q, got %q", "rev-abc123", local.PolicyRev)
	}
}

func TestDPUStatusesVisibleOnPeer(t *testing.T) {
	ctx := context.Background()
	m, hs := newTestManager(ctx)

	m.RegisterDpu(ctx, "dpu-1")
	m.UpdateKeepalive(ctx, "dpu-1", true)
	m.UpdateBulkSyncLocal(ctx, "dpu-1", true)
	m.UpdateBulkSyncPeer(ctx, "dpu-1", true)

	peer, ok := hs.Peer("10.0.0.2")
	if !ok {
		t.Fatal("peer not found")
	}
	s, ok := peer.DPUStatuses["dpu-1"]
	if !ok {
		t.Fatal("dpu-1 status not found on peer")
	}
	if !s.KeepaliveUp {
		t.Error("expected KeepaliveUp true")
	}
	if !s.BulkSyncLocal {
		t.Error("expected BulkSyncLocal true")
	}
	if !s.BulkSyncPeer {
		t.Error("expected BulkSyncPeer true")
	}
}

func TestRegisterDpu_ResolvesIPToName(t *testing.T) {
	ctx := context.Background()
	hs := hastore.NewStore(ctx)
	hs.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		AdjacencyCriteria: make(types.HACriteria),
	})

	ds := dpu.NewStore(ctx)
	ds.Update(ctx, types.DPU{Name: "dpu-1", IP: "169.254.0.1"})
	ds.Update(ctx, types.DPU{Name: "dpu-2", IP: "169.254.0.2"})

	m := NewManager(
		WithHAStoreForManager(hs),
		WithLocalIP("10.0.0.1"),
		WithDPUStore(ds),
	).(*manager)

	// Register using IP (as FWA gRPC does) — should resolve to DPU name.
	m.RegisterDpu(ctx, "169.254.0.1")

	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.dpuStatuses["dpu-1"]; !ok {
		t.Error("expected IP 169.254.0.1 to resolve to dpu-1")
	}
	if _, ok := m.dpuStatuses["169.254.0.1"]; ok {
		t.Error("expected no entry under raw IP 169.254.0.1")
	}
}

func TestUpdateKeepalive_ResolvesIPToName(t *testing.T) {
	ctx := context.Background()
	hs := hastore.NewStore(ctx)
	hs.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		AdjacencyCriteria: make(types.HACriteria),
	})

	ds := dpu.NewStore(ctx)
	ds.Update(ctx, types.DPU{Name: "dpu-1", IP: "169.254.0.1"})

	m := NewManager(
		WithHAStoreForManager(hs),
		WithLocalIP("10.0.0.1"),
		WithDPUStore(ds),
	).(*manager)

	// Pre-populate via name (as NewManager does), then update via IP.
	m.UpdateKeepalive(ctx, "169.254.0.1", true)

	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.dpuStatuses["dpu-1"]
	if !ok {
		t.Fatal("expected IP to resolve to dpu-1")
	}
	if !s.keepaliveUp {
		t.Error("expected keepaliveUp true after update via IP")
	}
}
