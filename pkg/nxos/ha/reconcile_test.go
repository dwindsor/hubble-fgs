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

	hastore "github.com/isovalent/hubble-fgs/pkg/nxos/store/ha"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/vlan"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/vrf"
	hav1 "github.com/isovalent/hubble-fgs/pkg/proto/ha/v1"
)

func newTestReconciler(t *testing.T) (*Reconciler, hastore.Store, vrf.Store, vlan.Store) {
	t.Helper()
	ctx := context.Background()
	haStore := hastore.NewStore(ctx)
	vrfStore := vrf.NewStore(ctx)
	vlanStore := vlan.NewStore(ctx)
	return NewReconciler(haStore, vrfStore, vlanStore), haStore, vrfStore, vlanStore
}

func activateVRFInStore(vs vrf.Store, name string) {
	ctx := context.Background()
	vs.SetGlobal(ctx, name, true)
	vs.SetService(ctx, name, true)
	vs.SetAffinity(ctx, name, 0)
}

// TestReconcile_NilMbrInfo verifies that Reconcile(nil) returns (false, nil) without error.
func TestReconcile_NilMbrInfo(t *testing.T) {
	r, _, _, _ := newTestReconciler(t)
	ok, err := r.Reconcile(context.Background(), "10.0.0.2", nil, "symmetric_hash")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if ok {
		t.Error("expected false for nil peerMbrInfo")
	}
}

// TestReconcile_NoConflicts_ReturnsTrue verifies that reconciliation with no conflicts returns true.
func TestReconcile_NoConflicts_ReturnsTrue(t *testing.T) {
	ctx := context.Background()
	r, _, _, _ := newTestReconciler(t)

	// No local VRFs, peer has some VRFs — no conflicts possible
	peerMbrInfo := &hav1.MbrInfo{
		VrfInfo: []*hav1.VrfInfo{
			{Name: "vrf-a", Id: 10},
			{Name: "vrf-b", Id: 11},
		},
	}

	ok, err := r.Reconcile(ctx, "10.0.0.2", peerMbrInfo, "symmetric_hash")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if !ok {
		t.Error("expected true when there are no conflicts")
	}
}

// TestReconcile_NonLeaderSetsPresets verifies that Reconcile as non-leader creates
// skeleton VRFs with presets, so local activation picks up the peer's GID.
func TestReconcile_NonLeaderSetsPresets(t *testing.T) {
	ctx := context.Background()
	r, haStore, vrfStore, _ := newTestReconciler(t)

	// Set local as non-leader so SetGIDs is called.
	haStore.SetLeader(ctx, false)

	peerMbrInfo := &hav1.MbrInfo{
		VrfInfo: []*hav1.VrfInfo{
			{Name: "peer-vrf", Id: 42},
		},
	}

	_, err := r.Reconcile(ctx, "10.0.0.2", peerMbrInfo, "symmetric_hash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// After reconciliation, activating the same-named VRF locally should get GID=42
	// because SetGIDs created a skeleton with Preset=42.
	vrfStore.SetGlobal(ctx, "peer-vrf", true)
	vrfStore.SetService(ctx, "peer-vrf", true)
	vrfStore.SetAffinity(ctx, "peer-vrf", 0)

	gid, ok := vrfStore.GetGID("peer-vrf")
	if !ok {
		t.Fatal("expected GID to be allocated")
	}
	if gid != 42 {
		t.Errorf("expected preset GID=42 from reconciliation, got %d", gid)
	}
}

// TestReconcile_NonLeaderAdoptsPeerGID verifies that a non-leader adopts the leader's GID.
func TestReconcile_NonLeaderAdoptsPeerGID(t *testing.T) {
	ctx := context.Background()
	r, haStore, vrfStore, _ := newTestReconciler(t)

	// Set local as non-leader
	haStore.SetLeader(ctx, false)

	// Activate local VRF with a different GID from what peer has
	activateVRFInStore(vrfStore, "shared-vrf")
	localGID, ok := vrfStore.GetGID("shared-vrf")
	if !ok {
		t.Fatal("expected local GID to be set")
	}

	peerGID := uint16(99)
	if localGID == peerGID {
		t.Fatal("test setup: localGID and peerGID must differ")
	}

	peerMbrInfo := &hav1.MbrInfo{
		VrfInfo: []*hav1.VrfInfo{
			{Name: "shared-vrf", Id: uint32(peerGID)},
		},
	}

	ok2, err := r.Reconcile(ctx, "10.0.0.2", peerMbrInfo, "symmetric_hash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok2 {
		t.Error("expected true after successful reconciliation")
	}

	// Non-leader should have adopted the peer's GID
	newGID, _ := vrfStore.GetGID("shared-vrf")
	if newGID != peerGID {
		t.Errorf("expected non-leader to adopt peer GID %d, got %d", peerGID, newGID)
	}
}

// TestReconcile_LeaderKeepsOwnGID verifies that the leader does not adopt the peer's GID.
func TestReconcile_LeaderKeepsOwnGID(t *testing.T) {
	ctx := context.Background()
	r, haStore, vrfStore, _ := newTestReconciler(t)

	// Set local as leader
	haStore.SetLeader(ctx, true)

	// Activate local VRF
	activateVRFInStore(vrfStore, "shared-vrf")
	localGID, _ := vrfStore.GetGID("shared-vrf")

	peerMbrInfo := &hav1.MbrInfo{
		VrfInfo: []*hav1.VrfInfo{
			{Name: "shared-vrf", Id: uint32(localGID + 5)}, // peer has different GID
		},
	}

	ok, err := r.Reconcile(ctx, "10.0.0.2", peerMbrInfo, "symmetric_hash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected true for leader (no changes needed)")
	}

	// Leader should keep own GID
	keepGID, _ := vrfStore.GetGID("shared-vrf")
	if keepGID != localGID {
		t.Errorf("expected leader to keep GID %d, got %d", localGID, keepGID)
	}
}

// TestReconcile_BatchedGIDChanges verifies that non-leader adopts all peer GIDs via SetGIDs.
func TestReconcile_BatchedGIDChanges(t *testing.T) {
	ctx := context.Background()
	r, haStore, vrfStore, _ := newTestReconciler(t)

	// Set local as non-leader
	haStore.SetLeader(ctx, false)

	// Activate two local VRFs
	activateVRFInStore(vrfStore, "vrf-a")
	activateVRFInStore(vrfStore, "vrf-b")

	localGIDA, _ := vrfStore.GetGID("vrf-a")
	localGIDB, _ := vrfStore.GetGID("vrf-b")

	// Peer has different GIDs for both VRFs
	peerMbrInfo := &hav1.MbrInfo{
		VrfInfo: []*hav1.VrfInfo{
			{Name: "vrf-a", Id: uint32(localGIDA + 100)},
			{Name: "vrf-b", Id: uint32(localGIDB + 100)},
		},
	}

	ok, err := r.Reconcile(ctx, "10.0.0.2", peerMbrInfo, "symmetric_hash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected true after successful batched reconciliation")
	}

	// Verify both GIDs were adopted
	newGIDA, _ := vrfStore.GetGID("vrf-a")
	newGIDB, _ := vrfStore.GetGID("vrf-b")
	if newGIDA != localGIDA+100 {
		t.Errorf("expected vrf-a GID=%d, got %d", localGIDA+100, newGIDA)
	}
	if newGIDB != localGIDB+100 {
		t.Errorf("expected vrf-b GID=%d, got %d", localGIDB+100, newGIDB)
	}
}

// TestBuildLocalVRFInfo_IncludesActiveVRFs verifies that BuildLocalVRFInfo includes
// active VRFs with GIDs and excludes deactivated ones (GID is freed on deactivation).
func TestBuildLocalVRFInfo_IncludesActiveVRFs(t *testing.T) {
	ctx := context.Background()
	vs := vrf.NewStore(ctx)

	// Activate two VRFs
	vs.SetGlobal(ctx, "vrf-a", true)
	vs.SetService(ctx, "vrf-a", true)
	vs.SetAffinity(ctx, "vrf-a", 0)

	vs.SetGlobal(ctx, "vrf-b", true)
	vs.SetService(ctx, "vrf-b", true)
	vs.SetAffinity(ctx, "vrf-b", 0)

	infos := BuildLocalVRFInfo(vs)
	if len(infos) != 2 {
		t.Fatalf("expected 2 VRFs, got %d", len(infos))
	}

	// Deactivate vrf-b — GID is freed, should no longer appear
	vs.SetService(ctx, "vrf-b", false)

	infos = BuildLocalVRFInfo(vs)
	if len(infos) != 1 {
		t.Fatalf("expected 1 VRF after deactivation, got %d", len(infos))
	}
	if infos[0].Name != "vrf-a" {
		t.Errorf("expected vrf-a, got %s", infos[0].Name)
	}
}

// TestBuildLocalVRFInfo_SendsDPUPinned verifies that BuildLocalVRFInfo sends
// the computed DPUPinned value from the store.
func TestBuildLocalVRFInfo_SendsDPUPinned(t *testing.T) {
	ctx := context.Background()
	vs := vrf.NewStore(ctx, vrf.WithLbModePinning(func() bool { return true }))

	// Activate VRF with affinity=2 — in pinning mode, static affinity
	// goes directly to DPUPinned
	vs.SetGlobal(ctx, "test-vrf", true)
	vs.SetService(ctx, "test-vrf", true)
	vs.SetAffinity(ctx, "test-vrf", 2)

	infos := BuildLocalVRFInfo(vs)
	if len(infos) != 1 {
		t.Fatalf("expected 1 VRF, got %d", len(infos))
	}
	if infos[0].Affinity != 2 {
		t.Errorf("expected DPUPinned=2, got %d", infos[0].Affinity)
	}

	// Test with affinity=0 (dynamic) — DPUPinned is 0 without dpuCount
	vs.SetAffinity(ctx, "test-vrf", 0)
	infos = BuildLocalVRFInfo(vs)
	if infos[0].Affinity != 0 {
		t.Errorf("expected DPUPinned=0 when dynamic without dpuCount, got %d", infos[0].Affinity)
	}
}

// TestBuildLocalVRFInfo_DynamicWithDPUCount verifies that dynamic VRFs
// get FNV-1a pinning when dpuCount is set.
func TestBuildLocalVRFInfo_DynamicWithDPUCount(t *testing.T) {
	ctx := context.Background()
	vs := vrf.NewStore(ctx, vrf.WithLbModePinning(func() bool { return true }), vrf.WithDPUCount(4))

	// Activate VRF with affinity=0 (dynamic)
	vs.SetGlobal(ctx, "test-vrf", true)
	vs.SetService(ctx, "test-vrf", true)
	vs.SetAffinity(ctx, "test-vrf", 0)

	infos := BuildLocalVRFInfo(vs)
	if len(infos) != 1 {
		t.Fatalf("expected 1 VRF, got %d", len(infos))
	}
	// DPUPinned should be in range [1, 4] from FNV-1a hash
	if infos[0].Affinity < 1 || infos[0].Affinity > 4 {
		t.Errorf("expected DPUPinned in [1,4], got %d", infos[0].Affinity)
	}
}

// TestBuildLocalVLANInfo_SendsDPUPinned verifies that BuildLocalVLANInfo sends
// the computed DPUPinned value regardless of lbMode.
func TestBuildLocalVLANInfo_SendsDPUPinned(t *testing.T) {
	ctx := context.Background()
	vlanStore := vlan.NewStore(ctx, vlan.WithLbModePinning(func() bool { return true }))

	// Activate VLAN with affinity=4 — in pinning mode, static pinning
	vlanStore.SetGlobal(ctx, "vlan-100", true)
	vlanStore.SetService(ctx, "vlan-100", true)
	vlanStore.SetAffinity(ctx, "vlan-100", 4)

	infos := BuildLocalVLANInfo(vlanStore)
	if len(infos) != 1 {
		t.Fatalf("expected 1 VLAN, got %d", len(infos))
	}
	if infos[0].Affinity != 4 {
		t.Errorf("expected DPUPinned=4, got %d", infos[0].Affinity)
	}
}
