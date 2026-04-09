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
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
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
	ok, err := r.Reconcile(context.Background(), "10.0.0.2", nil, "symmetric-hash")
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

	ok, err := r.Reconcile(ctx, "10.0.0.2", peerMbrInfo, "symmetric-hash")
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

	_, err := r.Reconcile(ctx, "10.0.0.2", peerMbrInfo, "symmetric-hash")
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

	ok2, err := r.Reconcile(ctx, "10.0.0.2", peerMbrInfo, "symmetric-hash")
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

	ok, err := r.Reconcile(ctx, "10.0.0.2", peerMbrInfo, "symmetric-hash")
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

	ok, err := r.Reconcile(ctx, "10.0.0.2", peerMbrInfo, "symmetric-hash")
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

// TestReconcile_LeaderAdoptsCheaperSide verifies that the leader adopts the peer's GID
// when doing so causes fewer cascading collisions than the peer adopting.
func TestReconcile_LeaderAdoptsCheaperSide(t *testing.T) {
	ctx := context.Background()
	r, haStore, vrfStore, _ := newTestReconciler(t)

	haStore.SetLeader(ctx, true)

	// Activate vrf-a on leader — gets sequential GID (e.g. 10).
	activateVRFInStore(vrfStore, "vrf-a")
	leaderGID, _ := vrfStore.GetGID("vrf-a")

	// Peer has vrf-a=<different>, vrf-b=leaderGID.
	// If peer adopts leaderGID for vrf-a: vrf-b already uses leaderGID → peerCost=1.
	// If leader adopts peerGIDForA: no other leader VRF uses peerGIDForA → leaderCost=0.
	// Leader should adopt peerGIDForA (cheaper).
	peerGIDForA := leaderGID + 10

	peerMbrInfo := &hav1.MbrInfo{
		VrfInfo: []*hav1.VrfInfo{
			{Name: "vrf-a", Id: uint32(peerGIDForA)},
			{Name: "vrf-b", Id: uint32(leaderGID)}, // forces peerCost=1 for vrf-a conflict
		},
	}

	ok, err := r.Reconcile(ctx, "10.0.0.2", peerMbrInfo, "symmetric-hash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected true from leader reconciliation")
	}

	// Leader should have adopted peer's GID for vrf-a.
	gid, _ := vrfStore.GetGID("vrf-a")
	if gid != peerGIDForA {
		t.Errorf("expected leader to adopt GID=%d, got %d", peerGIDForA, gid)
	}
}

// TestReconcile_LeaderBreaksTie verifies that the leader keeps its own GID on a tie.
func TestReconcile_LeaderBreaksTie(t *testing.T) {
	ctx := context.Background()
	r, haStore, vrfStore, _ := newTestReconciler(t)

	haStore.SetLeader(ctx, true)

	// Activate vrf-a → gets sequential GID.
	activateVRFInStore(vrfStore, "vrf-a")
	localGID, _ := vrfStore.GetGID("vrf-a")

	// Peer has vrf-a with a different GID.
	// Neither side has other VRFs using the conflicting GID → both costs = 0.
	// Tie: leader keeps its own GID.
	peerGID := localGID + 10

	peerMbrInfo := &hav1.MbrInfo{
		VrfInfo: []*hav1.VrfInfo{
			{Name: "vrf-a", Id: uint32(peerGID)},
		},
	}

	_, err := r.Reconcile(ctx, "10.0.0.2", peerMbrInfo, "symmetric-hash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Leader should keep its own GID (tie → leader wins).
	gid, _ := vrfStore.GetGID("vrf-a")
	if gid != localGID {
		t.Errorf("expected leader to keep GID=%d on tie, got %d", localGID, gid)
	}
}

// TestReconcile_LeaderAdoptsMultiple verifies that when multiple conflicts exist,
// only the subset where leader-side adoption is cheaper actually changes on leader.
func TestReconcile_LeaderAdoptsMultiple(t *testing.T) {
	ctx := context.Background()
	r, haStore, vrfStore, _ := newTestReconciler(t)

	haStore.SetLeader(ctx, true)

	// Activate vrf-a and vrf-b on leader.
	activateVRFInStore(vrfStore, "vrf-a")
	activateVRFInStore(vrfStore, "vrf-b")
	localGIDA, _ := vrfStore.GetGID("vrf-a")
	localGIDB, _ := vrfStore.GetGID("vrf-b")

	// For vrf-a: peer has a different GID, no cascade either side → tie → leader keeps localGIDA.
	peerGIDA := localGIDA + 100

	// For vrf-b: peer has peerGIDB, AND peer also has vrf-c=localGIDB.
	// peerCost for vrf-b = peerByGID[localGIDB] = 1 (vrf-c uses localGIDB).
	// leaderCost for vrf-b = localByGID[peerGIDB] = 0 (no leader VRF uses peerGIDB).
	// Leader adopts peerGIDB (cheaper).
	peerGIDB := localGIDB + 100

	peerMbrInfo := &hav1.MbrInfo{
		VrfInfo: []*hav1.VrfInfo{
			{Name: "vrf-a", Id: uint32(peerGIDA)},
			{Name: "vrf-b", Id: uint32(peerGIDB)},
			{Name: "vrf-c", Id: uint32(localGIDB)}, // forces peerCost=1 for vrf-b conflict
		},
	}

	_, err := r.Reconcile(ctx, "10.0.0.2", peerMbrInfo, "symmetric-hash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// vrf-a: leader keeps its GID (tie)
	gidA, _ := vrfStore.GetGID("vrf-a")
	if gidA != localGIDA {
		t.Errorf("expected vrf-a GID=%d (leader keeps on tie), got %d", localGIDA, gidA)
	}

	// vrf-b: leader adopts peerGIDB (cheaper)
	gidB, _ := vrfStore.GetGID("vrf-b")
	if gidB != peerGIDB {
		t.Errorf("expected vrf-b GID=%d (leader adopts), got %d", peerGIDB, gidB)
	}
}

// TestReconcile_NoConflictsLeaderUnchanged verifies that when GIDs agree, leader makes no changes.
func TestReconcile_NoConflictsLeaderUnchanged(t *testing.T) {
	ctx := context.Background()
	r, haStore, vrfStore, _ := newTestReconciler(t)

	haStore.SetLeader(ctx, true)

	activateVRFInStore(vrfStore, "vrf-a")
	activateVRFInStore(vrfStore, "vrf-b")
	localGIDA, _ := vrfStore.GetGID("vrf-a")
	localGIDB, _ := vrfStore.GetGID("vrf-b")

	// Peer has the exact same GIDs.
	peerMbrInfo := &hav1.MbrInfo{
		VrfInfo: []*hav1.VrfInfo{
			{Name: "vrf-a", Id: uint32(localGIDA)},
			{Name: "vrf-b", Id: uint32(localGIDB)},
		},
	}

	ok, err := r.Reconcile(ctx, "10.0.0.2", peerMbrInfo, "symmetric-hash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected true when GIDs agree")
	}

	// GIDs must be unchanged.
	gidA, _ := vrfStore.GetGID("vrf-a")
	gidB, _ := vrfStore.GetGID("vrf-b")
	if gidA != localGIDA || gidB != localGIDB {
		t.Errorf("expected unchanged GIDs %d/%d, got vrf-a=%d vrf-b=%d", localGIDA, localGIDB, gidA, gidB)
	}
}

// TestReconcile_ReservePresetForMissingVRF verifies that a VRF known only to the peer
// gets a Preset set so that local activation picks up the peer's GID.
func TestReconcile_ReservePresetForMissingVRF(t *testing.T) {
	ctx := context.Background()
	r, haStore, vrfStore, _ := newTestReconciler(t)

	// Works for both leader and non-leader — ReservePreset is always called.
	haStore.SetLeader(ctx, true)

	peerMbrInfo := &hav1.MbrInfo{
		VrfInfo: []*hav1.VrfInfo{
			{Name: "peer-only-vrf", Id: 77},
		},
	}

	_, err := r.Reconcile(ctx, "10.0.0.2", peerMbrInfo, "symmetric-hash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Activating the VRF locally should pick up preset GID=77.
	vrfStore.SetGlobal(ctx, "peer-only-vrf", true)
	vrfStore.SetService(ctx, "peer-only-vrf", true)
	vrfStore.SetAffinity(ctx, "peer-only-vrf", 0)

	gid, ok := vrfStore.GetGID("peer-only-vrf")
	if !ok {
		t.Fatal("expected GID to be allocated after activation")
	}
	if gid != 77 {
		t.Errorf("expected preset GID=77 to be honored, got %d", gid)
	}
}

// TestReconcile_ReservePresetSkipsActiveVRF verifies that ReservePreset does not
// disturb a VRF that is already active with a different GID.
func TestReconcile_ReservePresetSkipsActiveVRF(t *testing.T) {
	ctx := context.Background()
	r, haStore, vrfStore, _ := newTestReconciler(t)

	haStore.SetLeader(ctx, true)

	// Activate locally with GID=20.
	activateVRFInStore(vrfStore, "active-vrf")
	localGID, _ := vrfStore.GetGID("active-vrf")

	// Peer reports a different GID for the same VRF.
	peerGID := localGID + 10
	peerMbrInfo := &hav1.MbrInfo{
		VrfInfo: []*hav1.VrfInfo{
			{Name: "active-vrf", Id: uint32(peerGID)},
		},
	}

	_, err := r.Reconcile(ctx, "10.0.0.2", peerMbrInfo, "symmetric-hash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// ReservePreset must not have changed the active VRF's GID.
	// (Leader tie-break may or may not change it, but for this test
	// we only verify ReservePreset didn't silently overwrite.)
	// Since both costs=0 it's a tie → leader keeps its GID.
	gid, _ := vrfStore.GetGID("active-vrf")
	if gid != localGID {
		t.Errorf("expected active VRF GID=%d to be preserved, got %d", localGID, gid)
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
	vs := vrf.NewStore(ctx, vrf.WithLbModePinning(true))

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
	vs := vrf.NewStore(ctx, vrf.WithLbModePinning(true), vrf.WithDPUCount(4))

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

// TestBuildLocalVLANIdRanges verifies that consecutive VLAN IDs are merged into ranges
// and non-consecutive IDs produce separate ranges.
func TestBuildLocalVLANIdRanges(t *testing.T) {
	ctx := context.Background()
	vs := vlan.NewStore(ctx)

	// Activate VLANs 100, 101, 102 (consecutive) and 200 (separate).
	for _, name := range []string{"vlan-100", "vlan-101", "vlan-102", "vlan-200"} {
		vs.SetGlobal(ctx, name, true)
		vs.SetService(ctx, name, true)
		vs.SetAffinity(ctx, name, 0)
	}

	ranges := BuildLocalVLANIdRanges(vs)
	if len(ranges) != 2 {
		t.Fatalf("expected 2 ranges, got %d", len(ranges))
	}
	// First range: 100-102
	if ranges[0].Start != 100 || ranges[0].End != 102 {
		t.Errorf("expected range [100,102], got [%d,%d]", ranges[0].Start, ranges[0].End)
	}
	// Second range: 200-200
	if ranges[1].Start != 200 || ranges[1].End != 200 {
		t.Errorf("expected range [200,200], got [%d,%d]", ranges[1].Start, ranges[1].End)
	}
}

// TestExpandVlanIdRanges verifies that ranges are expanded into the correct name->ID map.
func TestExpandVlanIdRanges(t *testing.T) {
	ctx := context.Background()
	vs := vlan.NewStore(ctx)

	for _, name := range []string{"vlan-10", "vlan-11", "vlan-20"} {
		vs.SetGlobal(ctx, name, true)
		vs.SetService(ctx, name, true)
		vs.SetAffinity(ctx, name, 0)
	}

	ranges := BuildLocalVLANIdRanges(vs)
	result := ExpandVlanIdRanges(ranges)

	expected := map[string]uint16{
		"vlan-10": 10,
		"vlan-11": 11,
		"vlan-20": 20,
	}
	if len(result) != len(expected) {
		t.Fatalf("expected %d entries, got %d", len(expected), len(result))
	}
	for name, id := range expected {
		if result[name] != id {
			t.Errorf("expected %s=%d, got %d", name, id, result[name])
		}
	}
}

// TestReconcile_StoresPeerVlanIDs verifies that peer VLAN IDs are stored on HAPeerState
// after reconciliation.
func TestReconcile_StoresPeerVlanIDs(t *testing.T) {
	ctx := context.Background()
	r, haStore, _, _ := newTestReconciler(t)

	haStore.SetLeader(ctx, true)
	haStore.SetPeer(ctx, "10.0.0.2", types.HAPeerState{IP: "10.0.0.2"})

	peerMbrInfo := &hav1.MbrInfo{
		VlanIdRanges: []*hav1.VlanIdRange{
			{Start: 100, End: 102},
			{Start: 200, End: 200},
		},
	}

	_, err := r.Reconcile(ctx, "10.0.0.2", peerMbrInfo, "symmetric-hash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	peer, ok := haStore.Peer("10.0.0.2")
	if !ok {
		t.Fatal("peer not found")
	}
	if len(peer.VlanIDs) != 4 {
		t.Fatalf("expected 4 VLAN IDs (100,101,102,200), got %d", len(peer.VlanIDs))
	}
	for _, name := range []string{"vlan-100", "vlan-101", "vlan-102", "vlan-200"} {
		if _, ok := peer.VlanIDs[name]; !ok {
			t.Errorf("expected %s in peer VlanIDs", name)
		}
	}
}

// TestBuildLocalVLANInfo_SendsDPUPinned verifies that BuildLocalVLANInfo sends
// the computed DPUPinned value regardless of lbMode.
func TestBuildLocalVLANInfo_SendsDPUPinned(t *testing.T) {
	ctx := context.Background()
	vlanStore := vlan.NewStore(ctx, vlan.WithLbModePinning(true))

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
