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

	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"
	hav1 "github.com/isovalent/hubble-fgs/pkg/proto/ha/v1"
)

// stubPolicyHandler satisfies switchpolicy.PolicyHandler without any real logic.
type stubPolicyHandler struct{}

func (s *stubPolicyHandler) SetL3Networks(_ *switchpolicy.L3Networks) error { return nil }
func (s *stubPolicyHandler) GetL3Networks() *switchpolicy.L3Networks {
	return switchpolicy.NewL3Networks()
}
func (s *stubPolicyHandler) ListPolicies() map[switchpolicy.ResourceID]switchpolicy.K8sRulesList {
	return nil
}
func (s *stubPolicyHandler) UpsertPolicy(_ switchpolicy.ResourceID, _ switchpolicy.K8sRulesList, _ string) error {
	return nil
}
func (s *stubPolicyHandler) DeletePolicy(_ switchpolicy.ResourceID, _ string) error { return nil }
func (s *stubPolicyHandler) ResourceVersion() (string, error)                       { return "", nil }

// newTestNxos returns a minimal Nxos suitable for HaReconcile unit tests.
// Target is nil so gnmiSet is a no-op; policyHandler is stubbed out.
func newTestNxos() *Nxos {
	n := &Nxos{
		GidsInUse:     make(map[uint16]string),
		policyHandler: &stubPolicyHandler{},
	}
	n.Alloc.Gids = make(map[string]uint16)
	n.Alloc.VrfDpus = make(map[string]uint16)
	n.Alloc.BdDpus = make(map[string]uint16)
	n.Alloc.Next = 10
	n.Ha.Alloc = make(map[string]HaAlloc)
	n.Ha.peers = make(map[string]HaPeer)
	n.Vrfs = make(map[string]VrfBd)
	n.Bds = make(map[string]VrfBd)
	return n
}

// TestHaReconcile_GidsInUseIntegrity verifies when Phase 1 processes
// a chained GID swap (red:100→200, blue:200→400), the conditional delete must
// not remove red's newly-written GidsInUse[200] entry when processing blue.
//
// After reconciliation:
//   - GidsInUse[200] == "red"
//   - GidsInUse[400] == "blue"
//   - GID 200 must not be re-allocated to a new VRF
func TestHaReconcile_GidsInUseIntegrity(t *testing.T) {
	n := newTestNxos()
	n.Ha.IsLeader = false
	n.Ha.enabled = true
	n.Ha.operUp = true

	// Local state: red=100, blue=200
	n.Alloc.Gids["red"] = 100
	n.Alloc.Gids["blue"] = 200
	n.GidsInUse[100] = "red"
	n.GidsInUse[200] = "blue"

	// Populate Vrfs so setGlobalId can look up VRF entries.
	n.Vrfs["red"] = VrfBd{Name: "red"}
	n.Vrfs["blue"] = VrfBd{Name: "blue"}

	// Peer state: red=200, blue=400
	peer := "peer1"
	info := hav1.MbrInfo{
		VrfInfo: []*hav1.VrfInfo{
			{Name: "red", Id: 200},
			{Name: "blue", Id: 400},
		},
	}

	n.HaReconcile(context.Background(), peer, info)

	// Both GIDs must be correctly tracked.
	if got, ok := n.GidsInUse[200]; !ok || got != "red" {
		t.Errorf("GidsInUse[200] = %q (ok=%v), want \"red\"", got, ok)
	}
	if got, ok := n.GidsInUse[400]; !ok || got != "blue" {
		t.Errorf("GidsInUse[400] = %q (ok=%v), want \"blue\"", got, ok)
	}

	// Old GID 100 must be freed.
	if v, ok := n.GidsInUse[100]; ok {
		t.Errorf("GidsInUse[100] = %q still present; expected freed", v)
	}

	// Alloc.Gids must reflect the new GIDs.
	if n.Alloc.Gids["red"] != 200 {
		t.Errorf("Alloc.Gids[red] = %d, want 200", n.Alloc.Gids["red"])
	}
	if n.Alloc.Gids["blue"] != 400 {
		t.Errorf("Alloc.Gids[blue] = %d, want 400", n.Alloc.Gids["blue"])
	}

	// GID 200 must not be re-allocatable: getGid for a new VRF must not return 200.
	n.Alloc.Next = 10
	assigned := n.getGid(context.Background(), "orange")
	if assigned == 200 {
		t.Errorf("getGid(orange) returned 200; GID 200 leaked from GidsInUse")
	}

	// Invariant: every (vrf, gid) in Alloc.Gids must be tracked in GidsInUse.
	for vrf, gid := range n.Alloc.Gids {
		if tracked, ok := n.GidsInUse[gid]; !ok || tracked != vrf {
			t.Errorf("invariant broken: Alloc.Gids[%s]=%d but GidsInUse[%d]=%q", vrf, gid, gid, tracked)
		}
	}
}

// TestReconBatches_GidSwapOrdering verifies when two VRFs swap GIDs,
// reconBatches puts the VRF freeing the contested GID in batch 1 and the VRF
// adopting it in batch 2.
//
// Scenario: red: 100→200, blue: 200→400
//   - blue's old GID (200) is adopted by red → blue must go in batch 1
//   - red's old GID (100) is not claimed by anyone → red goes in batch 2
func TestReconBatches_GidSwapOrdering(t *testing.T) {
	recon := map[string]ReconGid{
		"red":  {OldGid: 100, NewGid: 200},
		"blue": {OldGid: 200, NewGid: 400},
	}

	batch1, batch2 := reconBatches(recon)

	// blue must be in batch 1 (its old GID 200 is contested).
	if _, ok := batch1["blue"]; !ok {
		t.Error("batch1 missing \"blue\"; expected it to free GID 200 first")
	}
	if _, ok := batch2["blue"]; ok {
		t.Error("batch2 should not contain \"blue\"")
	}

	// red must be in batch 2 (its old GID 100 is not contested).
	if _, ok := batch2["red"]; !ok {
		t.Error("batch2 missing \"red\"; expected it to adopt GID 200 after blue vacates it")
	}
	if _, ok := batch1["red"]; ok {
		t.Error("batch1 should not contain \"red\"")
	}

	// New GIDs must be preserved.
	if batch1["blue"] != 400 {
		t.Errorf("batch1[blue] = %d, want 400", batch1["blue"])
	}
	if batch2["red"] != 200 {
		t.Errorf("batch2[red] = %d, want 200", batch2["red"])
	}
}

// TestUpdateHaConfig_BatchSuppressesIntermediatePushes verifies that
// updateHaConfig calls made inside a batch are deferred (haConfigPending set)
// and a single flush occurs when the batch ends.
func TestUpdateHaConfig_BatchSuppressesIntermediatePushes(t *testing.T) {
	n := newTestNxos()

	n.beginHaConfigBatch()

	if n.haConfigDeferDepth != 1 {
		t.Fatalf("haConfigDeferDepth = %d, want 1 after beginHaConfigBatch", n.haConfigDeferDepth)
	}

	// Simulate the setters calling updateHaConfig inside the batch.
	n.updateHaConfig()
	n.updateHaConfig()

	if !n.haConfigPending {
		t.Error("haConfigPending should be true after updateHaConfig calls while batching")
	}
	if n.haConfigDeferDepth != 1 {
		t.Errorf("haConfigDeferDepth = %d, want 1 (no change from updateHaConfig calls)", n.haConfigDeferDepth)
	}

	// End the batch: pending should be cleared and a single flush fires.
	n.endHaConfigBatch()

	if n.haConfigDeferDepth != 0 {
		t.Errorf("haConfigDeferDepth = %d, want 0 after endHaConfigBatch", n.haConfigDeferDepth)
	}
	if n.haConfigPending {
		t.Error("haConfigPending should be false after endHaConfigBatch flushed the deferred update")
	}
}

// TestUpdateHaConfig_NestedBatch verifies that nested begin/end pairs only
// flush when the outermost batch ends (depth reaches 0).
func TestUpdateHaConfig_NestedBatch(t *testing.T) {
	n := newTestNxos()

	n.beginHaConfigBatch() // depth = 1
	if n.haConfigDeferDepth != 1 {
		t.Fatalf("depth = %d after outer begin, want 1", n.haConfigDeferDepth)
	}

	n.beginHaConfigBatch() // depth = 2
	if n.haConfigDeferDepth != 2 {
		t.Fatalf("depth = %d after inner begin, want 2", n.haConfigDeferDepth)
	}

	n.updateHaConfig() // deferred, sets pending
	if !n.haConfigPending {
		t.Error("haConfigPending should be true after updateHaConfig at depth 2")
	}

	n.endHaConfigBatch() // depth = 1, no flush
	if n.haConfigDeferDepth != 1 {
		t.Fatalf("depth = %d after inner end, want 1 (no flush yet)", n.haConfigDeferDepth)
	}
	if !n.haConfigPending {
		t.Error("haConfigPending should still be true after inner endHaConfigBatch")
	}

	n.endHaConfigBatch() // depth = 0, flush fires
	if n.haConfigDeferDepth != 0 {
		t.Fatalf("depth = %d after outer end, want 0", n.haConfigDeferDepth)
	}
	if n.haConfigPending {
		t.Error("haConfigPending should be false after outer endHaConfigBatch flushed")
	}
}

// TestUpdateHaConfig_NoBatchPassesThrough verifies that without an active
// batch, updateHaConfig calls doUpdateHaConfig directly and never sets
// haConfigPending.
func TestUpdateHaConfig_NoBatchPassesThrough(t *testing.T) {
	n := newTestNxos()

	// No batch started: depth == 0.
	n.updateHaConfig()

	if n.haConfigPending {
		t.Error("haConfigPending should remain false when no batch is active")
	}
	if n.haConfigDeferDepth != 0 {
		t.Errorf("haConfigDeferDepth = %d, want 0", n.haConfigDeferDepth)
	}
}

// TestReconBatches_NoContest verifies that when no GID is contested all
// entries land in batch 2 and batch 1 is empty.
func TestReconBatches_NoContest(t *testing.T) {
	recon := map[string]ReconGid{
		"red":  {OldGid: 100, NewGid: 300},
		"blue": {OldGid: 200, NewGid: 400},
	}

	batch1, batch2 := reconBatches(recon)

	if len(batch1) != 0 {
		t.Errorf("batch1 should be empty, got %v", batch1)
	}
	if len(batch2) != 2 {
		t.Errorf("batch2 should have 2 entries, got %v", batch2)
	}
}
