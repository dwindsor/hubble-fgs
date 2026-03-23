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
	model "github.com/isovalent/hubble-fgs/pkg/nxosmodel"
	hav1 "github.com/isovalent/hubble-fgs/pkg/proto/ha/v1"

	"golang.design/x/chann"
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
	n.Ha.Members = make(map[string]HaMbr)
	n.Ha.Adjacencies = make(map[string]HaAdj)
	n.Ha.PeerSvcStates = make(map[string]PeerServiceState)
	n.Ha.PeerCriteria = make(map[string]HaPeerCriteria)
	n.Vrfs = make(map[string]VrfBd)
	n.Bds = make(map[string]VrfBd)
	n.WaitHa = chann.New[string]()
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

// TestHaSetMbrInfo_LbModeMismatch verifies that a peer reporting a different
// LB mode is rejected with IsRequiredCritFail = true.
func TestHaSetMbrInfo_LbModeMismatch(t *testing.T) {
	n := newTestNxos()
	n.Ha.enabled = true
	n.Ha.operUp = true
	n.Ha.IsLeader = true
	n.Model = "Nexus9000"
	n.SwVer = "10.3.1"
	n.CpaVer = "2.0.0"
	// Local switch uses pinning; peer reports symmetric-hash.
	n.LbMode = model.Cisco_NX_OSDevice_Sas_LbModeType_pinning

	peer := "192.168.1.2"
	n.SetHaPeer(peer, HaPeer{})
	n.Ha.Adjacencies = map[string]HaAdj{peer: {Connected: true}}

	info := hav1.MbrInfo{
		SysInfo: &hav1.SysInfo{
			Model:  n.Model,
			SwVer:  n.SwVer,
			Cpa:    n.CpaVer,
			LbMode: model.Cisco_NX_OSDevice_Sas_LbModeType_symmetric_hash.String(),
		},
		HaInfo: &hav1.HaInfo{
			Service: hav1.SERVICE_STATE_SVC_SUCCESS,
			Ha:      hav1.HA_STATE_HA_READY,
		},
		PolInfo: &hav1.PolInfo{},
	}

	result := n.HaSetMbrInfo(context.Background(), peer, info)

	if !result.IsDel {
		t.Error("IsDel should be true on LB mode mismatch")
	}
	if !result.IsRequiredCritFail {
		t.Error("IsRequiredCritFail should be true on LB mode mismatch")
	}
	if result.Reason == "" {
		t.Error("Reason should be non-empty on LB mode mismatch")
	}
}

// newTestNxosForHA returns a minimal Nxos with HA state initialized for
// deriveAgentHaState and standby criteria tests.
func newTestNxosForHA(isLeader bool) *Nxos {
	n := newTestNxos()
	n.Ha.enabled = true
	n.Ha.operUp = true
	n.Ha.IsLeader = isLeader
	n.Ha.HaIp = "10.0.0.1"
	n.Ha.Local.Criteria = map[HaCrit]bool{
		HaCritDpuHealth: true,
		HaCritDpuInSync: true,
		HaCritInService: true,
	}
	n.Ha.Local.IsFunc = true
	return n
}

// TestDeriveAgentHaState_BothReadyPeerHAFail_LeaderTakeover verifies that
// when both peers are ready but HA criteria fail, the leader computes TAKEOVER.
func TestDeriveAgentHaState_BothReadyPeerHAFail_LeaderTakeover(t *testing.T) {
	n := newTestNxosForHA(true) // leader
	peer := "10.0.0.2"
	n.SetHaPeer(peer, HaPeer{IpConfigOk: true})
	n.Ha.PeerSvcStates[peer] = PeerSvcReady
	n.Ha.PeerCriteria[peer] = HaPeerCriteria{MembershipOk: false} // HA fail

	// Leader should NOT get standby criteria injected.
	n.haEvaluateStandbyCrit()
	if _, has := n.Ha.Local.Criteria[HaCritHaStandby]; has {
		t.Error("Leader should not have HaCritHaStandby injected")
	}

	state := n.deriveAgentHaState()
	if state != hav1.HA_STATE_HA_TAKEOVER {
		t.Errorf("Leader state = %v, want HA_TAKEOVER", state)
	}
}

// TestDeriveAgentHaState_BothReadyPeerHAFail_FollowerSwitchover verifies that
// when both peers are ready but HA criteria fail, the follower gets standby
// criteria injected and computes SWITCHOVER with SVC_FAILURE.
func TestDeriveAgentHaState_BothReadyPeerHAFail_FollowerSwitchover(t *testing.T) {
	n := newTestNxosForHA(false) // follower
	peer := "10.0.0.2"
	n.SetHaPeer(peer, HaPeer{IpConfigOk: true})
	n.Ha.PeerSvcStates[peer] = PeerSvcReady
	n.Ha.PeerCriteria[peer] = HaPeerCriteria{MembershipOk: false} // HA fail

	// Follower should get standby criteria injected.
	n.haEvaluateStandbyCrit()
	if v, has := n.Ha.Local.Criteria[HaCritHaStandby]; !has || v != false {
		t.Error("Follower should have HaCritHaStandby = false")
	}
	if n.Ha.Local.IsFunc {
		t.Error("Follower IsFunc should be false after standby criteria injection")
	}

	state := n.deriveAgentHaState()
	if state != hav1.HA_STATE_HA_SWITCHOVER {
		t.Errorf("Follower state = %v, want HA_SWITCHOVER", state)
	}
}

// TestStandbyCrit_Recovery verifies that when peer HA criteria recover,
// the standby criteria is removed and the follower can return to READY.
func TestStandbyCrit_Recovery(t *testing.T) {
	n := newTestNxosForHA(false) // follower
	peer := "10.0.0.2"
	n.SetHaPeer(peer, HaPeer{IpConfigOk: true})
	n.Ha.PeerSvcStates[peer] = PeerSvcReady

	// Initially: HA fail → standby injected
	n.Ha.PeerCriteria[peer] = HaPeerCriteria{MembershipOk: false}
	n.haEvaluateStandbyCrit()
	if _, has := n.Ha.Local.Criteria[HaCritHaStandby]; !has {
		t.Fatal("Expected standby criteria to be injected")
	}

	// Recovery: all peer criteria pass
	n.Ha.PeerCriteria[peer] = HaPeerCriteria{
		MembershipOk: true,
		PolicyOk:     true,
		KeepaliveOk:  true,
		BulkSyncOk:   true,
	}
	n.haEvaluateStandbyCrit()
	if _, has := n.Ha.Local.Criteria[HaCritHaStandby]; has {
		t.Error("Standby criteria should be removed after peer recovery")
	}
	if !n.Ha.Local.IsFunc {
		t.Error("IsFunc should be true after standby criteria removal")
	}

	state := n.deriveAgentHaState()
	if state != hav1.HA_STATE_HA_READY {
		t.Errorf("Follower state after recovery = %v, want HA_READY", state)
	}
}

// TestHaHandleNotify_LeaderTakeover verifies that when the follower receives
// a Notify with HA_TAKEOVER from the leader, the standby criteria injection
// is transient — haEvaluateStandbyCrit removes it when peer HA criteria are healthy.
func TestHaHandleNotify_LeaderTakeover(t *testing.T) {
	n := newTestNxosForHA(false) // follower
	n.Ha.NxStates.HaState = hav1.HA_STATE_HA_READY
	peer := "10.0.0.2"
	n.SetHaPeer(peer, HaPeer{IpConfigOk: true})
	n.Ha.PeerSvcStates[peer] = PeerSvcReady
	n.Ha.PeerCriteria[peer] = HaPeerCriteria{MembershipOk: true, PolicyOk: true, KeepaliveOk: true, BulkSyncOk: true}

	haInfo := &hav1.HaInfo{
		Service: hav1.SERVICE_STATE_SVC_SUCCESS,
		Ha:      hav1.HA_STATE_HA_TAKEOVER,
	}
	resp := n.HaHandleNotify(context.Background(), peer, haInfo)

	if _, has := n.Ha.Local.Criteria[HaCritHaStandby]; has {
		t.Error("Expected standby criteria to be removed by haEvaluateStandbyCrit")
	}
	if resp.Ha != hav1.HA_STATE_HA_READY {
		t.Errorf("Response HA state = %v, want HA_READY", resp.Ha)
	}
	if resp.Service != hav1.SERVICE_STATE_SVC_SUCCESS {
		t.Errorf("Response service state = %v, want SVC_SUCCESS", resp.Service)
	}
}

// TestHaHandleNotify_Recovery verifies that when the follower receives
// a Notify with HA_READY, it removes the standby criteria.
func TestHaHandleNotify_Recovery(t *testing.T) {
	n := newTestNxosForHA(false) // follower
	peer := "10.0.0.2"
	n.SetHaPeer(peer, HaPeer{IpConfigOk: true})
	n.Ha.PeerSvcStates[peer] = PeerSvcReady
	n.Ha.PeerCriteria[peer] = HaPeerCriteria{MembershipOk: true, PolicyOk: true, KeepaliveOk: true, BulkSyncOk: true}

	// Pre-inject standby criteria
	n.Ha.Local.Criteria[HaCritHaStandby] = false
	n.Ha.Local.IsFunc = false

	haInfo := &hav1.HaInfo{
		Service: hav1.SERVICE_STATE_SVC_SUCCESS,
		Ha:      hav1.HA_STATE_HA_READY,
	}
	resp := n.HaHandleNotify(context.Background(), peer, haInfo)

	if _, has := n.Ha.Local.Criteria[HaCritHaStandby]; has {
		t.Error("Standby criteria should be removed after recovery Notify")
	}
	if resp.Ha != hav1.HA_STATE_HA_READY {
		t.Errorf("Response HA state = %v, want HA_READY", resp.Ha)
	}
	if resp.Service != hav1.SERVICE_STATE_SVC_SUCCESS {
		t.Errorf("Response service state = %v, want SVC_SUCCESS", resp.Service)
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
