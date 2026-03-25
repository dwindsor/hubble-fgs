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
	"strings"
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

// TestHaSetMbrInfo_PeerSvcFailure_MembershipStaysOk verifies that when a peer
// reports SVC_FAILURE, MembershipOk remains true because service failure is
// not a required criteria failure.
func TestHaSetMbrInfo_PeerSvcFailure_MembershipStaysOk(t *testing.T) {
	n := newTestNxos()
	n.Ha.enabled = true
	n.Ha.operUp = true
	n.Ha.IsLeader = true
	n.Model = "Nexus9000"
	n.SwVer = "10.3.1"
	n.CpaVer = "2.0.0"
	n.LbMode = model.Cisco_NX_OSDevice_Sas_LbModeType_pinning

	peer := "192.168.1.2"
	n.SetHaPeer(peer, HaPeer{})
	n.Ha.Adjacencies = map[string]HaAdj{peer: {Connected: true}}
	n.Ha.PeerCriteria[peer] = HaPeerCriteria{
		MembershipOk: true, PolicyOk: true, KeepaliveOk: true, BulkSyncOk: true,
	}

	info := hav1.MbrInfo{
		SysInfo: &hav1.SysInfo{
			Model:  n.Model,
			SwVer:  n.SwVer,
			Cpa:    n.CpaVer,
			LbMode: n.LbMode.String(),
		},
		HaInfo: &hav1.HaInfo{
			Service: hav1.SERVICE_STATE_SVC_FAILURE,
			Ha:      hav1.HA_STATE_HA_READY,
		},
		PolInfo: &hav1.PolInfo{},
	}

	result := n.HaSetMbrInfo(context.Background(), peer, info)

	if !result.IsDel {
		t.Error("IsDel should be true on peer service failure")
	}
	if result.IsRequiredCritFail {
		t.Error("IsRequiredCritFail should be false on peer service failure")
	}

	// Membership should remain OK since service failure is not a required criteria failure.
	pc := n.Ha.PeerCriteria[peer]
	if !pc.MembershipOk {
		t.Error("MembershipOk should remain true when peer reports SVC_FAILURE")
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
// when both peers are ready but HA criteria fail and HA was previously
// established (HA_READY), the leader computes TAKEOVER.
func TestDeriveAgentHaState_BothReadyPeerHAFail_LeaderTakeover(t *testing.T) {
	n := newTestNxosForHA(true)                    // leader
	n.Ha.NxStates.HaState = hav1.HA_STATE_HA_READY // was previously established
	peer := "10.0.0.2"
	n.SetHaPeer(peer, HaPeer{IpConfigOk: true})
	n.Ha.PeerSvcStates[peer] = PeerSvcReady
	n.Ha.PeerCriteria[peer] = HaPeerCriteria{MembershipOk: false} // HA fail

	// Leader should NOT get standby criteria injected (no peer in TAKEOVER).
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
// when the peer (leader) reports HA_TAKEOVER and HA criteria haven't converged,
// the follower gets standby criteria injected and computes SWITCHOVER.
func TestDeriveAgentHaState_BothReadyPeerHAFail_FollowerSwitchover(t *testing.T) {
	n := newTestNxosForHA(false) // follower
	peer := "10.0.0.2"
	n.SetHaPeer(peer, HaPeer{IpConfigOk: true})
	n.Ha.PeerSvcStates[peer] = PeerSvcReady
	n.Ha.PeerCriteria[peer] = HaPeerCriteria{MembershipOk: false} // HA fail
	// Peer (leader) reports HA_TAKEOVER — it's already the active side.
	n.Ha.Members[peer] = HaMbr{Info: hav1.MbrInfo{HaInfo: &hav1.HaInfo{
		Service: hav1.SERVICE_STATE_SVC_SUCCESS,
		Ha:      hav1.HA_STATE_HA_TAKEOVER,
	}}}

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

	// Initially: HA fail + peer reports TAKEOVER → standby injected
	n.Ha.PeerCriteria[peer] = HaPeerCriteria{MembershipOk: false}
	n.Ha.Members[peer] = HaMbr{Info: hav1.MbrInfo{HaInfo: &hav1.HaInfo{
		Service: hav1.SERVICE_STATE_SVC_SUCCESS,
		Ha:      hav1.HA_STATE_HA_TAKEOVER,
	}}}
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

// TestHaUpdateCrit_InServiceFalse_SvcFailureDerived verifies that setting
// HaCritInService=false causes stableIsFunc to return false and the derived
// HA state to reflect a service failure (HA_NOTREADY when no peer, or
// HA_SWITCHOVER when peer is ready).
func TestHaUpdateCrit_InServiceFalse_SvcFailureDerived(t *testing.T) {
	n := newTestNxosForHA(true) // leader
	peer := "10.0.0.2"
	n.SetHaPeer(peer, HaPeer{IpConfigOk: true})
	n.Ha.PeerSvcStates[peer] = PeerSvcReady
	n.Ha.PeerCriteria[peer] = HaPeerCriteria{
		MembershipOk: true, PolicyOk: true, KeepaliveOk: true, BulkSyncOk: true,
	}

	// Baseline: all criteria pass → HA_READY.
	ctx := context.Background()
	n.haUpdateNxState(ctx)
	if n.Ha.NxStates.HaState != hav1.HA_STATE_HA_READY {
		t.Fatalf("baseline state = %v, want HA_READY", n.Ha.NxStates.HaState)
	}

	// Simulate out-of-service: clear InService criterion.
	n.haUpdateCrit(ctx, HaCritInService, false)

	// Local is no longer func → SVC_FAILURE.
	if n.stableIsFunc() {
		t.Error("stableIsFunc should be false after HaCritInService=false")
	}
	// Peer is ready → local should derive HA_SWITCHOVER (standby side).
	if n.Ha.NxStates.HaState != hav1.HA_STATE_HA_SWITCHOVER {
		t.Errorf("state after InService=false = %v, want HA_SWITCHOVER", n.Ha.NxStates.HaState)
	}
}

// TestHaCheckAdjMbr_AdjTimeout_HaStateUpdated verifies that when an adjacency
// times out, the peer HA state is set to HA_FAIL and haUpdateNxState is called
// so the local derived HA state changes appropriately (e.g. HA_READY → HA_NOTREADY
// when the only peer goes unknown).
func TestHaCheckAdjMbr_AdjTimeout_HaStateUpdated(t *testing.T) {
	n := newTestNxosForHA(true) // leader
	peer := "10.0.0.2"
	n.SetHaPeer(peer, HaPeer{IpConfigOk: true})

	// Set up adjacency that is already expired.
	n.Ha.Adjacencies[peer] = HaAdj{
		Connected: true,
		Epoch:     0, // epoch=0 means it will always be expired
	}
	// Peer is ready and HA criteria pass → leader should be HA_READY.
	n.Ha.PeerSvcStates[peer] = PeerSvcReady
	n.Ha.PeerCriteria[peer] = HaPeerCriteria{
		MembershipOk: true, PolicyOk: true, KeepaliveOk: true, BulkSyncOk: true,
	}
	n.haUpdateNxState(context.Background())
	if n.Ha.NxStates.HaState != hav1.HA_STATE_HA_READY {
		t.Fatalf("baseline state = %v, want HA_READY", n.Ha.NxStates.HaState)
	}

	// Run adjacency check — should expire the adjacency and recalculate state.
	n.haCheckAdjMbr(context.Background())

	// Adjacency should be gone.
	n.RLock()
	_, adjExists := n.Ha.Adjacencies[peer]
	peerState, _ := n.GetHaPeer(peer)
	derivedState := n.Ha.NxStates.HaState
	n.RUnlock()

	if adjExists {
		t.Error("adjacency should have been removed after timeout")
	}
	if peerState.State != hav1.MBR_STATE_HA_FAIL {
		t.Errorf("peer HA state = %v, want MBR_STATE_HA_FAIL", peerState.State)
	}
	// With adjacency gone, PeerSvcStates[peer] = PeerSvcUnknown → local ready, peer unknown → HA_NOTREADY.
	if derivedState != hav1.HA_STATE_HA_NOTREADY {
		t.Errorf("derived HA state after adj timeout = %v, want HA_NOTREADY", derivedState)
	}
	// PeerCriteria must be fully reset so stale criteria don't linger.
	n.RLock()
	pc := n.Ha.PeerCriteria[peer]
	n.RUnlock()
	if pc.MembershipOk || pc.PolicyOk || pc.KeepaliveOk || pc.BulkSyncOk {
		t.Errorf("PeerCriteria should be reset after adj timeout, got %+v", pc)
	}
}

// TestDoUpdateHaConfig_StandbyKeepsFlowSync verifies that when the follower
// has HaCritHaStandby injected, the HA config still has enabled=true so that
// DPUs keep flow_sync active and bulk sync can complete.
func TestDoUpdateHaConfig_StandbyKeepsFlowSync(t *testing.T) {
	n := newTestNxosForHA(false) // follower
	n.Ha.configured = true
	n.Ha.HaIp = "10.0.0.1"
	n.SetHaPeer("10.0.0.2", HaPeer{IpConfigOk: true})

	// Inject standby criteria — stableIsFunc should be false.
	n.Ha.Local.Criteria[HaCritHaStandby] = false
	n.Ha.Local.IsFunc = n.computeIsFunc()
	if n.stableIsFunc() {
		t.Fatal("stableIsFunc should be false with standby criteria")
	}

	// InService is true, so the HA config enabled calculation should still
	// return true despite stableIsFunc being false.
	inService, ok := n.Ha.Local.Criteria[HaCritInService]
	if !ok {
		inService = true
	}
	wantEnabled := n.GetHaConfigured() && n.GetHaOperUp() && inService
	if !wantEnabled {
		t.Error("HA config enabled should be true when InService=true, even with standby criteria")
	}
}

// TestDoUpdateHaConfig_OutOfServiceDisablesFlowSync verifies that when
// HaCritInService is false, the HA config enabled calculation returns false.
func TestDoUpdateHaConfig_OutOfServiceDisablesFlowSync(t *testing.T) {
	n := newTestNxosForHA(true)
	n.Ha.configured = true
	n.Ha.HaIp = "10.0.0.1"
	n.SetHaPeer("10.0.0.2", HaPeer{IpConfigOk: true})

	// Take node out of service.
	n.Ha.Local.Criteria[HaCritInService] = false

	inService, ok := n.Ha.Local.Criteria[HaCritInService]
	if !ok {
		inService = true
	}
	wantEnabled := n.GetHaConfigured() && n.GetHaOperUp() && inService
	if wantEnabled {
		t.Error("HA config enabled should be false when InService=false")
	}
}

// TestDoUpdateHaConfig_MissingInServiceDefaultsTrue verifies that when
// HaCritInService is not present in the criteria map, enabled defaults to true.
func TestDoUpdateHaConfig_MissingInServiceDefaultsTrue(t *testing.T) {
	n := newTestNxosForHA(true)
	n.Ha.configured = true
	n.Ha.HaIp = "10.0.0.1"
	n.SetHaPeer("10.0.0.2", HaPeer{IpConfigOk: true})

	// Remove InService from criteria entirely.
	delete(n.Ha.Local.Criteria, HaCritInService)

	inService, ok := n.Ha.Local.Criteria[HaCritInService]
	if !ok {
		inService = true
	}
	wantEnabled := n.GetHaConfigured() && n.GetHaOperUp() && inService
	if !wantEnabled {
		t.Error("HA config enabled should default to true when InService criteria is absent")
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

// TestResetPeerToUnknown_ClearsAllCriteria verifies that resetPeerToUnknown
// zeroes all PeerCriteria fields and sets PeerSvcStates to unknown.
func TestResetPeerToUnknown_ClearsAllCriteria(t *testing.T) {
	n := newTestNxosForHA(true)
	peer := "10.0.0.2"
	n.SetHaPeer(peer, HaPeer{IpConfigOk: true})

	// Set all criteria passing and svc ready.
	n.Ha.PeerSvcStates[peer] = PeerSvcReady
	n.Ha.PeerCriteria[peer] = HaPeerCriteria{
		MembershipOk: true, PolicyOk: true, KeepaliveOk: true, BulkSyncOk: true,
	}

	n.Lock()
	n.resetPeerToUnknown(peer)
	n.Unlock()

	if n.Ha.PeerSvcStates[peer] != PeerSvcUnknown {
		t.Errorf("PeerSvcStates[peer] = %v, want PeerSvcUnknown", n.Ha.PeerSvcStates[peer])
	}
	pc := n.Ha.PeerCriteria[peer]
	if pc.MembershipOk || pc.PolicyOk || pc.KeepaliveOk || pc.BulkSyncOk {
		t.Errorf("PeerCriteria should be all-false after reset, got %+v", pc)
	}
}

// TestDeriveAgentHaState_StartupNoTakeover verifies that when a switch starts
// up (HA_NOTREADY) and sees a peer that is service-ready but HA criteria are
// not yet converged, it stays in HA_NOTREADY rather than going to TAKEOVER.
func TestDeriveAgentHaState_StartupNoTakeover(t *testing.T) {
	n := newTestNxosForHA(true) // leader
	// NxStates.HaState defaults to NO_HA (zero value) = not yet established
	peer := "10.0.0.2"
	n.SetHaPeer(peer, HaPeer{IpConfigOk: true})
	n.Ha.PeerSvcStates[peer] = PeerSvcReady
	n.Ha.PeerCriteria[peer] = HaPeerCriteria{MembershipOk: false} // not converged

	state := n.deriveAgentHaState()
	if state != hav1.HA_STATE_HA_NOTREADY {
		t.Errorf("Startup leader state = %v, want HA_NOTREADY (not TAKEOVER)", state)
	}
}

// TestDeriveAgentHaState_StartupNoTakeover_PeerNotReady verifies that when a
// switch starts up and peer service is not-ready, it stays in HA_NOTREADY.
func TestDeriveAgentHaState_StartupNoTakeover_PeerNotReady(t *testing.T) {
	n := newTestNxosForHA(true) // leader
	// NxStates.HaState defaults to NO_HA = not yet established
	peer := "10.0.0.2"
	n.SetHaPeer(peer, HaPeer{IpConfigOk: true})
	n.Ha.PeerSvcStates[peer] = PeerSvcNotReady

	state := n.deriveAgentHaState()
	if state != hav1.HA_STATE_HA_NOTREADY {
		t.Errorf("Startup leader state = %v, want HA_NOTREADY (not TAKEOVER)", state)
	}
}

// TestDeriveAgentHaState_EstablishedThenFailure verifies that after HA was
// established (HA_READY), a criteria failure correctly triggers TAKEOVER.
func TestDeriveAgentHaState_EstablishedThenFailure(t *testing.T) {
	n := newTestNxosForHA(true)                    // leader
	n.Ha.NxStates.HaState = hav1.HA_STATE_HA_READY // was previously active/active
	peer := "10.0.0.2"
	n.SetHaPeer(peer, HaPeer{IpConfigOk: true})
	n.Ha.PeerSvcStates[peer] = PeerSvcReady
	n.Ha.PeerCriteria[peer] = HaPeerCriteria{MembershipOk: false} // criteria failed

	state := n.deriveAgentHaState()
	if state != hav1.HA_STATE_HA_TAKEOVER {
		t.Errorf("Post-establishment failure state = %v, want HA_TAKEOVER", state)
	}
}

// TestStandbyCrit_PeerTakeover_InjectsStandby verifies that when a starting
// switch sees its peer reporting HA_TAKEOVER, standby criteria is injected.
func TestStandbyCrit_PeerTakeover_InjectsStandby(t *testing.T) {
	n := newTestNxosForHA(false) // follower (starting up)
	// NxStates.HaState is NO_HA (default), not HA_TAKEOVER
	peer := "10.0.0.2"
	n.SetHaPeer(peer, HaPeer{IpConfigOk: true})
	n.Ha.PeerSvcStates[peer] = PeerSvcReady
	n.Ha.PeerCriteria[peer] = HaPeerCriteria{MembershipOk: false} // not yet converged
	// Peer reports it is already in TAKEOVER (was the active side before restart).
	n.Ha.Members[peer] = HaMbr{Info: hav1.MbrInfo{HaInfo: &hav1.HaInfo{
		Service: hav1.SERVICE_STATE_SVC_SUCCESS,
		Ha:      hav1.HA_STATE_HA_TAKEOVER,
	}}}

	n.haEvaluateStandbyCrit()

	if v, has := n.Ha.Local.Criteria[HaCritHaStandby]; !has || v != false {
		t.Error("Expected HaCritHaStandby = false to be injected")
	}
	if n.Ha.Local.IsFunc {
		t.Error("IsFunc should be false after standby injection")
	}
}

// TestStandbyCrit_BothStartingUp_NoStandby verifies that when both switches
// are starting up (neither in TAKEOVER), no standby criteria is injected.
func TestStandbyCrit_BothStartingUp_NoStandby(t *testing.T) {
	n := newTestNxosForHA(false) // follower
	peer := "10.0.0.2"
	n.SetHaPeer(peer, HaPeer{IpConfigOk: true})
	n.Ha.PeerSvcStates[peer] = PeerSvcReady
	n.Ha.PeerCriteria[peer] = HaPeerCriteria{MembershipOk: false} // not converged
	// Peer reports HA_NOTREADY (also starting up, not TAKEOVER).
	n.Ha.Members[peer] = HaMbr{Info: hav1.MbrInfo{HaInfo: &hav1.HaInfo{
		Service: hav1.SERVICE_STATE_SVC_SUCCESS,
		Ha:      hav1.HA_STATE_HA_NOTREADY,
	}}}

	n.haEvaluateStandbyCrit()

	if _, has := n.Ha.Local.Criteria[HaCritHaStandby]; has {
		t.Error("No standby should be injected when neither peer is in TAKEOVER")
	}
}

// TestStandbyCrit_DualTakeover_LeaderWins verifies that when both switches
// are in HA_TAKEOVER (rare race), the leader does not inject standby.
func TestStandbyCrit_DualTakeover_LeaderWins(t *testing.T) {
	n := newTestNxosForHA(true) // leader
	n.Ha.NxStates.HaState = hav1.HA_STATE_HA_TAKEOVER
	peer := "10.0.0.2"
	n.SetHaPeer(peer, HaPeer{IpConfigOk: true})
	n.Ha.PeerSvcStates[peer] = PeerSvcReady
	n.Ha.PeerCriteria[peer] = HaPeerCriteria{MembershipOk: false}
	// Peer also reports TAKEOVER.
	n.Ha.Members[peer] = HaMbr{Info: hav1.MbrInfo{HaInfo: &hav1.HaInfo{
		Service: hav1.SERVICE_STATE_SVC_SUCCESS,
		Ha:      hav1.HA_STATE_HA_TAKEOVER,
	}}}

	n.haEvaluateStandbyCrit()

	if _, has := n.Ha.Local.Criteria[HaCritHaStandby]; has {
		t.Error("Leader should NOT inject standby in dual-TAKEOVER tiebreaker")
	}
}

// TestStandbyCrit_DualTakeover_FollowerYields verifies that when both switches
// are in HA_TAKEOVER, the follower yields (injects standby).
func TestStandbyCrit_DualTakeover_FollowerYields(t *testing.T) {
	n := newTestNxosForHA(false) // follower
	n.Ha.NxStates.HaState = hav1.HA_STATE_HA_TAKEOVER
	peer := "10.0.0.2"
	n.SetHaPeer(peer, HaPeer{IpConfigOk: true})
	n.Ha.PeerSvcStates[peer] = PeerSvcReady
	n.Ha.PeerCriteria[peer] = HaPeerCriteria{MembershipOk: false}
	// Peer also reports TAKEOVER.
	n.Ha.Members[peer] = HaMbr{Info: hav1.MbrInfo{HaInfo: &hav1.HaInfo{
		Service: hav1.SERVICE_STATE_SVC_SUCCESS,
		Ha:      hav1.HA_STATE_HA_TAKEOVER,
	}}}

	n.haEvaluateStandbyCrit()

	if _, has := n.Ha.Local.Criteria[HaCritHaStandby]; !has {
		t.Error("Follower should inject standby in dual-TAKEOVER tiebreaker")
	}
}

// TestDeriveAgentHaState_SwitchoverToTakeover verifies that a follower in
// HA_SWITCHOVER (standby) correctly transitions to TAKEOVER when the leader
// fails (SVC_FAILURE → PeerSvcNotReady) and standby is removed.
func TestDeriveAgentHaState_SwitchoverToTakeover(t *testing.T) {
	n := newTestNxosForHA(false) // follower, was in SWITCHOVER
	n.Ha.NxStates.HaState = hav1.HA_STATE_HA_SWITCHOVER

	// Standby is removed (leader failed, peerSvc=NotReady → shouldBeStandby=false).
	// Local IsFunc is restored.
	peer := "10.0.0.2"
	n.SetHaPeer(peer, HaPeer{IpConfigOk: true})
	n.Ha.PeerSvcStates[peer] = PeerSvcNotReady // leader failed

	state := n.deriveAgentHaState()
	if state != hav1.HA_STATE_HA_TAKEOVER {
		t.Errorf("SWITCHOVER→leader_fail state = %v, want HA_TAKEOVER", state)
	}
}

// TestShowHa_AgwKeepalive verifies the AGW Keepalive line in ShowHa output.
func TestShowHa_AgwKeepalive(t *testing.T) {
	ctx := context.Background()

	t.Run("unknown svc state shows FAIL", func(t *testing.T) {
		n := newTestNxosForHA(true)
		peer := "10.0.0.2"
		n.SetHaPeer(peer, HaPeer{IpConfigOk: true})
		n.Ha.PeerSvcStates[peer] = PeerSvcUnknown
		n.Ha.PeerCriteria[peer] = HaPeerCriteria{
			MembershipOk: true, PolicyOk: true, KeepaliveOk: true, BulkSyncOk: true,
		}

		out := n.ShowHa(ctx)
		if !strings.Contains(out, "[FAIL] AGW Keepalive") {
			t.Errorf("expected [FAIL] AGW Keepalive in output, got:\n%s", out)
		}
	})

	t.Run("ready svc with keepalive OK shows OK", func(t *testing.T) {
		n := newTestNxosForHA(true)
		peer := "10.0.0.2"
		n.SetHaPeer(peer, HaPeer{IpConfigOk: true})
		n.Ha.PeerSvcStates[peer] = PeerSvcReady
		n.Ha.PeerCriteria[peer] = HaPeerCriteria{
			MembershipOk: true, PolicyOk: true, KeepaliveOk: true, BulkSyncOk: true,
		}

		out := n.ShowHa(ctx)
		if !strings.Contains(out, "[OK] AGW Keepalive") {
			t.Errorf("expected [OK] AGW Keepalive in output, got:\n%s", out)
		}
	})
}
