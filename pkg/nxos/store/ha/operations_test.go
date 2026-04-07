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
	"fmt"
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/mock"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
	"github.com/isovalent/hubble-fgs/pkg/nxos/storage"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

func TestSetLocalDerivedStates_SetsHaStateAndReasonViaGnmi(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	store := NewStore(ctx, WithGnmiHandler(handler)).(*haStore)
	store.enabled = AdminStateEnabled
	store.switchState = SwitchStateHaReady

	reason := types.NewReasonString("local criteria not met")
	store.SetLocalDerivedStates(ctx, types.HAStateNotReady, types.SvcStateFailure, reason, reason, true)

	// Verify store state
	local := store.Local()
	if local.HaState != types.HAStateNotReady {
		t.Errorf("expected HaState %q, got %q", types.HAStateNotReady, local.HaState)
	}
	if local.HaStateReason != reason {
		t.Errorf("expected HaStateReason %q, got %q", reason, local.HaStateReason)
	}

	// Verify gNMI SET was called for both state and reason
	data := handler.GetAllData()
	stateKey := normalizeMockPath(paths.HAStoreLocalHaState)
	if v, ok := data[stateKey]; !ok || v != types.HAStateNotReady {
		t.Errorf("expected gNMI SET for HAStoreLocalHaState=%q, got %v (found=%v)", types.HAStateNotReady, v, ok)
	}
	reasonKey := normalizeMockPath(paths.HAStoreLocalHaStateReason)
	if v, ok := data[reasonKey]; !ok || v != reason.String() {
		t.Errorf("expected gNMI SET for HAStoreLocalHaStateReason=%q, got %v (found=%v)", reason, v, ok)
	}
}

func TestSetLocalDerivedStates_SetsSvcStateAndReasonViaGnmi(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	store := NewStore(ctx, WithGnmiHandler(handler)).(*haStore)

	reason := types.NewReasonString("local criteria not met")
	store.SetLocalDerivedStates(ctx, types.HAStateNotReady, types.SvcStateFailure, reason, reason, true)

	local := store.Local()
	if local.SvcState != types.SvcStateFailure {
		t.Errorf("expected SvcState %q, got %q", types.SvcStateFailure, local.SvcState)
	}
	if local.SvcStateReason != reason {
		t.Errorf("expected SvcStateReason %q, got %q", reason, local.SvcStateReason)
	}

	data := handler.GetAllData()
	stateKey := normalizeMockPath(paths.HAStoreLocalSvcState)
	if v, ok := data[stateKey]; !ok || v != types.SvcStateFailure {
		t.Errorf("expected gNMI SET for HAStoreLocalSvcState=%q, got %v (found=%v)", types.SvcStateFailure, v, ok)
	}
	reasonKey := normalizeMockPath(paths.HAStoreLocalSvcStateReason)
	if v, ok := data[reasonKey]; !ok || v != reason.String() {
		t.Errorf("expected gNMI SET for HAStoreLocalSvcStateReason=%q, got %v (found=%v)", reason, v, ok)
	}
}

func TestSetLocalDerivedStates_SuccessHasEmptyReasonViaGnmi(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	store := NewStore(ctx, WithGnmiHandler(handler)).(*haStore)
	store.enabled = AdminStateEnabled
	store.switchState = SwitchStateHaReady

	store.SetLocalDerivedStates(ctx, types.HAStateReady, types.SvcStateSuccess, "", "", true)

	local := store.Local()
	if local.SvcStateReason != "" {
		t.Errorf("expected empty SvcStateReason for success, got %q", local.SvcStateReason)
	}

	data := handler.GetAllData()
	reasonKey := normalizeMockPath(paths.HAStoreLocalSvcStateReason)
	if v, ok := data[reasonKey]; !ok || v != "" {
		t.Errorf("expected gNMI SET for empty reason, got %v (found=%v)", v, ok)
	}
}

func TestSetLocalHaStateToNotReady_SetsReasonViaGnmi(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	store := NewStore(ctx, WithGnmiHandler(handler)).(*haStore)
	store.enabled = AdminStateEnabled
	store.switchState = SwitchStateHaReady

	reason := types.NewReasonString("local criteria not met")
	err := store.SetLocalHaStateToNotReady(ctx, reason)
	if err != nil {
		t.Fatalf("SetLocalHaStateToNotReady failed: %v", err)
	}

	local := store.Local()
	if local.HaState != types.HAStateNotReady {
		t.Errorf("expected HaState %q, got %q", types.HAStateNotReady, local.HaState)
	}

	data := handler.GetAllData()
	reasonKey := normalizeMockPath(paths.HAStoreLocalHaStateReason)
	if v, ok := data[reasonKey]; !ok || v != reason.String() {
		t.Errorf("expected gNMI SET for reason=%q, got %v (found=%v)", reason, v, ok)
	}
}

func TestSetLocalSvcStateToFailure_SetsReasonViaGnmi(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	store := NewStore(ctx, WithGnmiHandler(handler)).(*haStore)

	reason := types.NewReasonString("local criteria not met")
	err := store.SetLocalSvcStateToFailure(ctx, reason)
	if err != nil {
		t.Fatalf("SetLocalSvcStateToFailure failed: %v", err)
	}

	local := store.Local()
	if local.SvcState != types.SvcStateFailure {
		t.Errorf("expected SvcState %q, got %q", types.SvcStateFailure, local.SvcState)
	}

	data := handler.GetAllData()
	reasonKey := normalizeMockPath(paths.HAStoreLocalSvcStateReason)
	if v, ok := data[reasonKey]; !ok || v != reason.String() {
		t.Errorf("expected gNMI SET for reason=%q, got %v (found=%v)", reason, v, ok)
	}
}

func TestUpdatePeerSvcState_SetsStateAndReasonViaGnmi(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	store := NewStore(ctx, WithGnmiHandler(handler)).(*haStore)
	store.enabled = AdminStateEnabled
	store.switchState = SwitchStateHaReady

	peerIP := "10.0.0.2"
	store.SetPeer(ctx, peerIP, types.HAPeerState{IP: peerIP})

	reason := types.NewReasonString("peer service failure")
	store.UpdatePeerSvcState(ctx, peerIP, types.SvcStateFailure, reason)

	data := handler.GetAllData()
	statePath := normalizeMockPath(fmt.Sprintf(paths.HAStorePeerSvcState, peerIP))
	if v, ok := data[statePath]; !ok || v != types.SvcStateFailure {
		t.Errorf("expected gNMI SET for peer svcState=%q, got %v (found=%v)", types.SvcStateFailure, v, ok)
	}
	reasonPath := normalizeMockPath(fmt.Sprintf(paths.HAStorePeerSvcStateReason, peerIP))
	if v, ok := data[reasonPath]; !ok || v != reason.String() {
		t.Errorf("expected gNMI SET for peer svcStateReason=%q, got %v (found=%v)", reason, v, ok)
	}
}

func TestUpdatePeerHaState_SetsStateAndReasonViaGnmi(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	store := NewStore(ctx, WithGnmiHandler(handler)).(*haStore)
	store.enabled = AdminStateEnabled
	store.switchState = SwitchStateHaReady

	peerIP := "10.0.0.3"
	store.SetPeer(ctx, peerIP, types.HAPeerState{IP: peerIP})

	reason := types.NewReasonString("membership failure: peer_compatible")
	store.UpdatePeerHaState(ctx, peerIP, types.PeerHAStateFail, reason)

	data := handler.GetAllData()
	statePath := normalizeMockPath(fmt.Sprintf(paths.HAStorePeerHaState, peerIP))
	if v, ok := data[statePath]; !ok || v != types.PeerHAStateFail {
		t.Errorf("expected gNMI SET for peer haState=%q, got %v (found=%v)", types.PeerHAStateFail, v, ok)
	}
	reasonPath := normalizeMockPath(fmt.Sprintf(paths.HAStorePeerHaStateReason, peerIP))
	if v, ok := data[reasonPath]; !ok || v != reason.String() {
		t.Errorf("expected gNMI SET for peer haStateReason=%q, got %v (found=%v)", reason, v, ok)
	}
}

func TestSetRemoteStatesAdjDown_SetsReasonsViaGnmi(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	store := NewStore(ctx, WithGnmiHandler(handler)).(*haStore)
	store.enabled = AdminStateEnabled
	store.switchState = SwitchStateHaReady

	peerIP := "10.0.0.4"
	store.SetPeer(ctx, peerIP, types.HAPeerState{IP: peerIP})
	err := store.SetRemoteStatesAdjDown(ctx, peerIP)
	if err != nil {
		t.Fatalf("SetRemoteStatesAdjDown failed: %v", err)
	}

	data := handler.GetAllData()
	// Check peer HA state set to no-ha
	haStatePath := normalizeMockPath(fmt.Sprintf(paths.HAStorePeerHaState, peerIP))
	if v, ok := data[haStatePath]; !ok || v != types.PeerHAStateNoHa {
		t.Errorf("expected gNMI SET for peer haState=%q, got %v (found=%v)", types.PeerHAStateNoHa, v, ok)
	}
	haReasonPath := normalizeMockPath(fmt.Sprintf(paths.HAStorePeerHaStateReason, peerIP))
	if v, ok := data[haReasonPath]; !ok || v != "adjacency down" {
		t.Errorf("expected gNMI SET for peer haStateReason=%q, got %v (found=%v)", "adjacency down", v, ok)
	}
	// Check peer SVC state set to unknown
	svcReasonPath := normalizeMockPath(fmt.Sprintf(paths.HAStorePeerSvcStateReason, peerIP))
	if v, ok := data[svcReasonPath]; !ok || v != "adjacency down" {
		t.Errorf("expected gNMI SET for peer svcStateReason=%q, got %v (found=%v)", "adjacency down", v, ok)
	}
}

func TestSetLocalDerivedStates_SwitchNotReady_SkipsHaGnmi_PushesSvc(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	store := NewStore(ctx, WithGnmiHandler(handler)).(*haStore)
	// switchState is "" (not "ha-ready") — switch HA container is not up.

	reason := types.NewReasonString("criteria not met")
	store.SetLocalDerivedStates(ctx, types.HAStateNotReady, types.SvcStateFailure, reason, reason, true)

	// Store state should be updated regardless.
	local := store.Local()
	if local.HaState != types.HAStateNotReady {
		t.Errorf("expected HaState %q, got %q", types.HAStateNotReady, local.HaState)
	}
	if local.SvcState != types.SvcStateFailure {
		t.Errorf("expected SvcState %q, got %q", types.SvcStateFailure, local.SvcState)
	}

	data := handler.GetAllData()
	// HA state should NOT be written to gNMI when switch is not in ha-ready.
	haStateKey := normalizeMockPath(paths.HAStoreLocalHaState)
	if _, ok := data[haStateKey]; ok {
		t.Error("expected NO gNMI SET for HAStoreLocalHaState when switch not ha-ready")
	}
	haReasonKey := normalizeMockPath(paths.HAStoreLocalHaStateReason)
	if _, ok := data[haReasonKey]; ok {
		t.Error("expected NO gNMI SET for HAStoreLocalHaStateReason when switch not ha-ready")
	}

	// SVC state SHOULD still be written to gNMI.
	svcStateKey := normalizeMockPath(paths.HAStoreLocalSvcState)
	if v, ok := data[svcStateKey]; !ok || v != types.SvcStateFailure {
		t.Errorf("expected gNMI SET for HAStoreLocalSvcState=%q, got %v (found=%v)", types.SvcStateFailure, v, ok)
	}
}

func TestSetLocalDerivedStates_SuccessHasEmptyReasons(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	store.SetLocalDerivedStates(ctx, types.HAStateReady, types.SvcStateSuccess, "", "", true)

	local := store.Local()
	if local.HaStateReason != "" {
		t.Errorf("expected empty HaStateReason for success, got %q", local.HaStateReason)
	}
	if local.SvcStateReason != "" {
		t.Errorf("expected empty SvcStateReason for success, got %q", local.SvcStateReason)
	}
}

func TestSetLocalDerivedStates_FailureHasReasons(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	haReason := types.NewReasonString("local criteria not met")
	svcReason := types.NewReasonString("local criteria not met")
	store.SetLocalDerivedStates(ctx, types.HAStateNotReady, types.SvcStateFailure, haReason, svcReason, true)

	local := store.Local()
	if local.HaStateReason != haReason {
		t.Errorf("expected HaStateReason %q, got %q", haReason, local.HaStateReason)
	}
	if local.SvcStateReason != svcReason {
		t.Errorf("expected SvcStateReason %q, got %q", svcReason, local.SvcStateReason)
	}
}

func TestUpdatePeerSvcState_FailureHasReason(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	peerIP := "10.0.0.5"
	store.SetPeer(ctx, peerIP, types.HAPeerState{IP: peerIP})

	reason := types.NewReasonString("heartbeat timeout")
	store.UpdatePeerSvcState(ctx, peerIP, types.SvcStateFailure, reason)

	peer, ok := store.Peer(peerIP)
	if !ok {
		t.Fatal("expected peer to exist")
	}
	if peer.SvcState != types.SvcStateFailure {
		t.Errorf("expected SvcState %q, got %q", types.SvcStateFailure, peer.SvcState)
	}
	if peer.SvcStateReason != reason {
		t.Errorf("expected SvcStateReason %q, got %q", reason, peer.SvcStateReason)
	}
}

func TestUpdatePeerSvcState_SuccessHasEmptyReason(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	peerIP := "10.0.0.6"
	store.SetPeer(ctx, peerIP, types.HAPeerState{IP: peerIP})

	store.UpdatePeerSvcState(ctx, peerIP, types.SvcStateSuccess, "")

	peer, ok := store.Peer(peerIP)
	if !ok {
		t.Fatal("expected peer to exist")
	}
	if peer.SvcState != types.SvcStateSuccess {
		t.Errorf("expected SvcState %q, got %q", types.SvcStateSuccess, peer.SvcState)
	}
	if peer.SvcStateReason != "" {
		t.Errorf("expected empty SvcStateReason for success, got %q", peer.SvcStateReason)
	}
}

func TestSetLocalDerivedStates_PushSvcToNxFalse_SkipsSvcGnmi(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	store := NewStore(ctx, WithGnmiHandler(handler)).(*haStore)
	store.enabled = AdminStateEnabled
	store.switchState = SwitchStateHaReady

	reason := types.NewReasonString("local criteria not met")
	store.SetLocalDerivedStates(ctx, types.HAStateNotReady, types.SvcStateFailure, reason, reason, false)

	// Store state should still be updated.
	local := store.Local()
	if local.SvcState != types.SvcStateFailure {
		t.Errorf("expected SvcState %q, got %q", types.SvcStateFailure, local.SvcState)
	}

	// HA state should be written to gNMI.
	data := handler.GetAllData()
	haStateKey := normalizeMockPath(paths.HAStoreLocalHaState)
	if v, ok := data[haStateKey]; !ok || v != types.HAStateNotReady {
		t.Errorf("expected gNMI SET for HAStoreLocalHaState=%q, got %v (found=%v)", types.HAStateNotReady, v, ok)
	}

	// Svc state should NOT be written to gNMI.
	svcStateKey := normalizeMockPath(paths.HAStoreLocalSvcState)
	if _, ok := data[svcStateKey]; ok {
		t.Error("expected NO gNMI SET for HAStoreLocalSvcState when pushSvcToNx=false")
	}
}

func TestSetLocalDerivedStates_NoHandler_NoError(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	store.SetLocalDerivedStates(ctx, types.HAStateReady, types.SvcStateSuccess, "", "", true)

	local := store.Local()
	if local.HaState != types.HAStateReady {
		t.Errorf("expected HaState %q, got %q", types.HAStateReady, local.HaState)
	}
	if local.HaStateReason != "" {
		t.Errorf("expected empty HaStateReason for success, got %q", local.HaStateReason)
	}
}

func TestSetLocalDerivedStates_SvcStateWrittenBeforeHaState(t *testing.T) {
	ctx := context.Background()
	persistPath := t.TempDir() + "/mock_gnmi.json"
	handler := mock.NewHandlerBuilder().WithPersistPath(persistPath).Build()
	store := NewStore(ctx, WithGnmiHandler(handler)).(*haStore)
	store.enabled = AdminStateEnabled
	store.switchState = SwitchStateHaReady

	reason := types.NewReasonString("test reason")
	store.SetLocalDerivedStates(ctx, types.HAStateNotReady, types.SvcStateFailure, reason, reason, true)

	entries, err := handler.TxLog().ReadEntries("", "", "set")
	if err != nil {
		t.Fatalf("failed to read tx log: %v", err)
	}

	var svcStateIdx, haStateIdx int = -1, -1
	for i, entry := range entries {
		normPath := normalizeMockPath(entry.Path)
		if normPath == normalizeMockPath(paths.HAStoreLocalSvcState) {
			svcStateIdx = i
		}
		if normPath == normalizeMockPath(paths.HAStoreLocalHaState) {
			haStateIdx = i
		}
	}

	if svcStateIdx == -1 {
		t.Fatal("expected gNMI SET for localSvcState not found in tx log")
	}
	if haStateIdx == -1 {
		t.Fatal("expected gNMI SET for agentHaState not found in tx log")
	}
	if svcStateIdx >= haStateIdx {
		t.Errorf("expected localSvcState (idx %d) to be written before agentHaState (idx %d)", svcStateIdx, haStateIdx)
	}
}

func TestUpdatePeerMemberCriterion_ComputesMet(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)
	peerIP := "10.0.0.10"
	store.SetPeer(ctx, peerIP, types.HAPeerState{IP: peerIP})

	// Single criterion set to true → Met becomes true, epoch set.
	store.UpdatePeerMemberCriterion(ctx, peerIP, types.HACritPeerCompatible, true)
	peer, _ := store.Peer(peerIP)
	if !peer.MemberCriteriaMet {
		t.Error("expected MemberCriteriaMet=true after all criteria pass")
	}
	if peer.MemberCriteriaMetEpoch == 0 {
		t.Error("expected MemberCriteriaMetEpoch to be set when Met becomes true")
	}
	// Criterion flipped to false → Met becomes false, epoch remains set.
	store.UpdatePeerMemberCriterion(ctx, peerIP, types.HACritPeerCompatible, false)
	peer, _ = store.Peer(peerIP)
	if peer.MemberCriteriaMet {
		t.Error("expected MemberCriteriaMet=false after criterion fails")
	}
	if peer.MemberCriteriaMetEpoch == 0 {
		t.Error("expected MemberCriteriaMetEpoch to remain set after Met changes to false")
	}
}

func TestUpdatePeerAdjacencyCriterion_ComputesMet(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)
	peerIP := "10.0.0.11"
	store.SetPeer(ctx, peerIP, types.HAPeerState{IP: peerIP})

	// First criterion passes — two criteria exist, second not yet set → not all ok.
	store.UpdatePeerAdjacencyCriterion(ctx, peerIP, types.HACritPeerDPUBulkSync, true)
	store.UpdatePeerAdjacencyCriterion(ctx, peerIP, types.HACritPeerPolicy, false)
	peer, _ := store.Peer(peerIP)
	if peer.AdjacencyCriteriaMet {
		t.Error("expected AdjacencyCriteriaMet=false when one criterion fails")
	}

	// Both criteria now pass → Met becomes true.
	store.UpdatePeerAdjacencyCriterion(ctx, peerIP, types.HACritPeerPolicy, true)
	peer, _ = store.Peer(peerIP)
	if !peer.AdjacencyCriteriaMet {
		t.Error("expected AdjacencyCriteriaMet=true after all criteria pass")
	}
	if peer.AdjacencyCriteriaMetEpoch == 0 {
		t.Error("expected AdjacencyCriteriaMetEpoch to be set when Met becomes true")
	}

	// One criterion fails again → Met reverts to false.
	store.UpdatePeerAdjacencyCriterion(ctx, peerIP, types.HACritPeerDPUBulkSync, false)
	peer, _ = store.Peer(peerIP)
	if peer.AdjacencyCriteriaMet {
		t.Error("expected AdjacencyCriteriaMet=false after criterion fails")
	}
}

func TestRemovePeerMemberCriterion(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)
	peerIP := "10.0.0.20"
	store.SetPeer(ctx, peerIP, types.HAPeerState{IP: peerIP})

	// Set criterion to false (injected failure), then remove it.
	store.UpdatePeerMemberCriterion(ctx, peerIP, types.HACritDebugMembershipFail, false)
	peer, _ := store.Peer(peerIP)
	if peer.MemberCriteriaMet {
		t.Error("expected MemberCriteriaMet=false with debug criterion set to false")
	}

	store.RemovePeerMemberCriterion(ctx, peerIP, types.HACritDebugMembershipFail)
	peer, _ = store.Peer(peerIP)
	if _, exists := peer.MemberCriteria[types.HACritDebugMembershipFail]; exists {
		t.Error("expected debug criterion to be removed from MemberCriteria")
	}

	// No-op when criterion doesn't exist.
	store.RemovePeerMemberCriterion(ctx, peerIP, types.HACritDebugMembershipFail)

	// No-op when peer doesn't exist.
	store.RemovePeerMemberCriterion(ctx, "1.2.3.4", types.HACritDebugMembershipFail)
}

func TestRemovePeerAdjacencyCriterion(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)
	peerIP := "10.0.0.21"
	store.SetPeer(ctx, peerIP, types.HAPeerState{IP: peerIP})

	// Set criterion to false (injected failure), then remove it.
	store.UpdatePeerAdjacencyCriterion(ctx, peerIP, types.HACritDebugAdjacencyFail, false)
	peer, _ := store.Peer(peerIP)
	if peer.AdjacencyCriteriaMet {
		t.Error("expected AdjacencyCriteriaMet=false with debug criterion set to false")
	}

	store.RemovePeerAdjacencyCriterion(ctx, peerIP, types.HACritDebugAdjacencyFail)
	peer, _ = store.Peer(peerIP)
	if _, exists := peer.AdjacencyCriteria[types.HACritDebugAdjacencyFail]; exists {
		t.Error("expected debug criterion to be removed from AdjacencyCriteria")
	}

	// No-op when criterion doesn't exist.
	store.RemovePeerAdjacencyCriterion(ctx, peerIP, types.HACritDebugAdjacencyFail)

	// No-op when peer doesn't exist.
	store.RemovePeerAdjacencyCriterion(ctx, "1.2.3.4", types.HACritDebugAdjacencyFail)
}

func TestUpdatePeerServiceCriterion_ComputesMet(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)
	peerIP := "10.0.0.22"
	store.SetPeer(ctx, peerIP, types.HAPeerState{IP: peerIP})

	// Set peer_service false → ServiceCriteriaMet=false.
	store.UpdatePeerServiceCriterion(ctx, peerIP, types.HACritPeerService, false)
	peer, _ := store.Peer(peerIP)
	if peer.ServiceCriteriaMet {
		t.Error("expected ServiceCriteriaMet=false when criterion fails")
	}

	// Set peer_service true → ServiceCriteriaMet=true.
	store.UpdatePeerServiceCriterion(ctx, peerIP, types.HACritPeerService, true)
	peer, _ = store.Peer(peerIP)
	if !peer.ServiceCriteriaMet {
		t.Error("expected ServiceCriteriaMet=true after criterion passes")
	}
	if peer.ServiceCriteriaMetEpoch == 0 {
		t.Error("expected ServiceCriteriaMetEpoch to be set when Met becomes true")
	}

	// Verify peer_service is NOT in AdjacencyCriteria.
	if _, exists := peer.AdjacencyCriteria[types.HACritPeerService]; exists {
		t.Error("expected peer_service to not be in AdjacencyCriteria")
	}

	// No-op when peer doesn't exist.
	store.UpdatePeerServiceCriterion(ctx, "1.2.3.4", types.HACritPeerService, true)
}

func TestRemovePeerServiceCriterion(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)
	peerIP := "10.0.0.23"
	store.SetPeer(ctx, peerIP, types.HAPeerState{IP: peerIP})

	store.UpdatePeerServiceCriterion(ctx, peerIP, types.HACritPeerService, false)
	peer, _ := store.Peer(peerIP)
	if peer.ServiceCriteriaMet {
		t.Error("expected ServiceCriteriaMet=false with criterion set to false")
	}

	store.RemovePeerServiceCriterion(ctx, peerIP, types.HACritPeerService)
	peer, _ = store.Peer(peerIP)
	if _, exists := peer.ServiceCriteria[types.HACritPeerService]; exists {
		t.Error("expected peer_service criterion to be removed from ServiceCriteria")
	}

	// No-op when criterion doesn't exist.
	store.RemovePeerServiceCriterion(ctx, peerIP, types.HACritPeerService)

	// No-op when peer doesn't exist.
	store.RemovePeerServiceCriterion(ctx, "1.2.3.4", types.HACritPeerService)
}

func TestSetPeer_ComputesMetFromMaps(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)
	peerIP := "10.0.0.12"

	// Pre-populate criteria that are all true → SetPeer should compute Met=true.
	store.SetPeer(ctx, peerIP, types.HAPeerState{
		IP:            peerIP,
		IpConfigState: PeerIpCfgStateSuccess,
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible: true,
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: true,
		},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerDPUBulkSync: true,
		},
	})

	peer, ok := store.Peer(peerIP)
	if !ok {
		t.Fatal("expected peer to exist")
	}
	if !peer.MemberCriteriaMet {
		t.Error("expected MemberCriteriaMet=true from pre-populated passing criteria")
	}
	if peer.MemberCriteriaMetEpoch == 0 {
		t.Error("expected MemberCriteriaMetEpoch to be set")
	}
	if !peer.ServiceCriteriaMet {
		t.Error("expected ServiceCriteriaMet=true from pre-populated passing criteria")
	}
	if peer.ServiceCriteriaMetEpoch == 0 {
		t.Error("expected ServiceCriteriaMetEpoch to be set")
	}
	if !peer.AdjacencyCriteriaMet {
		t.Error("expected AdjacencyCriteriaMet=true from pre-populated passing criteria")
	}
	if peer.AdjacencyCriteriaMetEpoch == 0 {
		t.Error("expected AdjacencyCriteriaMetEpoch to be set")
	}

	// Pre-populated with a failing criterion → Met=false.
	store.SetPeer(ctx, peerIP, types.HAPeerState{
		IP: peerIP,
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible: false,
		},
	})
	peer, _ = store.Peer(peerIP)
	if peer.MemberCriteriaMet {
		t.Error("expected MemberCriteriaMet=false when criterion is false")
	}

	// Empty criteria map on a fresh peer → Met=false (vacuous AllOk guard).
	// Use a different peer IP so there is no existing state to preserve.
	freshPeerIP := "10.0.0.99"
	store.SetPeer(ctx, freshPeerIP, types.HAPeerState{IP: freshPeerIP})
	freshPeer, _ := store.Peer(freshPeerIP)
	if freshPeer.MemberCriteriaMet {
		t.Error("expected MemberCriteriaMet=false for empty criteria map")
	}
	if freshPeer.AdjacencyCriteriaMet {
		t.Error("expected AdjacencyCriteriaMet=false for empty criteria map")
	}

	// When SetPeer is called without IpConfigState on an existing peer
	// that had IpConfigState set, the value is preserved.
	store.SetPeer(ctx, peerIP, types.HAPeerState{IP: peerIP})
	peer, _ = store.Peer(peerIP)
	if peer.IpConfigState != PeerIpCfgStateSuccess {
		t.Errorf("expected IpConfigState to be preserved from existing peer, got %q", peer.IpConfigState)
	}
}

func TestUpdatePeerConnected_Disconnect_ClearsConnectionCriteria(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)
	peerIP := "10.0.0.20"

	// Set peer with all connection-managed criteria true and connected.
	store.SetPeer(ctx, peerIP, types.HAPeerState{
		IP:            peerIP,
		Connected:     true,
		IpConfigState: PeerIpCfgStateSuccess,
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible: true,
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: true,
		},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerPolicy: true,
		},
	})

	store.UpdatePeerConnected(ctx, peerIP, false, 0)

	peer, ok := store.Peer(peerIP)
	if !ok {
		t.Fatal("expected peer to exist")
	}
	if peer.Connected {
		t.Error("expected Connected=false after disconnect")
	}
	if peer.MemberCriteria[types.HACritPeerCompatible] {
		t.Error("expected MemberCriteria[peer_compatible]=false after disconnect")
	}
	if peer.MemberCriteriaMet {
		t.Error("expected MemberCriteriaMet=false after disconnect")
	}
	if peer.ServiceCriteria[types.HACritPeerService] {
		t.Error("expected ServiceCriteria[peer_service]=false after disconnect")
	}
	if peer.ServiceCriteriaMet {
		t.Error("expected ServiceCriteriaMet=false after disconnect")
	}
	if peer.AdjacencyCriteria[types.HACritPeerPolicy] {
		t.Error("expected AdjacencyCriteria[peer_policy]=false after disconnect")
	}
	if peer.AdjacencyCriteriaMet {
		t.Error("expected AdjacencyCriteriaMet=false after disconnect")
	}
	// IpConfigState must be preserved — it's on the peer struct, not in criteria.
	if peer.IpConfigState != PeerIpCfgStateSuccess {
		t.Errorf("expected IpConfigState='success' (preserved) after disconnect, got %q", peer.IpConfigState)
	}
	// AnyPeerMemberCriteriaFail should return true (map has entries, all false).
	if !store.AnyPeerMemberCriteriaFail() {
		t.Error("expected AnyPeerMemberCriteriaFail()=true after disconnect clears criteria")
	}
}

func TestSetHaPort_SetsFieldAndCallsGnmiSet(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	store := NewStore(ctx, WithGnmiHandler(handler)).(*haStore)

	const testPort uint16 = 28416
	err := store.SetHaPort(ctx, testPort)
	if err != nil {
		t.Fatalf("SetHaPort failed: %v", err)
	}

	// Verify store field updated.
	if got := store.HaPort(); got != testPort {
		t.Errorf("expected HaPort()=%d, got %d", testPort, got)
	}

	// Verify gNMI SET was called with the port as a decimal string.
	data := handler.GetAllData()
	key := normalizeMockPath(paths.HAStoreHaPort)
	want := fmt.Sprintf("%d", testPort)
	if v, ok := data[key]; !ok || v != want {
		t.Errorf("expected gNMI SET for HAStoreHaPort=%q, got %v (found=%v)", want, v, ok)
	}
}

func TestSetHaPort_PersistsToStorage(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemoryStorage()
	store := NewStore(ctx, WithStorage(mem)).(*haStore)

	const testPort uint16 = 28416
	if err := store.SetHaPort(ctx, testPort); err != nil {
		t.Fatalf("SetHaPort failed: %v", err)
	}

	state, err := mem.LoadHA(ctx)
	if err != nil {
		t.Fatalf("LoadHA failed: %v", err)
	}
	if state.HaPort != testPort {
		t.Errorf("expected persisted HaPort=%d, got %d", testPort, state.HaPort)
	}
}

func TestNewStore_LoadsHaPortFromStorage(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemoryStorage()

	const testPort uint16 = 28416
	if err := mem.SaveHA(ctx, &storage.HAState{HaPort: testPort}); err != nil {
		t.Fatalf("SaveHA failed: %v", err)
	}

	store := NewStore(ctx, WithStorage(mem))
	if got := store.HaPort(); got != testPort {
		t.Errorf("expected HaPort()=%d after load, got %d", testPort, got)
	}
}

func TestSetHaPort_NoGnmiHandler(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	// Without a gNMI handler, SetHaPort should succeed silently.
	if err := store.SetHaPort(ctx, 28416); err != nil {
		t.Errorf("expected no error without gNMI handler, got %v", err)
	}
}

func TestRemoveLocalCriterion(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	// Set a criterion, then remove it.
	store.UpdateLocalCriterion(ctx, types.HACritHaStandby, false)
	local := store.Local()
	if _, has := local.Criteria[types.HACritHaStandby]; !has {
		t.Fatal("expected HACritHaStandby to exist after UpdateLocalCriterion")
	}

	store.RemoveLocalCriterion(ctx, types.HACritHaStandby)
	local = store.Local()
	if _, has := local.Criteria[types.HACritHaStandby]; has {
		t.Error("expected HACritHaStandby to be removed after RemoveLocalCriterion")
	}

	// Removing a non-existent criterion should not panic.
	store.RemoveLocalCriterion(ctx, types.HACritHaStandby)
}

func TestSetSwitchState_EmitsEventOnChange(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	var events []Event
	unsubscribe := store.Watch(func(e Event) {
		events = append(events, e)
	})
	defer unsubscribe()

	// First call should emit event (empty -> "ha-ready")
	store.SetSwitchState(ctx, "ha-ready")
	if len(events) != 1 {
		t.Fatalf("expected 1 event after first SetSwitchState, got %d", len(events))
	}
	if events[0].Type != EventSwitchStateChanged {
		t.Errorf("expected EventSwitchStateChanged, got %v", events[0].Type)
	}

	// Second call with same value should NOT emit event
	store.SetSwitchState(ctx, "ha-ready")
	if len(events) != 1 {
		t.Errorf("expected no new event when state unchanged, got %d total events", len(events))
	}

	// Third call with different value should emit event
	store.SetSwitchState(ctx, "ha_not_initialized")
	if len(events) != 2 {
		t.Fatalf("expected 2 events after state change, got %d", len(events))
	}
	if events[1].Type != EventSwitchStateChanged {
		t.Errorf("expected EventSwitchStateChanged on second change, got %v", events[1].Type)
	}
}

func TestResetAllPeerStates_WritesGnmiAndResetsCriteria(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	store := NewStore(ctx, WithGnmiHandler(handler)).(*haStore)
	store.enabled = AdminStateEnabled
	store.switchState = SwitchStateHaReady

	peer1 := "10.0.0.1"
	peer2 := "10.0.0.2"
	store.SetPeer(ctx, peer1, types.HAPeerState{
		IP:             peer1,
		MemberCriteria: types.HACriteria{types.HACritPeerCompatible: true},
		IsLeader:       true,
	})
	store.SetPeer(ctx, peer2, types.HAPeerState{
		IP:                peer2,
		AdjacencyCriteria: types.HACriteria{types.HACritPeerPolicy: true},
	})

	reason := types.NewReasonString("ha deactivated")
	store.ResetAllPeerStates(ctx, reason)

	// Verify gNMI SETs were written for both peers.
	data := handler.GetAllData()
	for _, ip := range []string{peer1, peer2} {
		haStatePath := normalizeMockPath(fmt.Sprintf(paths.HAStorePeerHaState, ip))
		if v, ok := data[haStatePath]; !ok || v != types.PeerHAStateNoHa {
			t.Errorf("peer %s: expected gNMI SET haState=%q, got %v (ok=%v)", ip, types.PeerHAStateNoHa, v, ok)
		}
		svcStatePath := normalizeMockPath(fmt.Sprintf(paths.HAStorePeerSvcState, ip))
		if v, ok := data[svcStatePath]; !ok || v != types.SvcStateUnknown {
			t.Errorf("peer %s: expected gNMI SET svcState=%q, got %v (ok=%v)", ip, types.SvcStateUnknown, v, ok)
		}
	}

	// Verify all peer runtime state was reset but peers remain in the map.
	p1, ok := store.Peer(peer1)
	if !ok {
		t.Fatal("expected peer1 to remain in map after ResetAllPeerStates")
	}
	if p1.IP != peer1 {
		t.Errorf("expected peer1.IP=%q preserved, got %q", peer1, p1.IP)
	}
	if p1.IsLeader {
		t.Error("expected IsLeader=false after reset")
	}
	if p1.MemberCriteria[types.HACritPeerCompatible] {
		t.Error("expected MemberCriteria[peer_compatible]=false after reset")
	}
	if p1.MemberCriteriaMet {
		t.Error("expected MemberCriteriaMet=false after reset")
	}
	if p1.HaState != types.PeerHAStateNoHa {
		t.Errorf("expected HaState=%q, got %q", types.PeerHAStateNoHa, p1.HaState)
	}
	if p1.SvcState != types.SvcStateUnknown {
		t.Errorf("expected SvcState=%q, got %q", types.SvcStateUnknown, p1.SvcState)
	}
}

func TestResetAllPeerStates_SkipsGnmiWhenDisabled(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	store := NewStore(ctx, WithGnmiHandler(handler)).(*haStore)
	// enabled is "" — HA disabled.

	store.SetPeer(ctx, "10.0.0.1", types.HAPeerState{IP: "10.0.0.1"})
	store.ResetAllPeerStates(ctx, types.NewReasonString("ha deactivated"))

	// No gNMI SETs should have been written for peer states.
	data := handler.GetAllData()
	haStatePath := normalizeMockPath(fmt.Sprintf(paths.HAStorePeerHaState, "10.0.0.1"))
	if _, ok := data[haStatePath]; ok {
		t.Error("expected NO gNMI SET for peer haState when HA disabled")
	}
}

func TestResetLocalHaState_ClearsHaFieldsPreservesSvc(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	// Set up svc and HA state.
	store.SetLocalDerivedStates(ctx,
		types.HAStateReady, types.SvcStateSuccess,
		types.NewReasonString("ha ok"), types.NewReasonString("svc ok"),
		false)
	store.SetLeader(ctx, true)
	store.UpdateLocalCriterion(ctx, types.HACritDpuHealth, true)
	store.UpdateLocalCriterion(ctx, types.HACritHaStandby, true)

	store.ResetLocalHaState(ctx)

	local := store.Local()
	// HA fields cleared.
	if local.HaState != "" {
		t.Errorf("expected HaState cleared, got %q", local.HaState)
	}
	if local.Leader {
		t.Error("expected Leader=false after reset")
	}
	if local.CriteriaRecoveryPending {
		t.Error("expected CriteriaRecoveryPending=false after reset")
	}
	// Svc fields preserved.
	if local.SvcState != types.SvcStateSuccess {
		t.Errorf("expected SvcState=%q preserved, got %q", types.SvcStateSuccess, local.SvcState)
	}
	if local.SvcStateReason != types.NewReasonString("svc ok") {
		t.Errorf("expected SvcStateReason preserved, got %q", local.SvcStateReason)
	}
	// Svc criteria preserved.
	if _, ok := local.Criteria[types.HACritDpuHealth]; !ok {
		t.Error("expected dpu_healthy criterion preserved after reset")
	}
	// HA-only criteria removed.
	if _, ok := local.Criteria[types.HACritHaStandby]; ok {
		t.Error("expected ha_standby criterion removed after reset")
	}
}

// normalizeMockPath strips the "device:" prefix and leading "/" to match mock handler keys.
func normalizeMockPath(path string) string {
	if len(path) > 7 && path[:7] == "device:" {
		path = path[7:]
	}
	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}
	return path
}
