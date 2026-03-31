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

func TestSetLocalHaState_SetsStateAndReason(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	store := NewStore(ctx, WithGnmiHandler(handler)).(*haStore)

	reason := types.NewReasonString("local criteria not met")
	err := store.SetLocalHaState(ctx, types.HAStateNotReady, reason)
	if err != nil {
		t.Fatalf("SetLocalHaState failed: %v", err)
	}

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

func TestSetLocalSvcState_SetsStateAndReason_Failure(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	store := NewStore(ctx, WithGnmiHandler(handler)).(*haStore)

	reason := types.NewReasonString("local criteria not met")
	err := store.SetLocalSvcState(ctx, types.SvcStateFailure, reason)
	if err != nil {
		t.Fatalf("SetLocalSvcState failed: %v", err)
	}

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

func TestSetLocalSvcState_SuccessHasEmptyReason(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	store := NewStore(ctx, WithGnmiHandler(handler)).(*haStore)

	err := store.SetLocalSvcState(ctx, types.SvcStateSuccess, "")
	if err != nil {
		t.Fatalf("SetLocalSvcState failed: %v", err)
	}

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

func TestSetRemoteSvcState_SetsStateAndReasonViaGnmi(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	store := NewStore(ctx, WithGnmiHandler(handler)).(*haStore)

	peerIP := "10.0.0.2"
	reason := types.NewReasonString("peer service failure")
	err := store.SetRemoteSvcState(ctx, peerIP, types.SvcStateFailure, reason)
	if err != nil {
		t.Fatalf("SetRemoteSvcState failed: %v", err)
	}

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

func TestSetRemoteMbrState_SetsStateAndReasonViaGnmi(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	store := NewStore(ctx, WithGnmiHandler(handler)).(*haStore)

	peerIP := "10.0.0.3"
	reason := types.NewReasonString("adjacency down")
	err := store.SetRemoteMbrState(ctx, peerIP, "no_ha", reason)
	if err != nil {
		t.Fatalf("SetRemoteMbrState failed: %v", err)
	}

	data := handler.GetAllData()
	reasonPath := normalizeMockPath(fmt.Sprintf(paths.HAStorePeerSvcStateReason, peerIP))
	if v, ok := data[reasonPath]; !ok || v != reason.String() {
		t.Errorf("expected gNMI SET for peer svcStateReason=%q, got %v (found=%v)", reason, v, ok)
	}
}

func TestSetRemoteStatesAdjDown_SetsReasonsViaGnmi(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	store := NewStore(ctx, WithGnmiHandler(handler)).(*haStore)

	peerIP := "10.0.0.4"
	err := store.SetRemoteStatesAdjDown(ctx, peerIP)
	if err != nil {
		t.Fatalf("SetRemoteStatesAdjDown failed: %v", err)
	}

	data := handler.GetAllData()
	reasonPath := normalizeMockPath(fmt.Sprintf(paths.HAStorePeerSvcStateReason, peerIP))
	if v, ok := data[reasonPath]; !ok || v != "adjacency down" {
		t.Errorf("expected gNMI SET for peer svcStateReason=%q, got %v (found=%v)", "adjacency down", v, ok)
	}
}

func TestSetLocalDerivedStates_SuccessHasEmptyReasons(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	store.SetLocalDerivedStates(ctx, types.HAStateReady, types.SvcStateSuccess, "", "")

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
	store.SetLocalDerivedStates(ctx, types.HAStateNotReady, types.SvcStateFailure, haReason, svcReason)

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

func TestSetLocalHaState_NoHandler_NoError(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	err := store.SetLocalHaState(ctx, types.HAStateReady, "")
	if err != nil {
		t.Fatalf("expected no error without handler, got: %v", err)
	}

	local := store.Local()
	if local.HaState != types.HAStateReady {
		t.Errorf("expected HaState %q, got %q", types.HAStateReady, local.HaState)
	}
	if local.HaStateReason != "" {
		t.Errorf("expected empty HaStateReason for success, got %q", local.HaStateReason)
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
	store.UpdatePeerAdjacencyCriterion(ctx, peerIP, types.HACritPeerIpConfig, true)
	store.UpdatePeerAdjacencyCriterion(ctx, peerIP, types.HACritPeerServiceRedir, false)
	peer, _ := store.Peer(peerIP)
	if peer.AdjacencyCriteriaMet {
		t.Error("expected AdjacencyCriteriaMet=false when one criterion fails")
	}

	// Both criteria now pass → Met becomes true.
	store.UpdatePeerAdjacencyCriterion(ctx, peerIP, types.HACritPeerServiceRedir, true)
	peer, _ = store.Peer(peerIP)
	if !peer.AdjacencyCriteriaMet {
		t.Error("expected AdjacencyCriteriaMet=true after all criteria pass")
	}
	if peer.AdjacencyCriteriaMetEpoch == 0 {
		t.Error("expected AdjacencyCriteriaMetEpoch to be set when Met becomes true")
	}

	// One criterion fails again → Met reverts to false.
	store.UpdatePeerAdjacencyCriterion(ctx, peerIP, types.HACritPeerIpConfig, false)
	peer, _ = store.Peer(peerIP)
	if peer.AdjacencyCriteriaMet {
		t.Error("expected AdjacencyCriteriaMet=false after criterion fails")
	}
}

func TestSetPeer_ComputesMetFromMaps(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)
	peerIP := "10.0.0.12"

	// Pre-populate criteria that are all true → SetPeer should compute Met=true.
	store.SetPeer(ctx, peerIP, types.HAPeerState{
		IP: peerIP,
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible: true,
		},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerIpConfig:     true,
			types.HACritPeerServiceRedir: true,
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

	// Empty criteria map → Met=false (vacuous AllOk guard).
	store.SetPeer(ctx, peerIP, types.HAPeerState{IP: peerIP})
	peer, _ = store.Peer(peerIP)
	if peer.MemberCriteriaMet {
		t.Error("expected MemberCriteriaMet=false for empty criteria map")
	}
	if peer.AdjacencyCriteriaMet {
		t.Error("expected AdjacencyCriteriaMet=false for empty criteria map")
	}
}

func TestUpdatePeerAdjacency_Disconnect_ClearsConnectionCriteria(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)
	peerIP := "10.0.0.20"

	// Set peer with all connection-managed criteria true and adjacency connected.
	store.SetPeer(ctx, peerIP, types.HAPeerState{
		IP:                 peerIP,
		AdjacencyConnected: true,
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible: true,
		},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerIpConfig:     true,
			types.HACritPeerServiceRedir: true,
			types.HACritPeerPolicy:       true,
		},
	})

	store.UpdatePeerAdjacency(ctx, peerIP, false, 0)

	peer, ok := store.Peer(peerIP)
	if !ok {
		t.Fatal("expected peer to exist")
	}
	if peer.AdjacencyConnected {
		t.Error("expected AdjacencyConnected=false after disconnect")
	}
	if peer.MemberCriteria[types.HACritPeerCompatible] {
		t.Error("expected MemberCriteria[peer_compatible]=false after disconnect")
	}
	if peer.MemberCriteriaMet {
		t.Error("expected MemberCriteriaMet=false after disconnect")
	}
	if peer.AdjacencyCriteria[types.HACritPeerServiceRedir] {
		t.Error("expected AdjacencyCriteria[peer_service_redir]=false after disconnect")
	}
	if peer.AdjacencyCriteria[types.HACritPeerPolicy] {
		t.Error("expected AdjacencyCriteria[peer_policy]=false after disconnect")
	}
	if peer.AdjacencyCriteriaMet {
		t.Error("expected AdjacencyCriteriaMet=false after disconnect")
	}
	// peer_ip_config must be preserved — used by checkAdjacencies to retry connection.
	if !peer.AdjacencyCriteria[types.HACritPeerIpConfig] {
		t.Error("expected AdjacencyCriteria[peer_ip_config]=true (preserved) after disconnect")
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
