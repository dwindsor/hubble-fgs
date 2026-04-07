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
	"strings"
	"testing"

	hastore "github.com/isovalent/hubble-fgs/pkg/nxos/store/ha"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

// setupStore creates a store with no peers and default local state.
func setupStore(t *testing.T) hastore.Store {
	t.Helper()
	return hastore.NewStore(context.Background())
}

// setLocalReady sets all local criteria to true and CriteriaMet=true.
func setLocalReady(t *testing.T, store hastore.Store) {
	t.Helper()
	ctx := context.Background()
	store.UpdateLocalCriterion(ctx, types.HACritInService, true)
	store.UpdateLocalCriterion(ctx, types.HACritDpuHealth, true)
	store.UpdateLocalCriterion(ctx, types.HACritDpuInSync, true)
	local := store.Local()
	local.CriteriaMet = true
	store.SetLocal(ctx, local)
}

// setLocalReadyEstablished sets local ready with an established HA state (for startup protection tests).
func setLocalReadyEstablished(t *testing.T, store hastore.Store) {
	t.Helper()
	setLocalReady(t, store)
	ctx := context.Background()
	store.SetLocalDerivedStates(ctx, types.HAStateReady, types.SvcStateSuccess,
		types.NewReasonString("established"), types.NewReasonString("established"), true)
}

// setLocalSyncing sets local to yielding/syncing state: all real criteria pass but
// standby criterion is injected, making CriteriaMet=false. This represents a node
// that is yielding to a peer in TAKEOVER.
func setLocalSyncing(t *testing.T, store hastore.Store) {
	t.Helper()
	ctx := context.Background()
	store.UpdateLocalCriterion(ctx, types.HACritInService, true)
	store.UpdateLocalCriterion(ctx, types.HACritDpuHealth, true)
	store.UpdateLocalCriterion(ctx, types.HACritDpuInSync, true)
	store.UpdateLocalCriterion(ctx, types.HACritHaStandby, false)
	// CriteriaMet stays false (default) because standby is false.
}

// setLocalServiceFailure sets local to not-in-service (service failure).
func setLocalServiceFailure(t *testing.T, store hastore.Store) {
	t.Helper()
	ctx := context.Background()
	store.UpdateLocalCriterion(ctx, types.HACritInService, false)
	// CriteriaMet stays false (default).
}

// addPeerConnectedAndReady adds a connected peer with service ready, membership ok, adjacency ok.
func addPeerConnectedAndReady(t *testing.T, store hastore.Store, ip string) {
	t.Helper()
	ctx := context.Background()
	store.SetPeer(ctx, ip, types.HAPeerState{
		IP:        ip,
		Connected: true,
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible:   true,
			types.HACritPeerVrfGid:       true,
			types.HACritPeerDPUKeepalive: true,
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: true,
		},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerDPUBulkSync: true,
			types.HACritPeerPolicy:      true,
		},
	})
}

// addPeerConnectedAdjacencyFail adds a connected peer with service ready, membership ok, but adjacency failing.
func addPeerConnectedAdjacencyFail(t *testing.T, store hastore.Store, ip string) {
	t.Helper()
	ctx := context.Background()
	store.SetPeer(ctx, ip, types.HAPeerState{
		IP:        ip,
		Connected: true,
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible:   true,
			types.HACritPeerVrfGid:       true,
			types.HACritPeerDPUKeepalive: true,
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: true,
		},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerDPUBulkSync: false, // adjacency failure
			types.HACritPeerPolicy:      true,
		},
	})
}

// addPeerConnectedMembershipFail adds a connected peer with membership criteria failing.
func addPeerConnectedMembershipFail(t *testing.T, store hastore.Store, ip string) {
	t.Helper()
	ctx := context.Background()
	store.SetPeer(ctx, ip, types.HAPeerState{
		IP:        ip,
		Connected: true,
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible: false, // membership failure
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: true,
		},
		AdjacencyCriteria: types.HACriteria{},
	})
}

// addPeerConnectedSvcFailure adds a connected peer with service not ready (peer service failure).
func addPeerConnectedSvcFailure(t *testing.T, store hastore.Store, ip string) {
	t.Helper()
	ctx := context.Background()
	store.SetPeer(ctx, ip, types.HAPeerState{
		IP:        ip,
		Connected: true,
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible: true,
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: false, // peer service failure
		},
		AdjacencyCriteria: types.HACriteria{},
	})
}

// addPeerConnectedSvcFailureInSwitchover adds a connected peer with service not
// ready because it is in standby hold-down (ha-switchover). Membership is OK.
func addPeerConnectedSvcFailureInSwitchover(t *testing.T, store hastore.Store, ip string) {
	t.Helper()
	ctx := context.Background()
	store.SetPeer(ctx, ip, types.HAPeerState{
		IP:         ip,
		Connected:  true,
		MemberInfo: &types.HAPeerMember{HaState: types.HAStateSwitchover},
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible:   true,
			types.HACritPeerVrfGid:       true,
			types.HACritPeerDPUKeepalive: true,
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: false, // not ready due to standby
		},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerDPUBulkSync: true,
			types.HACritPeerPolicy:      true,
		},
	})
}

// addPeerNotConnected adds a peer that is not connected (unknown state).
func addPeerNotConnected(t *testing.T, store hastore.Store, ip string) {
	t.Helper()
	ctx := context.Background()
	store.SetPeer(ctx, ip, types.HAPeerState{
		IP:                ip,
		Connected:         false,
		AdjacencyCriteria: types.HACriteria{},
	})
}

// assertResult checks agent HA state, SVC state, and optionally per-peer HA state.
func assertResult(t *testing.T, result stateResult, wantHa, wantSvc string) {
	t.Helper()
	if result.HaState != wantHa {
		t.Errorf("expected Agent HaState=%s, got %s (reason=%s)", wantHa, result.HaState, result.HaReason)
	}
	if result.SvcState != wantSvc {
		t.Errorf("expected SvcState=%s, got %s (reason=%s)", wantSvc, result.SvcState, result.SvcReason)
	}
	// Verify all state values have non-empty reasons
	if result.HaReason == "" {
		t.Errorf("Agent HaState=%s has empty reason", result.HaState)
	}
	if result.SvcReason == "" {
		t.Errorf("SvcState=%s has empty reason", result.SvcState)
	}
}

func assertPeerHaState(t *testing.T, result stateResult, ip, wantPeerHa string) {
	t.Helper()
	ps, ok := result.PeerStates[ip]
	if !ok {
		t.Fatalf("no peer state for %s", ip)
	}
	if ps.HaState != wantPeerHa {
		t.Errorf("expected Peer HaState=%s for %s, got %s (reason=%s)", wantPeerHa, ip, ps.HaState, ps.HaReason)
	}
	if ps.HaReason == "" {
		t.Errorf("Peer HaState=%s for %s has empty reason", ps.HaState, ip)
	}
}

func assertReasonContains(t *testing.T, reason types.ReasonString, substring string) {
	t.Helper()
	if !strings.Contains(reason.String(), substring) {
		t.Errorf("expected reason to contain %q, got %q", substring, reason)
	}
}

// TestComputeState_NoConnectivity_LocalReady: no peers connected, local ready → standalone (ha-not-ready, svc ready).
func TestComputeState_NoConnectivity_LocalReady(t *testing.T) {
	store := setupStore(t)
	setLocalReady(t, store)

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertResult(t, result, types.HAStateNotReady, types.SvcStateSuccess)
	assertReasonContains(t, result.HaReason, "no peer connectivity")
	assertReasonContains(t, result.SvcReason, "all criteria met")
}

// TestComputeState_NoConnectivity_LocalNotReady: no peers connected, local not-ready → standalone (ha-not-ready, svc not-ready).
func TestComputeState_NoConnectivity_LocalNotReady(t *testing.T) {
	store := setupStore(t)
	setLocalServiceFailure(t, store)

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertResult(t, result, types.HAStateNotReady, types.SvcStateFailure)
	assertReasonContains(t, result.HaReason, "no peer connectivity")
}

// TestComputeState_NoConnectivity_PeerConfiguredButNotConnected: peer exists but not connected → standalone.
func TestComputeState_NoConnectivity_PeerConfiguredButNotConnected(t *testing.T) {
	store := setupStore(t)
	setLocalReady(t, store)
	addPeerNotConnected(t, store, "10.0.0.2")

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertResult(t, result, types.HAStateNotReady, types.SvcStateSuccess)
	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateNoHa)
}

// TestComputeState_BothReady_AllOk: both ready, all criteria ok → active/active (ha-ready, svc ready).
func TestComputeState_BothReady_AllOk(t *testing.T) {
	store := setupStore(t)
	setLocalReady(t, store)
	addPeerConnectedAndReady(t, store, "10.0.0.2")

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertResult(t, result, types.HAStateReady, types.SvcStateSuccess)
	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateOk)
	assertReasonContains(t, result.HaReason, "all criteria met")
}

// TestComputeState_BothReady_AdjacencyFail: both ready, adjacency failure → active/active degraded (ha-degraded, svc ready).
func TestComputeState_BothReady_AdjacencyFail(t *testing.T) {
	store := setupStore(t)
	setLocalReady(t, store)
	addPeerConnectedAdjacencyFail(t, store, "10.0.0.2")

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertResult(t, result, types.HAStateDegraded, types.SvcStateSuccess)
	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateDegraded)
	assertReasonContains(t, result.PeerStates["10.0.0.2"].HaReason, "adjacency failure")
	assertReasonContains(t, result.PeerStates["10.0.0.2"].HaReason, "peer_dpu_bulk_sync")
}

// TestComputeState_LocalReady_MembershipFail: local ready (established), membership failure → active/standby active (ha-takeover, svc ready).
func TestComputeState_LocalReady_MembershipFail(t *testing.T) {
	store := setupStore(t)
	setLocalReadyEstablished(t, store)
	addPeerConnectedMembershipFail(t, store, "10.0.0.2")

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertResult(t, result, types.HAStateTakeover, types.SvcStateSuccess)
	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateFail)
	assertReasonContains(t, result.PeerStates["10.0.0.2"].HaReason, "membership failure")
	assertReasonContains(t, result.PeerStates["10.0.0.2"].HaReason, "peer_compatible")
}

// TestComputeState_LocalReady_PeerSvcFailure: local ready, peer service failure → standalone (ha-not-ready, svc ready).
func TestComputeState_LocalReady_PeerSvcFailure(t *testing.T) {
	store := setupStore(t)
	setLocalReady(t, store)
	addPeerConnectedSvcFailure(t, store, "10.0.0.2")

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertResult(t, result, types.HAStateNotReady, types.SvcStateSuccess)
	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateUnavailable)
	assertReasonContains(t, result.PeerStates["10.0.0.2"].HaReason, "peer service failure")
}

// TestComputeState_LocalSyncing_PeerReady: local yielding (standby injected), peer ready → active/standby standby (ha-switchover, svc not-ready).
func TestComputeState_LocalSyncing_PeerReady(t *testing.T) {
	store := setupStore(t)
	setLocalSyncing(t, store)
	addPeerConnectedAndReady(t, store, "10.0.0.2")

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertResult(t, result, types.HAStateSwitchover, types.SvcStateFailure)
	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateDegraded)
	assertReasonContains(t, result.PeerStates["10.0.0.2"].HaReason, "syncing")
	assertReasonContains(t, result.HaReason, "syncing")
}

// TestComputeState_LocalSvcFailure_PeerReady: local service failure (not in-service), peer ready → unavailable (ha-unavailable, svc not-ready).
func TestComputeState_LocalSvcFailure_PeerReady(t *testing.T) {
	store := setupStore(t)
	setLocalServiceFailure(t, store)
	addPeerConnectedAndReady(t, store, "10.0.0.2")

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertResult(t, result, types.HAStateUnavailable, types.SvcStateFailure)
	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateUnavailable)
	assertReasonContains(t, result.PeerStates["10.0.0.2"].HaReason, "local service failure")
}

// TestComputeState_BothNotReady: both not ready → unavailable (ha-unavailable, svc not-ready).
func TestComputeState_BothNotReady(t *testing.T) {
	store := setupStore(t)
	setLocalServiceFailure(t, store)
	addPeerConnectedSvcFailure(t, store, "10.0.0.2")

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertResult(t, result, types.HAStateUnavailable, types.SvcStateFailure)
	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateUnavailable)
	assertReasonContains(t, result.PeerStates["10.0.0.2"].HaReason, "local and peer service failure")
}

// TestComputeState_MembershipFailPriority: local ready (established), peer service ready BUT membership fails → ha-takeover (membership takes priority).
func TestComputeState_MembershipFailPriority(t *testing.T) {
	store := setupStore(t)
	setLocalReadyEstablished(t, store)
	ctx := context.Background()
	// Peer connected, service ready, but membership fails.
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:        "10.0.0.2",
		Connected: true,
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible: false, // membership failure
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: true, // peer service IS ready
		},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerDPUBulkSync: true,
			types.HACritPeerPolicy:      true,
		},
	})

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertResult(t, result, types.HAStateTakeover, types.SvcStateSuccess)
	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateFail)
	assertReasonContains(t, result.PeerStates["10.0.0.2"].HaReason, "membership failure")
}

// TestComputeState_KeepaliveMembershipFail: keepalive failure (now membership) → ha-takeover (not ha-degraded).
func TestComputeState_KeepaliveMembershipFail(t *testing.T) {
	store := setupStore(t)
	setLocalReadyEstablished(t, store)
	ctx := context.Background()
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:        "10.0.0.2",
		Connected: true,
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible:   true,
			types.HACritPeerVrfGid:       true,
			types.HACritPeerDPUKeepalive: false, // keepalive is now membership
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: true,
		},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerDPUBulkSync: true,
			types.HACritPeerPolicy:      true,
		},
	})

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertResult(t, result, types.HAStateTakeover, types.SvcStateSuccess)
	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateFail)
	assertReasonContains(t, result.PeerStates["10.0.0.2"].HaReason, "peer_dpu_keepalive")
}

// TestComputeState_PolicyAdjacencyFail: policy failure (adjacency criterion) → ha-degraded (not ha-fail).
func TestComputeState_PolicyAdjacencyFail(t *testing.T) {
	store := setupStore(t)
	setLocalReady(t, store)
	ctx := context.Background()
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:        "10.0.0.2",
		Connected: true,
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible:   true,
			types.HACritPeerVrfGid:       true,
			types.HACritPeerDPUKeepalive: true,
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: true,
		},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerDPUBulkSync: true,
			types.HACritPeerPolicy:      false, // policy is adjacency criterion
		},
	})

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertResult(t, result, types.HAStateDegraded, types.SvcStateSuccess)
	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateDegraded)
	assertReasonContains(t, result.PeerStates["10.0.0.2"].HaReason, "peer_policy")
}

// TestComputeState_LocalSyncing_MembershipFail: local syncing + membership failure → peer ha-fail, agent ha-switchover.
func TestComputeState_LocalSyncing_MembershipFail(t *testing.T) {
	store := setupStore(t)
	setLocalSyncing(t, store)
	ctx := context.Background()
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:        "10.0.0.2",
		Connected: true,
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible: false, // membership failure
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: true,
		},
		AdjacencyCriteria: types.HACriteria{},
	})

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertResult(t, result, types.HAStateSwitchover, types.SvcStateFailure)
	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateFail)
	assertReasonContains(t, result.PeerStates["10.0.0.2"].HaReason, "membership failure")
}

// TestComputeState_LocalSyncing_AdjacencyFail: local syncing + adjacency failure → peer ha-degraded, agent ha-switchover.
func TestComputeState_LocalSyncing_AdjacencyFail(t *testing.T) {
	store := setupStore(t)
	setLocalSyncing(t, store)
	ctx := context.Background()
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:        "10.0.0.2",
		Connected: true,
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible:   true,
			types.HACritPeerVrfGid:       true,
			types.HACritPeerDPUKeepalive: true,
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: true,
		},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerDPUBulkSync: false, // adjacency failure
			types.HACritPeerPolicy:      true,
		},
	})

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertResult(t, result, types.HAStateSwitchover, types.SvcStateFailure)
	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateDegraded)
	assertReasonContains(t, result.PeerStates["10.0.0.2"].HaReason, "syncing")
}

// TestBestPeerHaState_SelectsHighestPriority: with multiple peers, selects the best HA state.
func TestBestPeerHaState_SelectsHighestPriority(t *testing.T) {
	tests := []struct {
		name     string
		states   map[string]peerStateResult
		wantBest string
	}{
		{
			name: "ha-ok wins over ha-degraded",
			states: map[string]peerStateResult{
				"10.0.0.2": {IP: "10.0.0.2", HaState: types.PeerHAStateDegraded, HaReason: "adj"},
				"10.0.0.3": {IP: "10.0.0.3", HaState: types.PeerHAStateOk, HaReason: "ok"},
			},
			wantBest: types.PeerHAStateOk,
		},
		{
			name: "ha-fail wins over ha-unavailable",
			states: map[string]peerStateResult{
				"10.0.0.2": {IP: "10.0.0.2", HaState: types.PeerHAStateUnavailable, HaReason: "u"},
				"10.0.0.3": {IP: "10.0.0.3", HaState: types.PeerHAStateFail, HaReason: "f"},
			},
			wantBest: types.PeerHAStateFail,
		},
		{
			name:     "empty map returns no-ha",
			states:   map[string]peerStateResult{},
			wantBest: types.PeerHAStateNoHa,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			best := bestPeerHaState(tt.states)
			if best.HaState != tt.wantBest {
				t.Errorf("expected best=%s, got %s", tt.wantBest, best.HaState)
			}
		})
	}
}

// TestAgentHaStateReason_IncludesPeerIP: agent HA state reason should include the peer IP when derived from a peer.
func TestAgentHaStateReason_IncludesPeerIP(t *testing.T) {
	store := setupStore(t)
	setLocalReady(t, store)
	addPeerConnectedAdjacencyFail(t, store, "10.0.0.2")

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertReasonContains(t, result.HaReason, "10.0.0.2")
	assertReasonContains(t, result.HaReason, "adjacency failure")
}

// TestSvcStateReason_AlwaysPopulated: SVC state reason is always populated.
func TestSvcStateReason_AlwaysPopulated(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T, store hastore.Store)
		wantSvc   string
		wantInRsn string
	}{
		{
			name:      "ready",
			setup:     func(t *testing.T, s hastore.Store) { setLocalReady(t, s) },
			wantSvc:   types.SvcStateSuccess,
			wantInRsn: "all criteria met",
		},
		{
			name:      "not in service",
			setup:     func(t *testing.T, s hastore.Store) { setLocalServiceFailure(t, s) },
			wantSvc:   types.SvcStateFailure,
			wantInRsn: "in_service",
		},
		{
			name:      "syncing",
			setup:     func(t *testing.T, s hastore.Store) { setLocalSyncing(t, s) },
			wantSvc:   types.SvcStateFailure,
			wantInRsn: "syncing",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := setupStore(t)
			tt.setup(t, store)
			sm := NewStateMachine(store)
			result := sm.ComputeState()
			if result.SvcState != tt.wantSvc {
				t.Errorf("expected SvcState=%s, got %s", tt.wantSvc, result.SvcState)
			}
			assertReasonContains(t, result.SvcReason, tt.wantInRsn)
		})
	}
}

// --- Startup Protection Tests ---

// TestDeriveAgentHaState_StartupProtection: on startup (no established state), PeerHAStateFail → ha-not-ready (not ha-takeover).
func TestDeriveAgentHaState_StartupProtection(t *testing.T) {
	store := setupStore(t)
	setLocalReady(t, store) // no established HaState (default "")
	addPeerConnectedMembershipFail(t, store, "10.0.0.2")

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertResult(t, result, types.HAStateNotReady, types.SvcStateSuccess)
	assertReasonContains(t, result.HaReason, "startup")
}

// TestDeriveAgentHaState_EstablishedTakeover: when in established HA_READY, PeerHAStateFail → ha-takeover.
func TestDeriveAgentHaState_EstablishedTakeover(t *testing.T) {
	store := setupStore(t)
	setLocalReadyEstablished(t, store)
	addPeerConnectedMembershipFail(t, store, "10.0.0.2")

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertResult(t, result, types.HAStateTakeover, types.SvcStateSuccess)
	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateFail)
}

// --- Standby Criteria Evaluation Tests ---

// TestEvaluateStandbyCrit_PeerTakeover: when peer reports HA_TAKEOVER, svc ready, criteria not converged → inject.
func TestEvaluateStandbyCrit_PeerTakeover(t *testing.T) {
	store := setupStore(t)
	setLocalReady(t, store)
	ctx := context.Background()
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:         "10.0.0.2",
		Connected:  true,
		MemberInfo: &types.HAPeerMember{HaState: types.HAStateTakeover},
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible: false, // not converged
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: true,
		},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerDPUBulkSync: false,
			types.HACritPeerPolicy:      false,
		},
	})

	sm := NewStateMachine(store)
	inject, remove := sm.EvaluateStandbyCrit("", false)
	if !inject {
		t.Error("expected inject=true when peer reports TAKEOVER and criteria not converged")
	}
	if remove {
		t.Error("expected remove=false")
	}
}

// TestEvaluateStandbyCrit_Tiebreaker: both TAKEOVER, local is leader → do NOT inject.
func TestEvaluateStandbyCrit_Tiebreaker(t *testing.T) {
	store := setupStore(t)
	setLocalReady(t, store)
	ctx := context.Background()
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:         "10.0.0.2",
		Connected:  true,
		MemberInfo: &types.HAPeerMember{HaState: types.HAStateTakeover},
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible: false,
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: true,
		},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerDPUBulkSync: false,
			types.HACritPeerPolicy:      false,
		},
	})

	sm := NewStateMachine(store)
	// Local is TAKEOVER and leader → tiebreaker wins, no inject.
	inject, _ := sm.EvaluateStandbyCrit(types.HAStateTakeover, true)
	if inject {
		t.Error("expected inject=false when local is TAKEOVER and leader (tiebreaker)")
	}
}

// TestEvaluateStandbyCrit_LeaderNotYetTakeover: leader not yet in TAKEOVER
// (e.g. still ha-ready), peer reports TAKEOVER → leader should NOT inject standby
// because leader wins the tiebreaker regardless of current state.
func TestEvaluateStandbyCrit_LeaderNotYetTakeover(t *testing.T) {
	store := setupStore(t)
	setLocalReady(t, store)
	ctx := context.Background()
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:         "10.0.0.2",
		Connected:  true,
		MemberInfo: &types.HAPeerMember{HaState: types.HAStateTakeover},
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible: false,
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: true,
		},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerDPUBulkSync: false,
			types.HACritPeerPolicy:      false,
		},
	})

	sm := NewStateMachine(store)
	// Local is ha-ready (not yet TAKEOVER) but IS the leader → tiebreaker wins.
	inject, _ := sm.EvaluateStandbyCrit(types.HAStateReady, true)
	if inject {
		t.Error("expected inject=false: leader wins tiebreaker even before entering TAKEOVER")
	}
}

// TestEvaluateStandbyCrit_LeaderWithSvcFailureYields: leader with local service
// failure should yield to peer TAKEOVER despite being leader.
func TestEvaluateStandbyCrit_LeaderWithSvcFailureYields(t *testing.T) {
	store := setupStore(t)
	setLocalServiceFailure(t, store) // in_service=false → service failure
	ctx := context.Background()
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:         "10.0.0.2",
		Connected:  true,
		MemberInfo: &types.HAPeerMember{HaState: types.HAStateTakeover},
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible: true,
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: true,
		},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerDPUBulkSync: false,
			types.HACritPeerPolicy:      false,
		},
	})

	sm := NewStateMachine(store)
	// Leader has local service failure → should yield to peer's TAKEOVER.
	inject, _ := sm.EvaluateStandbyCrit(types.HAStateUnavailable, true)
	if !inject {
		t.Error("expected inject=true: leader with service failure should yield")
	}
}

// TestEvaluateStandbyCrit_PeerTakeoverWithConvergedCriteria: peer reports TAKEOVER
// but criteria have converged (membership + adjacency all OK) → do NOT inject
// standby. Converged criteria mean the node can transition back to HA_READY
// quickly. Standby is only injected when criteria have NOT yet converged.
func TestEvaluateStandbyCrit_PeerTakeoverWithConvergedCriteria(t *testing.T) {
	store := setupStore(t)
	setLocalReady(t, store)
	ctx := context.Background()
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:         "10.0.0.2",
		Connected:  true,
		MemberInfo: &types.HAPeerMember{HaState: types.HAStateTakeover},
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible:   true,
			types.HACritPeerVrfGid:       true,
			types.HACritPeerDPUKeepalive: true,
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: true,
		},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerDPUBulkSync: true,
			types.HACritPeerPolicy:      true,
		},
	})

	sm := NewStateMachine(store)
	// Criteria have converged → standby should NOT be injected even if peer reports TAKEOVER.
	inject, _ := sm.EvaluateStandbyCrit("", false)
	if inject {
		t.Error("expected inject=false: criteria converged, standby not needed even if peer reports TAKEOVER")
	}
}

// TestEvaluateStandbyCrit_RemoveOnPeerReady: when standby is present and peer is no longer TAKEOVER → remove.
func TestEvaluateStandbyCrit_RemoveOnPeerReady(t *testing.T) {
	store := setupStore(t)
	ctx := context.Background()
	// Local has standby injected
	store.UpdateLocalCriterion(ctx, types.HACritInService, true)
	store.UpdateLocalCriterion(ctx, types.HACritDpuHealth, true)
	store.UpdateLocalCriterion(ctx, types.HACritDpuInSync, true)
	store.UpdateLocalCriterion(ctx, types.HACritHaStandby, false)

	// Peer is now HA_READY (recovered)
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:         "10.0.0.2",
		Connected:  true,
		MemberInfo: &types.HAPeerMember{HaState: types.HAStateReady},
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible:   true,
			types.HACritPeerVrfGid:       true,
			types.HACritPeerDPUKeepalive: true,
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: true,
		},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerDPUBulkSync: true,
			types.HACritPeerPolicy:      true,
		},
	})

	sm := NewStateMachine(store)
	inject, remove := sm.EvaluateStandbyCrit("", false)
	if inject {
		t.Error("expected inject=false when peer is not TAKEOVER")
	}
	if !remove {
		t.Error("expected remove=true when standby is present and peer recovered")
	}
}

// TestEvaluateStandbyCrit_DisconnectedPeerIgnored: disconnected peer with stale TAKEOVER
// MemberInfo should not trigger standby injection, and should trigger removal if standby present.
func TestEvaluateStandbyCrit_DisconnectedPeerIgnored(t *testing.T) {
	ctx := context.Background()

	t.Run("no inject when peer disconnected", func(t *testing.T) {
		store := setupStore(t)
		setLocalReady(t, store)
		store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
			IP:         "10.0.0.2",
			Connected:  false, // disconnected
			MemberInfo: &types.HAPeerMember{HaState: types.HAStateTakeover},
			MemberCriteria: types.HACriteria{
				types.HACritPeerCompatible: false, // not converged
			},
			ServiceCriteria: types.HACriteria{
				types.HACritPeerService: true, // stale
			},
			AdjacencyCriteria: types.HACriteria{
				types.HACritPeerDPUBulkSync: false,
				types.HACritPeerPolicy:      false,
			},
		})

		sm := NewStateMachine(store)
		inject, remove := sm.EvaluateStandbyCrit("", false)
		if inject {
			t.Error("expected inject=false for disconnected peer")
		}
		if remove {
			t.Error("expected remove=false when no standby present")
		}
	})

	t.Run("remove standby when only peer is disconnected", func(t *testing.T) {
		store := setupStore(t)
		setLocalSyncing(t, store) // standby already injected
		store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
			IP:         "10.0.0.2",
			Connected:  false, // disconnected
			MemberInfo: &types.HAPeerMember{HaState: types.HAStateTakeover},
			MemberCriteria: types.HACriteria{
				types.HACritPeerCompatible: false,
			},
			ServiceCriteria: types.HACriteria{
				types.HACritPeerService: true, // stale
			},
			AdjacencyCriteria: types.HACriteria{
				types.HACritPeerDPUBulkSync: false,
			},
		})

		sm := NewStateMachine(store)
		inject, remove := sm.EvaluateStandbyCrit("", false)
		if inject {
			t.Error("expected inject=false for disconnected peer")
		}
		if !remove {
			t.Error("expected remove=true when standby present and no connected peer in TAKEOVER")
		}
	})
}

// TestEvaluateStandbyCrit_PeerRecoveredRemovesStandby: standby is removed when
// the peer transitions from TAKEOVER to READY (recovery complete), not when
// criteria converge. The peer's reported state is the authoritative signal.
func TestEvaluateStandbyCrit_PeerRecoveredRemovesStandby(t *testing.T) {
	store := setupStore(t)
	setLocalSyncing(t, store) // standby injected
	ctx := context.Background()
	// Peer has recovered and now reports READY (no longer TAKEOVER).
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:         "10.0.0.2",
		Connected:  true,
		MemberInfo: &types.HAPeerMember{HaState: types.HAStateReady}, // recovered
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible:   true,
			types.HACritPeerVrfGid:       true,
			types.HACritPeerDPUKeepalive: true,
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: true,
		},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerDPUBulkSync: true,
			types.HACritPeerPolicy:      true,
		},
	})

	sm := NewStateMachine(store)
	inject, remove := sm.EvaluateStandbyCrit("", false)
	if inject {
		t.Error("expected inject=false when peer recovered to READY")
	}
	if !remove {
		t.Error("expected remove=true when standby present and peer no longer TAKEOVER")
	}
}

// TestComputeState_RecoveryToReady: after standby removed and CriteriaMet=true with peer
// all-ok, both agent HA state and peer HA state should be ha-ready / ha-ok.
func TestComputeState_RecoveryToReady(t *testing.T) {
	store := setupStore(t)
	ctx := context.Background()

	// Simulate post-recovery: standby removed, all local criteria pass, CriteriaMet=true.
	store.UpdateLocalCriterion(ctx, types.HACritInService, true)
	store.UpdateLocalCriterion(ctx, types.HACritDpuHealth, true)
	store.UpdateLocalCriterion(ctx, types.HACritDpuInSync, true)
	// No ha_standby criterion — it was removed.
	local := store.Local()
	local.CriteriaMet = true
	store.SetLocal(ctx, local)

	// Peer is fully ready (was TAKEOVER, now recovered to READY).
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:         "10.0.0.2",
		Connected:  true,
		MemberInfo: &types.HAPeerMember{HaState: types.HAStateReady},
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible:   true,
			types.HACritPeerVrfGid:       true,
			types.HACritPeerDPUKeepalive: true,
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: true,
		},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerDPUBulkSync: true,
			types.HACritPeerPolicy:      true,
		},
	})

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertResult(t, result, types.HAStateReady, types.SvcStateSuccess)
	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateOk)
	assertReasonContains(t, result.HaReason, "all criteria met")
}

// --- Priority Tests: worst failure takes precedence ---

// TestComputeState_LocalReady_PeerSvcFailure_MembershipFail: when both peer svc failure
// and membership failure exist, ha-unavailable (peer service failure) takes precedence.
func TestComputeState_LocalReady_PeerSvcFailure_MembershipFail(t *testing.T) {
	store := setupStore(t)
	setLocalReady(t, store)
	ctx := context.Background()
	// Peer connected, service NOT ready, AND membership fails.
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:        "10.0.0.2",
		Connected: true,
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible: false, // membership failure (symptom)
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: false, // peer svc failure (root cause)
		},
		AdjacencyCriteria: types.HACriteria{},
	})

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	// Peer service failure takes precedence - membership failure is typically a symptom.
	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateUnavailable)
	assertReasonContains(t, result.PeerStates["10.0.0.2"].HaReason, "peer service failure")
}

// --- Validation soft/hard failure Tests ---

// TestComputeState_PeerSvcFailure_MembershipStaysOk: peer service failure should NOT
// contaminate membership criteria — it produces ha-unavailable via peerSvcReady check.
func TestComputeState_PeerSvcFailure_MembershipStaysOk(t *testing.T) {
	store := setupStore(t)
	setLocalReady(t, store)
	ctx := context.Background()
	// Peer connected with svc failure, but membership criteria are all ok.
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:        "10.0.0.2",
		Connected: true,
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible:   true,
			types.HACritPeerVrfGid:       true,
			types.HACritPeerDPUKeepalive: true,
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: false, // svc failure
		},
		AdjacencyCriteria: types.HACriteria{},
	})

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	// Peer state should be ha-unavailable (svc failure), NOT ha-fail
	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateUnavailable)
}

// --- Debug criteria Tests ---

// TestComputeState_DebugMembershipFail: debug membership fail should cause ha-fail.
func TestComputeState_DebugMembershipFail(t *testing.T) {
	store := setupStore(t)
	setLocalReadyEstablished(t, store)
	ctx := context.Background()
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:        "10.0.0.2",
		Connected: true,
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible:      true,
			types.HACritPeerVrfGid:          true,
			types.HACritPeerDPUKeepalive:    true,
			types.HACritDebugMembershipFail: false, // debug override
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: true,
		},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerDPUBulkSync: true,
			types.HACritPeerPolicy:      true,
		},
	})

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateFail)
	assertResult(t, result, types.HAStateTakeover, types.SvcStateSuccess)
}

// TestComputeState_DebugAdjacencyFail: debug adjacency fail should cause ha-degraded.
func TestComputeState_DebugAdjacencyFail(t *testing.T) {
	store := setupStore(t)
	setLocalReady(t, store)
	ctx := context.Background()
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:        "10.0.0.2",
		Connected: true,
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible:   true,
			types.HACritPeerVrfGid:       true,
			types.HACritPeerDPUKeepalive: true,
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: true,
		},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerDPUBulkSync:    true,
			types.HACritPeerPolicy:         true,
			types.HACritDebugAdjacencyFail: false, // debug override
		},
	})

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateDegraded)
	assertResult(t, result, types.HAStateDegraded, types.SvcStateSuccess)
}

// TestComputeState_DebugRemoteMembershipFail: remote debug membership fail propagated from peer.
func TestComputeState_DebugRemoteMembershipFail(t *testing.T) {
	store := setupStore(t)
	setLocalReadyEstablished(t, store)
	ctx := context.Background()
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:        "10.0.0.2",
		Connected: true,
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible:            true,
			types.HACritPeerVrfGid:                true,
			types.HACritPeerDPUKeepalive:          true,
			types.HACritDebugMembershipFailRemote: false, // propagated from peer
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: true,
		},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerDPUBulkSync: true,
			types.HACritPeerPolicy:      true,
		},
	})

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateFail)
}

// --- isLocalServiceFailure Tests ---

func TestIsLocalServiceFailure(t *testing.T) {
	tests := []struct {
		name     string
		criteria types.HACriteria
		want     bool
	}{
		{
			name:     "all ok → not failure",
			criteria: types.HACriteria{types.HACritInService: true, types.HACritDpuHealth: true},
			want:     false,
		},
		{
			name:     "dpu health false → failure",
			criteria: types.HACriteria{types.HACritInService: true, types.HACritDpuHealth: false},
			want:     true,
		},
		{
			name:     "only standby false → not failure (yielding)",
			criteria: types.HACriteria{types.HACritInService: true, types.HACritDpuHealth: true, types.HACritHaStandby: false},
			want:     false,
		},
		{
			name:     "standby false + dpu false → failure",
			criteria: types.HACriteria{types.HACritInService: true, types.HACritDpuHealth: false, types.HACritHaStandby: false},
			want:     true,
		},
		{
			name:     "not in service → failure",
			criteria: types.HACriteria{types.HACritInService: false},
			want:     true,
		},
		{
			name:     "empty criteria → not failure",
			criteria: types.HACriteria{},
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLocalServiceFailure(tt.criteria)
			if got != tt.want {
				t.Errorf("isLocalServiceFailure() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- Peer Service Failure Tests ---

// TestComputeState_LocalReady_PeerSvcFailureMembershipOk: local ready, peer svc not ready
// with membership OK → ha-unavailable (peer service failure).
func TestComputeState_LocalReady_PeerSvcFailureMembershipOk(t *testing.T) {
	store := setupStore(t)
	setLocalReady(t, store)
	addPeerConnectedSvcFailure(t, store, "10.0.0.2")

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateUnavailable)
	assertReasonContains(t, result.PeerStates["10.0.0.2"].HaReason, "peer service failure")
	// Agent HA state: local ready, peer unavailable → ha-not-ready (standalone).
	assertResult(t, result, types.HAStateNotReady, types.SvcStateSuccess)
}

// TestComputeState_LocalReady_PeerSvcFailureMembershipFail: local ready,
// peer svc not ready AND membership fail → peer service failure takes precedence.
func TestComputeState_LocalReady_PeerSvcFailureMembershipFail(t *testing.T) {
	store := setupStore(t)
	setLocalReady(t, store)
	ctx := context.Background()
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:        "10.0.0.2",
		Connected: true,
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible: false, // membership failure (symptom)
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: false, // svc not ready (root cause)
		},
		AdjacencyCriteria: types.HACriteria{},
	})

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	// Peer service failure takes precedence over membership failure.
	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateUnavailable)
	assertReasonContains(t, result.PeerStates["10.0.0.2"].HaReason, "peer service failure")
}

// TestComputeState_BothNotReady_PeerSvcFailure: local not ready (service failure),
// peer not ready → ha-unavailable.
func TestComputeState_BothNotReady_PeerSvcFailure(t *testing.T) {
	store := setupStore(t)
	setLocalServiceFailure(t, store)
	ctx := context.Background()
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:        "10.0.0.2",
		Connected: true,
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible: true,
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: false, // peer svc not ready
		},
		AdjacencyCriteria: types.HACriteria{},
	})

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateUnavailable)
	assertReasonContains(t, result.PeerStates["10.0.0.2"].HaReason, "local and peer service failure")
}

// TestComputeState_LocalReady_PeerSwitchoverHoldDown: local ready (established),
// peer service not-ready because peer is in ha-switchover (standby hold-down)
// → ha-takeover (NOT ha-not-ready). This is the flap bug fix.
func TestComputeState_LocalReady_PeerSwitchoverHoldDown(t *testing.T) {
	store := setupStore(t)
	setLocalReadyEstablished(t, store)
	addPeerConnectedSvcFailureInSwitchover(t, store, "10.0.0.2")

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	// Peer should be ha-fail (not ha-unavailable) because it's in standby hold-down.
	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateFail)
	assertReasonContains(t, result.PeerStates["10.0.0.2"].HaReason, "peer standby hold-down")
	// Agent should stay in ha-takeover (not flap to ha-not-ready).
	assertResult(t, result, types.HAStateTakeover, types.SvcStateSuccess)
}

// TestComputeState_Startup_PeerSwitchoverHoldDown: on startup (no established state),
// peer in switchover hold-down → ha-not-ready (startup protection prevents takeover).
func TestComputeState_Startup_PeerSwitchoverHoldDown(t *testing.T) {
	store := setupStore(t)
	setLocalReady(t, store) // no established HaState
	addPeerConnectedSvcFailureInSwitchover(t, store, "10.0.0.2")

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	// Peer should still be ha-fail.
	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateFail)
	// But agent stays ha-not-ready due to startup protection.
	assertResult(t, result, types.HAStateNotReady, types.SvcStateSuccess)
	assertReasonContains(t, result.HaReason, "startup")
}

// TestComputeState_LocalReady_PeerSvcFailureNilMemberInfo: peer service not-ready
// with nil MemberInfo (no adjacency exchange yet) → ha-unavailable (not ha-fail).
// This ensures the nil guard works correctly.
func TestComputeState_LocalReady_PeerSvcFailureNilMemberInfo(t *testing.T) {
	store := setupStore(t)
	setLocalReady(t, store)
	addPeerConnectedSvcFailure(t, store, "10.0.0.2") // MemberInfo is nil

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateUnavailable)
	assertReasonContains(t, result.PeerStates["10.0.0.2"].HaReason, "peer service failure")
	assertResult(t, result, types.HAStateNotReady, types.SvcStateSuccess)
}

// TestComputeState_LocalReady_PeerSvcFailureNotSwitchover: peer service not-ready
// and peer reports ha-not-ready (not ha-switchover) → ha-unavailable (genuine failure).
func TestComputeState_LocalReady_PeerSvcFailureNotSwitchover(t *testing.T) {
	store := setupStore(t)
	setLocalReady(t, store)
	ctx := context.Background()
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:         "10.0.0.2",
		Connected:  true,
		MemberInfo: &types.HAPeerMember{HaState: types.HAStateNotReady},
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible:   true,
			types.HACritPeerVrfGid:       true,
			types.HACritPeerDPUKeepalive: true,
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: false,
		},
		AdjacencyCriteria: types.HACriteria{},
	})

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateUnavailable)
	assertReasonContains(t, result.PeerStates["10.0.0.2"].HaReason, "peer service failure")
}

// TestComputeState_LocalReady_PeerSwitchoverWithMembershipFail: peer in switchover
// but membership also fails → membership failure takes precedence (ha-fail with
// membership reason, not standby hold-down reason).
func TestComputeState_LocalReady_PeerSwitchoverWithMembershipFail(t *testing.T) {
	store := setupStore(t)
	setLocalReadyEstablished(t, store)
	ctx := context.Background()
	store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:         "10.0.0.2",
		Connected:  true,
		MemberInfo: &types.HAPeerMember{HaState: types.HAStateSwitchover},
		MemberCriteria: types.HACriteria{
			types.HACritPeerCompatible: false, // membership failure
		},
		ServiceCriteria: types.HACriteria{
			types.HACritPeerService: false,
		},
		AdjacencyCriteria: types.HACriteria{},
	})

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	assertPeerHaState(t, result, "10.0.0.2", types.PeerHAStateFail)
	assertReasonContains(t, result.PeerStates["10.0.0.2"].HaReason, "membership failure")
	assertResult(t, result, types.HAStateTakeover, types.SvcStateSuccess)
}
