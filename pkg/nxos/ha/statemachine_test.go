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
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

// setupStore creates a store with local criteria met and no peers, ready for per-test configuration.
func setupStore(t *testing.T) hastore.Store {
	t.Helper()
	return hastore.NewStore(context.Background())
}

// setLocalCriteriaMet sets CriteriaMet=true with required criteria all passing.
func setLocalCriteriaMet(t *testing.T, store hastore.Store, isLeader bool) {
	t.Helper()
	ctx := context.Background()
	store.UpdateLocalCriterion(ctx, types.HACritSvcRedir, true)
	store.UpdateLocalCriterion(ctx, types.HACritDpuHealth, true)
	store.UpdateLocalCriterion(ctx, types.HACritDpuInSync, true)
	local := store.Local()
	local.CriteriaMet = true
	local.Leader = isLeader
	store.SetLocal(ctx, local)
}

// setAdjacencyReached marks AdjacencyReached=true on local state.
func setAdjacencyReached(t *testing.T, store hastore.Store) {
	t.Helper()
	store.SetLocalAdjacencyReached(context.Background(), true)
}

// addPeerWithMembershipOK adds a peer with member criteria passing but adjacency not yet OK.
func addPeerWithMembershipOK(t *testing.T, store hastore.Store, ip string) {
	t.Helper()
	ctx := context.Background()
	store.SetPeer(ctx, ip, types.HAPeerState{
		IP:             ip,
		MemberCriteria: types.HACriteria{types.HACritPeerCompatible: true},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerIpConfig:     true,
			types.HACritPeerServiceRedir: false, // adjacency not yet established
		},
	})
}

// addPeerWithMembershipFail adds a peer with member criteria failing and adjacency not OK.
func addPeerWithMembershipFail(t *testing.T, store hastore.Store, ip string) {
	t.Helper()
	ctx := context.Background()
	store.SetPeer(ctx, ip, types.HAPeerState{
		IP:             ip,
		MemberCriteria: types.HACriteria{types.HACritPeerCompatible: false},
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerIpConfig:     true,
			types.HACritPeerServiceRedir: false, // adjacency not established due to membership failure
		},
	})
}

// addPeerWithAllAdjacencyOK adds a peer with all adjacency criteria passing.
func addPeerWithAllAdjacencyOK(t *testing.T, store hastore.Store, ip string) {
	t.Helper()
	ctx := context.Background()
	store.SetPeer(ctx, ip, types.HAPeerState{
		IP:                 ip,
		MemberCriteria:     types.HACriteria{types.HACritPeerCompatible: true},
		MemberCriteriaMet:  true,
		AdjacencyConnected: true,
		AdjacencyCriteria: types.HACriteria{
			types.HACritPeerIpConfig:     true,
			types.HACritPeerServiceRedir: true,
			types.HACritPeerPolicy:       true,
		},
		AdjacencyCriteriaMet: true,
	})
}

// TestComputeState_Row1_NoConnectivity tests Row 1: no connectivity, adjacency not reached → ha_notready.
func TestComputeState_Row1_NoConnectivity(t *testing.T) {
	store := setupStore(t)
	setLocalCriteriaMet(t, store, true)
	// No peers added → no connectivity.

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	if result.HaState != types.HAStateNotReady {
		t.Errorf("Row 1: expected HaState=%s, got %s", types.HAStateNotReady, result.HaState)
	}
	if result.SvcState != types.SvcStateSuccess {
		t.Errorf("Row 1: expected SvcState=%s, got %s", types.SvcStateSuccess, result.SvcState)
	}
}

// TestComputeState_Row2_LeaderMembershipFailure tests Row 2: leader + membership failure,
// adjacency not reached → ha_notready, svc_success.
func TestComputeState_Row2_LeaderMembershipFailure(t *testing.T) {
	store := setupStore(t)
	setLocalCriteriaMet(t, store, true /* isLeader */)
	addPeerWithMembershipFail(t, store, "10.0.0.2")

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	if result.HaState != types.HAStateNotReady {
		t.Errorf("Row 2: expected HaState=%s, got %s", types.HAStateNotReady, result.HaState)
	}
	if result.SvcState != types.SvcStateSuccess {
		t.Errorf("Row 2: expected SvcState=%s, got %s", types.SvcStateSuccess, result.SvcState)
	}
}

// TestComputeState_Row3_FollowerMembershipFailure tests Row 3: follower + membership failure,
// adjacency not reached → ha_switchover, svc_failure.
func TestComputeState_Row3_FollowerMembershipFailure(t *testing.T) {
	store := setupStore(t)
	setLocalCriteriaMet(t, store, false /* isLeader=false → follower */)
	addPeerWithMembershipFail(t, store, "10.0.0.2")

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	if result.HaState != types.HAStateSwitchover {
		t.Errorf("Row 3: expected HaState=%s, got %s", types.HAStateSwitchover, result.HaState)
	}
	if result.SvcState != types.SvcStateFailure {
		t.Errorf("Row 3: expected SvcState=%s, got %s", types.SvcStateFailure, result.SvcState)
	}
}

// TestComputeState_Row4_BothInService tests Row 4: both in-service, adjacency OK → ha_ready, svc_success.
func TestComputeState_Row4_BothInService(t *testing.T) {
	store := setupStore(t)
	setLocalCriteriaMet(t, store, true)
	addPeerWithAllAdjacencyOK(t, store, "10.0.0.2")

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	if result.HaState != types.HAStateReady {
		t.Errorf("Row 4: expected HaState=%s, got %s", types.HAStateReady, result.HaState)
	}
	if result.SvcState != types.SvcStateSuccess {
		t.Errorf("Row 4: expected SvcState=%s, got %s", types.SvcStateSuccess, result.SvcState)
	}
}

// TestComputeState_Row5_AdjacencyFailure_Leader tests Row 5: leader + adjacency failure
// after adjacency reached → ha_takeover, svc_success.
func TestComputeState_Row5_AdjacencyFailure_Leader(t *testing.T) {
	store := setupStore(t)
	setLocalCriteriaMet(t, store, true /* isLeader */)
	setAdjacencyReached(t, store)
	addPeerWithMembershipOK(t, store, "10.0.0.2")

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	if result.HaState != types.HAStateTakeover {
		t.Errorf("Row 5 Leader: expected HaState=%s, got %s", types.HAStateTakeover, result.HaState)
	}
	if result.SvcState != types.SvcStateSuccess {
		t.Errorf("Row 5 Leader: expected SvcState=%s, got %s", types.SvcStateSuccess, result.SvcState)
	}
}

// TestComputeState_Row5_AdjacencyFailure_Follower tests Row 5: follower + adjacency failure
// after adjacency reached → ha_switchover, svc_failure.
func TestComputeState_Row5_AdjacencyFailure_Follower(t *testing.T) {
	store := setupStore(t)
	setLocalCriteriaMet(t, store, false /* isLeader=false → follower */)
	setAdjacencyReached(t, store)
	addPeerWithMembershipOK(t, store, "10.0.0.2")

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	if result.HaState != types.HAStateSwitchover {
		t.Errorf("Row 5 Follower: expected HaState=%s, got %s", types.HAStateSwitchover, result.HaState)
	}
	if result.SvcState != types.SvcStateFailure {
		t.Errorf("Row 5 Follower: expected SvcState=%s, got %s", types.SvcStateFailure, result.SvcState)
	}
}

// TestComputeState_Row6_NoConnectivityAfterAdjReached_Leader tests Row 6: leader + no connectivity
// after adjacency reached → ha_takeover, svc_success.
func TestComputeState_Row6_NoConnectivityAfterAdjReached_Leader(t *testing.T) {
	store := setupStore(t)
	setLocalCriteriaMet(t, store, true /* isLeader */)
	setAdjacencyReached(t, store)

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	if result.HaState != types.HAStateTakeover {
		t.Errorf("Row 6 Leader: expected HaState=%s, got %s", types.HAStateTakeover, result.HaState)
	}
	if result.SvcState != types.SvcStateSuccess {
		t.Errorf("Row 6 Leader: expected SvcState=%s, got %s", types.SvcStateSuccess, result.SvcState)
	}
}

// TestComputeState_Row6_NoConnectivityAfterAdjReached_Follower tests Row 6: follower + no connectivity
// after adjacency reached → ha_switchover, svc_failure.
func TestComputeState_Row6_NoConnectivityAfterAdjReached_Follower(t *testing.T) {
	store := setupStore(t)
	setLocalCriteriaMet(t, store, false /* isLeader=false → follower */)
	setAdjacencyReached(t, store)

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	if result.HaState != types.HAStateSwitchover {
		t.Errorf("Row 6 Follower: expected HaState=%s, got %s", types.HAStateSwitchover, result.HaState)
	}
	if result.SvcState != types.SvcStateFailure {
		t.Errorf("Row 6 Follower: expected SvcState=%s, got %s", types.SvcStateFailure, result.SvcState)
	}
}

// TestComputeState_Row7a_LocalCriteriaFailure_AdjNotReached tests Row 7a: local criteria failure,
// adjacency not reached → ha_switchover, svc_failure.
func TestComputeState_Row7a_LocalCriteriaFailure_AdjNotReached(t *testing.T) {
	store := setupStore(t)
	// Do NOT set CriteriaMet — local criteria are failing.
	addPeerWithAllAdjacencyOK(t, store, "10.0.0.2")

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	if result.HaState != types.HAStateSwitchover {
		t.Errorf("Row 7a: expected HaState=%s, got %s", types.HAStateSwitchover, result.HaState)
	}
	if result.SvcState != types.SvcStateFailure {
		t.Errorf("Row 7a: expected SvcState=%s, got %s", types.SvcStateFailure, result.SvcState)
	}
}

// TestComputeState_Row7b_LocalCriteriaFailure_AdjReached tests Row 7b: local criteria failure,
// adjacency previously reached → still ha_switchover (local criteria always wins).
func TestComputeState_Row7b_LocalCriteriaFailure_AdjReached(t *testing.T) {
	store := setupStore(t)
	// Set adjacency reached but then local criteria fail (e.g. DPU went unhealthy).
	setAdjacencyReached(t, store)
	// Do NOT set CriteriaMet.
	addPeerWithAllAdjacencyOK(t, store, "10.0.0.2")

	sm := NewStateMachine(store)
	result := sm.ComputeState()

	if result.HaState != types.HAStateSwitchover {
		t.Errorf("Row 7b: expected HaState=%s, got %s", types.HAStateSwitchover, result.HaState)
	}
	if result.SvcState != types.SvcStateFailure {
		t.Errorf("Row 7b: expected SvcState=%s, got %s", types.SvcStateFailure, result.SvcState)
	}
}

// TestAdjacencyReached_Sticky verifies that AdjacencyReached is a one-way latch:
// once true, it stays true even when HA state drops to ha_notready or ha_takeover/ha_switchover.
func TestAdjacencyReached_Sticky(t *testing.T) {
	store := setupStore(t)
	setLocalCriteriaMet(t, store, true /* isLeader */)
	setAdjacencyReached(t, store)

	// Start with no peers — leader should give ha_takeover (not reset AdjacencyReached).
	sm := NewStateMachine(store)
	result := sm.ComputeState()
	if result.HaState != types.HAStateTakeover {
		t.Errorf("expected ha_takeover after adjacency reached + no peers (leader), got %s", result.HaState)
	}

	// AdjacencyReached should still be true.
	local := store.Local()
	if !local.AdjacencyReached {
		t.Error("AdjacencyReached should remain true (sticky latch), but was reset to false")
	}
}

// TestComputeState_AdjacencyTimeout_vs_Failure verifies the distinction between
// adjacency timeout (AdjacencyConnected=false) and adjacency failure (connected but criteria fail).
func TestComputeState_AdjacencyTimeout_vs_Failure(t *testing.T) {
	ctx := context.Background()

	// Case 1: AdjacencyConnected=false with all criteria true → AnyPeerAdjacencyCriteriaOk=false (timeout case).
	t.Run("timeout_not_reported_as_ok", func(t *testing.T) {
		store := setupStore(t)
		setLocalCriteriaMet(t, store, true)
		setAdjacencyReached(t, store)
		// Peer connected=false but criteria still show all true (stale from before timeout).
		store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
			IP:                 "10.0.0.2",
			MemberCriteria:     types.HACriteria{types.HACritPeerCompatible: true},
			MemberCriteriaMet:  true,
			AdjacencyConnected: false, // timeout: connection lost
			AdjacencyCriteria: types.HACriteria{
				types.HACritPeerIpConfig:     true,
				types.HACritPeerServiceRedir: true,
				types.HACritPeerPolicy:       true,
			},
			AdjacencyCriteriaMet: true,
		})

		// AnyPeerAdjacencyCriteriaOk must return false when AdjacencyConnected=false.
		if store.AnyPeerAdjacencyCriteriaOk() {
			t.Error("AnyPeerAdjacencyCriteriaOk should be false when AdjacencyConnected=false (timeout)")
		}
	})

	// Case 2: AdjacencyConnected=true but peer_service_redir=false → AnyPeerAdjacencyCriteriaOk=false (failure case).
	t.Run("live_failure_reported_as_not_ok", func(t *testing.T) {
		store := setupStore(t)
		setLocalCriteriaMet(t, store, true)
		setAdjacencyReached(t, store)
		store.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
			IP:                 "10.0.0.2",
			MemberCriteria:     types.HACriteria{types.HACritPeerCompatible: true},
			MemberCriteriaMet:  true,
			AdjacencyConnected: true, // still connected
			AdjacencyCriteria: types.HACriteria{
				types.HACritPeerIpConfig:     true,
				types.HACritPeerServiceRedir: false, // peer SVC failed
				types.HACritPeerPolicy:       true,
			},
		})

		if store.AnyPeerAdjacencyCriteriaOk() {
			t.Error("AnyPeerAdjacencyCriteriaOk should be false when peer_service_redir=false")
		}
	})
}

// TestComputeStateForRemoval_LocalCriteriaFail tests that local criteria failure after
// peer removal yields ha_switchover (not ha_notready).
func TestComputeStateForRemoval_LocalCriteriaFail(t *testing.T) {
	store := setupStore(t)
	// Do NOT set CriteriaMet.

	sm := NewStateMachine(store)
	result := sm.ComputeStateForRemoval()

	if result.HaState != types.HAStateSwitchover {
		t.Errorf("expected HaState=%s after removal with local criteria fail, got %s",
			types.HAStateSwitchover, result.HaState)
	}
	if result.SvcState != types.SvcStateFailure {
		t.Errorf("expected SvcState=%s after removal with local criteria fail, got %s",
			types.SvcStateFailure, result.SvcState)
	}
}
