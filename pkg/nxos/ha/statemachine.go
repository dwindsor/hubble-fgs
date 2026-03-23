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
	"time"

	"github.com/cilium/tetragon/pkg/logger"

	hastore "github.com/isovalent/hubble-fgs/pkg/nxos/store/ha"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

// stateResult holds the computed HA/SVC state along with reasons.
type stateResult struct {
	HaState   string
	HaReason  types.ReasonString
	SvcState  string
	SvcReason types.ReasonString
}

const (
	// CriteriaMetHoldDown is the anti-flapping hold-down period for CriteriaMet recovery.
	CriteriaMetHoldDown = 30 * time.Second

	// NxUpdateTimeout is the debounce timeout for gNMI SET operations.
	NxUpdateTimeout = 30 * time.Second
)

// StateMachine is a stateless computation layer that reads from the HA store
// and returns computed state. The manager persists results via the Store interface.
type StateMachine struct {
	store hastore.Reader
}

// NewStateMachine creates a new state machine backed by the given store reader.
func NewStateMachine(store hastore.Reader) *StateMachine {
	return &StateMachine{store: store}
}

// ComputeState computes the derived HA and service states based on current store state.
// Returns a stateResult with haState, svcState and their reasons.
//
// State transitions follow HA.md:
//
//	Row 7: Local criteria not met → ha_switchover, svc_failure (regardless of peer state or AdjacencyReached)
//	Row 4: All peer adjacency criteria OK → ha_ready
//	Rows 5,6: AdjacencyReached + peer adjacency lost:
//	  - Leader → ha_takeover, svc_success
//	  - Follower → ha_switchover, svc_failure
//	Row 2: AdjacencyReached==false + membership failure + Leader → ha_notready
//	Row 3: AdjacencyReached==false + membership failure + Follower → ha_switchover
//	Row 1: AdjacencyReached==false + no connectivity/no svc → ha_notready
func (sm *StateMachine) ComputeState() stateResult {
	local := sm.store.Local()

	// Row 7: Local criteria not met → ha_switchover regardless of peer state.
	if !sm.stableCriteriaMet(local) {
		logger.GetLogger().Debug("Local criteria not met: ha_switchover")
		return stateResult{
			HaState:   types.HAStateSwitchover,
			HaReason:  types.NewReasonString("local criteria not met"),
			SvcState:  types.SvcStateFailure,
			SvcReason: types.NewReasonString("local criteria not met"),
		}
	}

	// Row 4: All peer adjacency criteria pass → ha_ready.
	if sm.store.AnyPeerAdjacencyCriteriaOk() {
		return stateResult{
			HaState:  types.HAStateReady,
			SvcState: types.SvcStateSuccess,
		}
	}

	// Peer adjacency is not OK. Behavior depends on whether adjacency was ever reached.
	if local.AdjacencyReached {
		if local.Leader {
			// Rows 5 & 6: Leader + adjacency lost after reached → ha_takeover.
			logger.GetLogger().Info("Peer adjacency lost after adjacency reached: leader ha_takeover")
			return stateResult{
				HaState:  types.HAStateTakeover,
				HaReason: types.NewReasonString("peer adjacency lost after adjacency reached: leader takeover"),
				SvcState: types.SvcStateSuccess,
			}
		}
		// Rows 5 & 6: Follower + adjacency lost after reached → ha_switchover.
		logger.GetLogger().Info("Peer adjacency lost after adjacency reached: follower ha_switchover")
		return stateResult{
			HaState:   types.HAStateSwitchover,
			HaReason:  types.NewReasonString("peer adjacency lost after adjacency reached: follower switchover"),
			SvcState:  types.SvcStateFailure,
			SvcReason: types.NewReasonString("peer adjacency lost: follower"),
		}
	}

	// Adjacency never reached. Check membership criteria.
	if sm.store.AnyPeerMemberCriteriaFail() {
		if local.Leader {
			// Row 2: Leader + membership failure → ha_notready.
			logger.GetLogger().Info("Peer member criteria failure: leader going ha_notready")
			return stateResult{
				HaState:  types.HAStateNotReady,
				HaReason: types.NewReasonString("peer member criteria failure: leader not-ready"),
				SvcState: types.SvcStateSuccess,
			}
		}
		// Row 3: Follower + membership failure → ha_switchover.
		logger.GetLogger().Info("Peer member criteria failure: follower going ha_switchover")
		return stateResult{
			HaState:   types.HAStateSwitchover,
			HaReason:  types.NewReasonString("peer member criteria failure: follower switchover"),
			SvcState:  types.SvcStateFailure,
			SvcReason: types.NewReasonString("peer member criteria failure"),
		}
	}

	// Row 1: No connectivity / no service firewall on peer → ha_notready.
	return stateResult{
		HaState:  types.HAStateNotReady,
		HaReason: types.NewReasonString("adjacency not yet reached"),
		SvcState: types.SvcStateSuccess,
	}
}

// ComputeStateForRemoval computes the derived states when peer intentionally removes HA.
// Unlike ComputeState, this always goes to HA_NOTREADY (not SWITCHOVER) since removal is intentional.
func (sm *StateMachine) ComputeStateForRemoval() stateResult {
	local := sm.store.Local()

	if sm.stableCriteriaMet(local) {
		if sm.store.AnyPeerAdjacencyCriteriaOk() {
			return stateResult{
				HaState:  types.HAStateReady,
				SvcState: types.SvcStateSuccess,
			}
		}
		return stateResult{
			HaState:  types.HAStateNotReady,
			HaReason: types.NewReasonString("peer removed"),
			SvcState: types.SvcStateSuccess,
		}
	}
	return stateResult{
		HaState:   types.HAStateSwitchover,
		HaReason:  types.NewReasonString("local criteria not met after peer removal"),
		SvcState:  types.SvcStateFailure,
		SvcReason: types.NewReasonString("local criteria not met"),
	}
}

// RecalculateCriteriaMet applies the anti-flapping logic for CriteriaMet state transitions.
// Takes a snapshot of the local state, returns updated copy.
// Degradation (true->false) is immediate. Recovery (false->true) starts a hold-down.
func (sm *StateMachine) RecalculateCriteriaMet(local types.HALocalState) types.HALocalState {
	now := time.Now().Unix()
	criteriaMet := local.Criteria.AllOk()

	if local.CriteriaMet && !criteriaMet {
		// Degradation: apply immediately (fail-fast).
		logger.GetLogger().Debug("Local HA State degraded", "prev", true, "new", false)
		local.CriteriaMet = false
		local.CriteriaMetEpoch = now
		local.CriteriaRecoveryPending = false
		local.CriteriaRecoveryEpoch = 0
	} else if !local.CriteriaMet && criteriaMet {
		// Recovery: start or maintain hold-down.
		if !local.CriteriaRecoveryPending {
			logger.GetLogger().Info("Local HA State recovery pending, starting hold-down",
				"holdDown", CriteriaMetHoldDown)
			local.CriteriaRecoveryPending = true
			local.CriteriaRecoveryEpoch = now
		}
		// Promotion is handled by CheckHoldDown in the periodic loop.
	} else if !local.CriteriaMet && !criteriaMet {
		// Still degraded — cancel any pending recovery if criteria flapped back to false.
		if local.CriteriaRecoveryPending {
			logger.GetLogger().Info("Local HA State hold-down cancelled, criteria failed again",
				"flapCount", local.CriteriaFlapCount+1)
			local.CriteriaRecoveryPending = false
			local.CriteriaRecoveryEpoch = 0
			local.CriteriaFlapCount++
		}
	}

	return local
}

// CheckHoldDown checks whether a pending CriteriaMet recovery has satisfied the hold-down period.
// Returns (promoted, updated local state).
func (sm *StateMachine) CheckHoldDown(local types.HALocalState) (bool, types.HALocalState) {
	if !local.CriteriaRecoveryPending {
		return false, local
	}

	now := time.Now().Unix()
	elapsed := now - local.CriteriaRecoveryEpoch
	holdDownSec := int64(CriteriaMetHoldDown / time.Second)

	if elapsed < holdDownSec {
		logger.GetLogger().Debug("Local HA State hold-down in progress",
			"elapsed", elapsed, "remaining", holdDownSec-elapsed)
		return false, local
	}

	// Verify criteria still pass before promoting.
	if !local.Criteria.AllOk() {
		logger.GetLogger().Info("Local HA State hold-down expired but criteria no longer pass, cancelling")
		local.CriteriaRecoveryPending = false
		local.CriteriaRecoveryEpoch = 0
		local.CriteriaFlapCount++
		return false, local
	}

	// Promote: hold-down satisfied and criteria still all-true.
	logger.GetLogger().Info("Local HA State hold-down complete, HA state set to true",
		"holdDown", CriteriaMetHoldDown, "flapCount", local.CriteriaFlapCount)
	local.CriteriaMet = true
	local.CriteriaMetEpoch = now
	local.CriteriaRecoveryPending = false
	local.CriteriaRecoveryEpoch = 0
	local.CriteriaFlapCount = 0

	return true, local
}

// stableCriteriaMet returns the effective CriteriaMet value that respects the anti-flapping hold-down.
func (sm *StateMachine) stableCriteriaMet(local types.HALocalState) bool {
	if local.CriteriaRecoveryPending {
		return false
	}
	return local.CriteriaMet
}
