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
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cilium/tetragon/pkg/logger"

	hastore "github.com/isovalent/hubble-fgs/pkg/nxos/store/ha"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

// peerStateResult holds the computed per-peer HA state.
type peerStateResult struct {
	IP       string
	HaState  string
	HaReason types.ReasonString
}

// stateResult holds the computed Agent HA/SVC state along with per-peer HA states.
type stateResult struct {
	HaState    string
	HaReason   types.ReasonString
	SvcState   string
	SvcReason  types.ReasonString
	PeerStates map[string]peerStateResult
}

const (
	// CriteriaMetHoldDown is the anti-flapping hold-down period for CriteriaMet recovery.
	CriteriaMetHoldDown = 15 * time.Second
)

// peerHaStatePriority returns a numeric priority for peer HA states (higher = better).
func peerHaStatePriority(state string) int {
	switch state {
	case types.PeerHAStateOk:
		return 4
	case types.PeerHAStateDegraded:
		return 3
	case types.PeerHAStateFail:
		return 2
	case types.PeerHAStateUnavailable:
		return 1
	case types.PeerHAStateNoHa:
		return 0
	default:
		return -1
	}
}

// StateMachine is a stateless computation layer that reads from the HA store
// and returns computed state. The manager persists results via the Store interface.
type StateMachine struct {
	store hastore.Reader
}

// NewStateMachine creates a new state machine backed by the given store reader.
func NewStateMachine(store hastore.Reader) *StateMachine {
	return &StateMachine{store: store}
}

// failedCriteria returns a sorted, comma-separated list of criteria names that are false.
func failedCriteria(criteria types.HACriteria) string {
	var failed []string
	for k, v := range criteria {
		if !v {
			failed = append(failed, string(k))
		}
	}
	sort.Strings(failed)
	return strings.Join(failed, ", ")
}

// failedMemberCriteria returns the names of failed membership criteria for a peer.
func failedMemberCriteria(peer types.HAPeerState) string {
	return failedCriteria(peer.MemberCriteria)
}

// failedAdjacencyCriteria returns the names of failed adjacency criteria for a peer.
func failedAdjacencyCriteria(peer types.HAPeerState) string {
	var failed []string
	for _, crit := range []types.HACriterion{
		types.HACritPeerDPUBulkSync,
		types.HACritPeerPolicy,
		types.HACritDebugAdjacencyFail,
		types.HACritDebugAdjacencyFailRemote,
	} {
		if val, exists := peer.AdjacencyCriteria[crit]; exists && !val {
			failed = append(failed, string(crit))
		}
	}
	sort.Strings(failed)
	return strings.Join(failed, ", ")
}

// failedLocalCriteria returns the names of failed local criteria.
func failedLocalCriteria(local types.HALocalState) string {
	return failedCriteria(local.Criteria)
}

// isLocalServiceFailure returns true when the local node is not-ready due to a
// hard service failure rather than deliberate standby injection. Only
// HACritHaStandby=false is considered "yielding/syncing"; every other failing
// criterion (DpuHealth, DpuInSync, InService) is a service failure.
func isLocalServiceFailure(criteria types.HACriteria) bool {
	for crit, ok := range criteria {
		if !ok && crit != types.HACritHaStandby {
			return true
		}
	}
	return false
}

// computePeerHaState computes the per-peer HA state for a single peer based on
// the state table defined in HA-states.md.
func (sm *StateMachine) computePeerHaState(peer types.HAPeerState, localReady bool, localCriteria types.HACriteria) peerStateResult {
	result := peerStateResult{IP: peer.IP}

	// Not connected → no-ha
	if !peer.AdjacencyConnected {
		result.HaState = types.PeerHAStateNoHa
		result.HaReason = types.NewReasonString("no peer connectivity")
		return result
	}

	peerSvcReady := peer.AdjacencyCriteria[types.HACritPeerService]
	membershipFail := !peer.MemberCriteria.AllOk()

	// Check adjacency criteria (bulk_sync, policy, and debug adjacency overrides)
	var adjacencyFail bool
	for _, crit := range []types.HACriterion{
		types.HACritPeerDPUBulkSync,
		types.HACritPeerPolicy,
		types.HACritDebugAdjacencyFail,
		types.HACritDebugAdjacencyFailRemote,
	} {
		if val, exists := peer.AdjacencyCriteria[crit]; exists && !val {
			adjacencyFail = true
		}
	}

	if localReady {
		// Tier 1 (worst): peer service failure → ha-unavailable.
		if !peerSvcReady {
			result.HaState = types.PeerHAStateUnavailable
			result.HaReason = types.NewReasonString("peer service failure")
			return result
		}
		// Tier 2: membership failure → ha-fail.
		if membershipFail {
			result.HaState = types.PeerHAStateFail
			result.HaReason = types.NewReasonString(fmt.Sprintf("membership failure: %s", failedMemberCriteria(peer)))
			return result
		}
		// Tier 3: adjacency failure → ha-degraded.
		if adjacencyFail {
			result.HaState = types.PeerHAStateDegraded
			result.HaReason = types.NewReasonString(fmt.Sprintf("adjacency failure: %s", failedAdjacencyCriteria(peer)))
			return result
		}
		result.HaState = types.PeerHAStateOk
		result.HaReason = types.NewReasonString("all criteria met")
		return result
	}

	// Local not ready.
	if peerSvcReady {
		// Distinguish between hard service failure and standby yielding/syncing.
		if isLocalServiceFailure(localCriteria) {
			result.HaState = types.PeerHAStateUnavailable
			result.HaReason = types.NewReasonString("local service failure")
			return result
		}
		// Only standby criterion is false → syncing/yielding.
		if membershipFail {
			result.HaState = types.PeerHAStateFail
			result.HaReason = types.NewReasonString(fmt.Sprintf("membership failure: %s", failedMemberCriteria(peer)))
			return result
		}
		if adjacencyFail {
			result.HaState = types.PeerHAStateDegraded
			result.HaReason = types.NewReasonString(fmt.Sprintf("adjacency failure: %s", failedAdjacencyCriteria(peer)))
			return result
		}
		local := sm.store.Local()
		result.HaState = types.PeerHAStateDegraded
		result.HaReason = types.NewReasonString(fmt.Sprintf("syncing: criteria not met: %s", failedLocalCriteria(local)))
		return result
	}

	// Both not ready.
	result.HaState = types.PeerHAStateUnavailable
	result.HaReason = types.NewReasonString("local and peer service failure")
	return result
}

// bestPeerHaState returns the best (highest priority) per-peer HA state result.
// Returns a no-ha result if no peers exist.
func bestPeerHaState(peerStates map[string]peerStateResult) peerStateResult {
	best := peerStateResult{
		HaState:  types.PeerHAStateNoHa,
		HaReason: types.NewReasonString("no peer connectivity"),
	}
	for _, ps := range peerStates {
		if peerHaStatePriority(ps.HaState) > peerHaStatePriority(best.HaState) {
			best = ps
		}
	}
	return best
}

// deriveActiveStandbyActive returns HAStateTakeover when transitioning from an
// already-established HA state, or HAStateNotReady on startup so that a newly
// joining switch does not disrupt a peer that is already providing service.
func deriveActiveStandbyActive(currentHaState string) string {
	switch currentHaState {
	case types.HAStateReady, types.HAStateTakeover, types.HAStateSwitchover:
		return types.HAStateTakeover
	default:
		return types.HAStateNotReady // starting up, wait for convergence
	}
}

// deriveAgentHaState maps (local service state + best per-peer HA state) to the
// cluster-level Agent HA State using the MO translation from HA-states.md.
func deriveAgentHaState(localReady bool, localCriteria types.HACriteria, best peerStateResult, local types.HALocalState) (string, types.ReasonString) {
	if localReady {
		switch best.HaState {
		case types.PeerHAStateOk:
			return types.HAStateReady, types.NewReasonString("all criteria met")
		case types.PeerHAStateDegraded:
			return types.HAStateDegraded, types.NewReasonString(fmt.Sprintf("%s (%s)", best.HaReason, best.IP))
		case types.PeerHAStateFail:
			// Startup protection: only claim TAKEOVER if already in an established state.
			state := deriveActiveStandbyActive(local.HaState)
			if state == types.HAStateTakeover {
				return types.HAStateTakeover, types.NewReasonString(fmt.Sprintf("%s (%s)", best.HaReason, best.IP))
			}
			return types.HAStateNotReady, types.NewReasonString("startup: waiting for convergence")
		case types.PeerHAStateUnavailable:
			return types.HAStateNotReady, types.NewReasonString(fmt.Sprintf("%s (%s)", best.HaReason, best.IP))
		default: // no-ha
			return types.HAStateNotReady, types.NewReasonString("no peer connectivity")
		}
	}

	// Local not ready.
	localSvcFailure := isLocalServiceFailure(localCriteria)
	switch best.HaState {
	case types.PeerHAStateOk, types.PeerHAStateDegraded, types.PeerHAStateFail:
		if !localSvcFailure {
			// Syncing/yielding — only standby criterion is false (or all ok but CriteriaMet not promoted yet).
			return types.HAStateSwitchover, types.NewReasonString(fmt.Sprintf("syncing: %s", failedLocalCriteria(local)))
		}
		// Hard service failure.
		return types.HAStateUnavailable, types.NewReasonString(fmt.Sprintf("local service failure: %s", failedLocalCriteria(local)))
	case types.PeerHAStateUnavailable:
		return types.HAStateUnavailable, types.NewReasonString("local and peer service failure")
	default: // no-ha
		return types.HAStateNotReady, types.NewReasonString("no peer connectivity")
	}
}

// ComputeState computes the derived HA and service states based on the state table
// defined in HA-states.md. It first computes per-peer HA states, then derives the
// cluster-level Agent HA State from the best per-peer state.
func (sm *StateMachine) ComputeState() stateResult {
	local := sm.store.Local()
	localReady := sm.stableCriteriaMet(local)

	// Phase 1: Compute per-peer HA states.
	allPeers := sm.store.AllPeers()
	peerStates := make(map[string]peerStateResult, len(allPeers))
	for ip, peer := range allPeers {
		peerStates[ip] = sm.computePeerHaState(peer, localReady, local.Criteria)
	}

	// Phase 2: Derive SVC state from local readiness.
	svcState := types.SvcStateSuccess
	var svcReason types.ReasonString
	if localReady {
		svcReason = types.NewReasonString("all criteria met")
	} else {
		svcState = types.SvcStateFailure
		if isLocalServiceFailure(local.Criteria) {
			svcReason = types.NewReasonString(fmt.Sprintf("criteria not met: %s", failedLocalCriteria(local)))
		} else {
			svcReason = types.NewReasonString(fmt.Sprintf("syncing: %s", failedLocalCriteria(local)))
		}
	}

	// Phase 3: Derive Agent HA State from best per-peer HA state.
	best := bestPeerHaState(peerStates)
	agentHa, agentReason := deriveAgentHaState(localReady, local.Criteria, best, local)

	return stateResult{
		HaState:    agentHa,
		HaReason:   agentReason,
		SvcState:   svcState,
		SvcReason:  svcReason,
		PeerStates: peerStates,
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

// EvaluateStandbyCrit determines whether the HACritHaStandby criterion should be
// injected or removed. Returns (shouldInject, shouldRemove).
//
// Inject when: a peer reports HA_TAKEOVER (already the active side), peer service
// is ready, raw peer criteria have not converged, and this node doesn't win the
// tiebreaker (leader stays active).
//
// Remove when: no peer reports TAKEOVER, or criteria have converged.
//
// Uses raw peer member criteria (not derived peer HA state) to avoid a feedback
// loop: injecting standby makes local not-ready, which would make derived peer
// state "degraded", keeping standby injected forever.
func (sm *StateMachine) EvaluateStandbyCrit(localHaState string, isLeader bool) (inject, remove bool) {
	local := sm.store.Local()
	_, hasStandby := local.Criteria[types.HACritHaStandby]

	allPeers := sm.store.AllPeers()

	peerIsTakeover := false
	peerSvcReady := false
	bestCritOk := false

	for _, peer := range allPeers {
		if !peer.AdjacencyConnected {
			continue
		}
		if peer.MemberInfo != nil && peer.MemberInfo.HaState == types.HAStateTakeover {
			peerIsTakeover = true
		}
		if peer.AdjacencyCriteria[types.HACritPeerService] {
			peerSvcReady = true
		}
		// Check raw peer criteria convergence (member + adjacency excluding indicators).
		if peer.MemberCriteria.AllOk() && peer.AdjacencyCriteria[types.HACritPeerDPUBulkSync] && peer.AdjacencyCriteria[types.HACritPeerPolicy] {
			bestCritOk = true
		}
	}

	// Yield to the peer already in TAKEOVER when criteria haven't converged.
	// Tiebreaker: if both are TAKEOVER, leader wins and does NOT inject standby.
	amTakeover := localHaState == types.HAStateTakeover
	shouldBeStandby := peerIsTakeover && peerSvcReady && !bestCritOk &&
		!(amTakeover && isLeader)

	if shouldBeStandby && !hasStandby {
		return true, false
	}
	if !shouldBeStandby && hasStandby {
		return false, true
	}
	return false, false
}
