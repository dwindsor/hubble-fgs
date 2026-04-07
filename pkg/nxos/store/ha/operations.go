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
	"time"

	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

func (s *haStore) SetEnabled(ctx context.Context, state string) {
	s.mu.Lock()
	old := s.enabled
	s.enabled = state
	s.mu.Unlock()
	if old != state {
		s.notify(Event{Type: EventAdminStateChanged})
		s.persist(ctx)
	}
}

func (s *haStore) SetSwitchState(ctx context.Context, state string) {
	s.mu.Lock()
	old := s.switchState
	s.switchState = state
	s.mu.Unlock()
	if old != state {
		s.notify(Event{Type: EventSwitchStateChanged})
	}
	s.persist(ctx)
}

func (s *haStore) SetHaIP(ctx context.Context, ip string) {
	s.mu.Lock()
	changed := s.haIP != ip
	s.haIP = ip
	s.mu.Unlock()
	s.persist(ctx)
	if changed {
		s.notify(Event{Type: EventHaIPChanged})
	}
}

// SetHaPort persists the HA gRPC port and SETs it to NXOS via gNMI.
// This is an outbound-only operation; the path is never subscribed.
func (s *haStore) SetHaPort(ctx context.Context, port uint16) error {
	s.mu.Lock()
	changed := s.haPort != port
	s.haPort = port
	handler := s.gnmiHandler
	s.mu.Unlock()

	s.persist(ctx)

	if handler == nil || !changed {
		return nil
	}
	return handler.Set(ctx, paths.HAStoreHaPort, fmt.Sprintf("%d", port))
}

func (s *haStore) SetLocal(ctx context.Context, local types.HALocalState) {
	s.mu.Lock()
	s.localState = local
	if s.localState.Criteria == nil {
		s.localState.Criteria = make(types.HACriteria)
	}
	s.mu.Unlock()
	s.notify(Event{Type: EventLocalStateChanged})
	// Not persisted — local state is fully rebuilt at startup via gNMI and HA protocol.
}

func (s *haStore) SetLeader(ctx context.Context, isLeader bool) {
	s.mu.Lock()
	old := s.localState.Leader
	s.localState.Leader = isLeader
	s.mu.Unlock()

	if old != isLeader {
		s.notify(Event{Type: EventLeaderChanged})
		// Not persisted — leader is determined at runtime by IP comparison.
	}
}

func (s *haStore) UpdateLocalCriterion(ctx context.Context, crit types.HACriterion, val bool) {
	s.mu.Lock()
	if s.localState.Criteria == nil {
		s.localState.Criteria = make(types.HACriteria)
	}
	old := s.localState.Criteria[crit]
	s.localState.Criteria[crit] = val
	s.mu.Unlock()

	if old != val {
		s.notify(Event{Type: EventCriterionSet, Criterion: string(crit), Value: val})
		s.notify(Event{Type: EventCriterionChanged, Criterion: string(crit), Value: val})
		// Not persisted — criteria are rebuilt from device/DPU state on startup.
	}
}

func (s *haStore) RemoveLocalCriterion(ctx context.Context, crit types.HACriterion) {
	s.mu.Lock()
	_, had := s.localState.Criteria[crit]
	delete(s.localState.Criteria, crit)
	s.mu.Unlock()

	if had {
		s.notify(Event{Type: EventCriterionChanged, Criterion: string(crit), Value: true})
		// Not persisted — criteria are rebuilt from device/DPU state on startup.
	}
}

func (s *haStore) SetLocalDerivedStates(ctx context.Context, haState, svcState string, haReason, svcReason types.ReasonString, pushSvcToNx bool) {
	s.mu.Lock()
	now := time.Now().Unix()
	haChanged := s.localState.HaState != haState
	haReasonChanged := s.localState.HaStateReason != haReason
	svcChanged := s.localState.SvcState != svcState
	svcReasonChanged := s.localState.SvcStateReason != svcReason
	changed := haChanged || svcChanged
	s.localState.HaState = haState
	s.localState.HaStateReason = haReason
	s.localState.SvcState = svcState
	s.localState.SvcStateReason = svcReason
	if haChanged {
		s.localState.HaStateEpoch = now
	}
	if svcChanged {
		s.localState.SvcStateEpoch = now
	}
	// Only push HA state to NX-OS when HA is enabled. When HA is disabled
	// the switch does not have an HA container and rejects SET operations
	// on HA paths with "Only end-users can create high-availability config".
	pushHaToNx := s.enabled == "enabled"
	handler := s.gnmiHandler
	s.mu.Unlock()

	if changed {
		s.notify(Event{Type: EventDerivedStateChanged})
		// Not persisted — derived states are computed by the HA state machine at runtime.
	}

	if handler == nil {
		return
	}
	// Write SVC state first so the switch sees local service readiness
	// before the aggregate HA state.
	if pushSvcToNx && svcChanged {
		if err := handler.Set(ctx, paths.HAStoreLocalSvcState, svcState); err != nil {
			logger.GetLogger().Warn("Failed to set local svc state via gNMI", "error", err)
		}
	}
	if pushSvcToNx && (svcChanged || svcReasonChanged) {
		if err := handler.Set(ctx, paths.HAStoreLocalSvcStateReason, svcReason.String()); err != nil {
			logger.GetLogger().Warn("Failed to set local svc state reason via gNMI", "error", err)
		}
	}
	if pushHaToNx && haChanged {
		if err := handler.Set(ctx, paths.HAStoreLocalHaState, haState); err != nil {
			logger.GetLogger().Warn("Failed to set local ha state via gNMI", "error", err)
		}
	}
	if pushHaToNx && (haChanged || haReasonChanged) {
		if err := handler.Set(ctx, paths.HAStoreLocalHaStateReason, haReason.String()); err != nil {
			logger.GetLogger().Warn("Failed to set local ha state reason via gNMI", "error", err)
		}
	}
}

func (s *haStore) SetLocalPolicyRevision(ctx context.Context, rev string) {
	s.mu.Lock()
	s.localState.PolicyRev = rev
	s.mu.Unlock()
	// Not persisted — policy state is rebuilt from controller on startup.
}

func (s *haStore) SetLocalPolicyCheck(ctx context.Context, check bool) {
	s.mu.Lock()
	s.localState.PolicyCheck = check
	s.mu.Unlock()
	// Not persisted — policy state is rebuilt from controller on startup.
}

func (s *haStore) SetLocalCriteriaMet(ctx context.Context, local types.HALocalState) {
	s.mu.Lock()
	s.localState.CriteriaMet = local.CriteriaMet
	s.localState.CriteriaMetEpoch = local.CriteriaMetEpoch
	s.localState.CriteriaRecoveryPending = local.CriteriaRecoveryPending
	s.localState.CriteriaRecoveryEpoch = local.CriteriaRecoveryEpoch
	s.localState.CriteriaFlapCount = local.CriteriaFlapCount
	s.mu.Unlock()
	s.notify(Event{Type: EventLocalStateChanged})
	// Not persisted — criteria met state is computed at runtime.
}

func (s *haStore) SetPeer(ctx context.Context, ip string, info types.HAPeerState) {
	s.mu.Lock()
	info.IP = ip
	if info.MemberCriteria == nil {
		info.MemberCriteria = make(types.HACriteria)
	}
	if info.ServiceCriteria == nil {
		info.ServiceCriteria = make(types.HACriteria)
	}
	if info.AdjacencyCriteria == nil {
		info.AdjacencyCriteria = make(types.HACriteria)
	}
	// Preserve IpConfigState from the existing peer if the incoming state
	// doesn't include it. This field is managed by gNMI and must not be
	// lost when SetPeer is called from code paths that don't set it (e.g.,
	// storage reload or partial gNMI updates).
	if info.IpConfigState == "" {
		if existing, ok := s.peers[ip]; ok {
			info.IpConfigState = existing.IpConfigState
		}
	}
	info.MemberCriteriaMet = len(info.MemberCriteria) > 0 && info.MemberCriteria.AllOk()
	if info.MemberCriteriaMet && info.MemberCriteriaMetEpoch == 0 {
		info.MemberCriteriaMetEpoch = time.Now().Unix()
	}
	info.ServiceCriteriaMet = len(info.ServiceCriteria) > 0 && info.ServiceCriteria.AllOk()
	if info.ServiceCriteriaMet && info.ServiceCriteriaMetEpoch == 0 {
		info.ServiceCriteriaMetEpoch = time.Now().Unix()
	}
	info.AdjacencyCriteriaMet = len(info.AdjacencyCriteria) > 0 && info.AdjacencyCriteria.AllOk()
	if info.AdjacencyCriteriaMet && info.AdjacencyCriteriaMetEpoch == 0 {
		info.AdjacencyCriteriaMetEpoch = time.Now().Unix()
	}
	_, existed := s.peers[ip]
	s.peers[ip] = info
	s.mu.Unlock()

	if existed {
		s.notify(Event{Type: EventMemberUpdated, PeerIP: ip})
	} else {
		s.notify(Event{Type: EventPeerAdded, PeerIP: ip})
	}
	s.persist(ctx)
}

func (s *haStore) RemovePeer(ctx context.Context, ip string) {
	s.mu.Lock()
	_, exists := s.peers[ip]
	if exists {
		delete(s.peers, ip)
	}
	s.mu.Unlock()

	if exists {
		s.notify(Event{Type: EventPeerRemoved, PeerIP: ip})
		s.persist(ctx)
	}
}

func (s *haStore) UpdatePeerMemberCriterion(ctx context.Context, ip string, crit types.HACriterion, val bool) {
	s.mu.Lock()
	peer, ok := s.peers[ip]
	if !ok {
		s.mu.Unlock()
		return
	}
	if peer.MemberCriteria == nil {
		peer.MemberCriteria = make(types.HACriteria)
	}
	peer.MemberCriteria[crit] = val
	newMet := len(peer.MemberCriteria) > 0 && peer.MemberCriteria.AllOk()
	peer.MemberCriteriaMet = newMet
	if newMet {
		peer.MemberCriteriaMetEpoch = time.Now().Unix()
	}
	s.peers[ip] = peer
	s.mu.Unlock()
	s.notify(Event{Type: EventPeerCriteriaUpdated, PeerIP: ip})
	s.notify(Event{Type: EventCriterionChanged, PeerIP: ip, Criterion: string(crit), Value: val})
	// Not persisted — peer criteria are runtime state rebuilt via HA protocol.
}

func (s *haStore) RemovePeerMemberCriterion(ctx context.Context, ip string, crit types.HACriterion) {
	s.mu.Lock()
	peer, ok := s.peers[ip]
	if !ok {
		s.mu.Unlock()
		return
	}
	_, had := peer.MemberCriteria[crit]
	if had {
		delete(peer.MemberCriteria, crit)
		newMet := len(peer.MemberCriteria) > 0 && peer.MemberCriteria.AllOk()
		peer.MemberCriteriaMet = newMet
		if newMet {
			peer.MemberCriteriaMetEpoch = time.Now().Unix()
		}
		s.peers[ip] = peer
	}
	s.mu.Unlock()

	if had {
		s.notify(Event{Type: EventPeerCriteriaUpdated, PeerIP: ip})
		s.notify(Event{Type: EventCriterionChanged, PeerIP: ip, Criterion: string(crit), Value: true})
		// Not persisted — peer criteria are runtime state rebuilt via HA protocol.
	}
}

func (s *haStore) UpdatePeerServiceCriterion(ctx context.Context, ip string, crit types.HACriterion, val bool) {
	s.mu.Lock()
	peer, ok := s.peers[ip]
	if !ok {
		s.mu.Unlock()
		return
	}
	if peer.ServiceCriteria == nil {
		peer.ServiceCriteria = make(types.HACriteria)
	}
	peer.ServiceCriteria[crit] = val
	newMet := len(peer.ServiceCriteria) > 0 && peer.ServiceCriteria.AllOk()
	if peer.ServiceCriteriaMet != newMet {
		peer.ServiceCriteriaMet = newMet
		peer.ServiceCriteriaMetEpoch = time.Now().Unix()
	}
	s.peers[ip] = peer
	s.mu.Unlock()
	s.notify(Event{Type: EventPeerCriteriaUpdated, PeerIP: ip})
	s.notify(Event{Type: EventCriterionChanged, PeerIP: ip, Criterion: string(crit), Value: val})
	// Not persisted — peer service criteria are runtime state rebuilt via HA protocol.
}

func (s *haStore) RemovePeerServiceCriterion(ctx context.Context, ip string, crit types.HACriterion) {
	s.mu.Lock()
	peer, ok := s.peers[ip]
	if !ok {
		s.mu.Unlock()
		return
	}
	_, had := peer.ServiceCriteria[crit]
	if had {
		delete(peer.ServiceCriteria, crit)
		newMet := len(peer.ServiceCriteria) > 0 && peer.ServiceCriteria.AllOk()
		if peer.ServiceCriteriaMet != newMet {
			peer.ServiceCriteriaMet = newMet
			peer.ServiceCriteriaMetEpoch = time.Now().Unix()
		}
		s.peers[ip] = peer
	}
	s.mu.Unlock()

	if had {
		s.notify(Event{Type: EventPeerCriteriaUpdated, PeerIP: ip})
		s.notify(Event{Type: EventCriterionChanged, PeerIP: ip, Criterion: string(crit), Value: true})
		// Not persisted — peer service criteria are runtime state rebuilt via HA protocol.
	}
}

func (s *haStore) UpdatePeerAdjacencyCriterion(ctx context.Context, ip string, crit types.HACriterion, val bool) {
	s.mu.Lock()
	peer, ok := s.peers[ip]
	if !ok {
		s.mu.Unlock()
		return
	}
	if peer.AdjacencyCriteria == nil {
		peer.AdjacencyCriteria = make(types.HACriteria)
	}
	peer.AdjacencyCriteria[crit] = val
	newMet := len(peer.AdjacencyCriteria) > 0 && peer.AdjacencyCriteria.AllOk()
	if peer.AdjacencyCriteriaMet != newMet {
		peer.AdjacencyCriteriaMet = newMet
		peer.AdjacencyCriteriaMetEpoch = time.Now().Unix()
	}
	s.peers[ip] = peer
	s.mu.Unlock()
	s.notify(Event{Type: EventPeerCriteriaUpdated, PeerIP: ip})
	s.notify(Event{Type: EventCriterionChanged, PeerIP: ip, Criterion: string(crit), Value: val})
	// Not persisted — peer adjacency criteria are runtime state rebuilt via HA protocol.
}

func (s *haStore) RemovePeerAdjacencyCriterion(ctx context.Context, ip string, crit types.HACriterion) {
	s.mu.Lock()
	peer, ok := s.peers[ip]
	if !ok {
		s.mu.Unlock()
		return
	}
	_, had := peer.AdjacencyCriteria[crit]
	if had {
		delete(peer.AdjacencyCriteria, crit)
		newMet := len(peer.AdjacencyCriteria) > 0 && peer.AdjacencyCriteria.AllOk()
		if peer.AdjacencyCriteriaMet != newMet {
			peer.AdjacencyCriteriaMet = newMet
			peer.AdjacencyCriteriaMetEpoch = time.Now().Unix()
		}
		s.peers[ip] = peer
	}
	s.mu.Unlock()

	if had {
		s.notify(Event{Type: EventPeerCriteriaUpdated, PeerIP: ip})
		s.notify(Event{Type: EventCriterionChanged, PeerIP: ip, Criterion: string(crit), Value: true})
		// Not persisted — peer adjacency criteria are runtime state rebuilt via HA protocol.
	}
}

func (s *haStore) UpdatePeerMember(ctx context.Context, ip string, member *types.HAPeerMember) {
	s.mu.Lock()
	peer, ok := s.peers[ip]
	if !ok {
		s.mu.Unlock()
		return
	}
	peer.MemberInfo = member
	s.peers[ip] = peer
	s.mu.Unlock()
	s.notify(Event{Type: EventMemberUpdated, PeerIP: ip})
	// Not persisted — member info is rebuilt via HA adjacency protocol on startup.
}

// UpdatePeerMemberHaState updates the HaState field of the peer's MemberInfo.
// This is called when a Notify RPC reports the peer's HA state, keeping
// MemberInfo.HaState current between full adjacency exchanges.
func (s *haStore) UpdatePeerMemberHaState(ctx context.Context, ip string, haState string) {
	s.mu.Lock()
	peer, ok := s.peers[ip]
	if !ok {
		s.mu.Unlock()
		return
	}
	if peer.MemberInfo == nil {
		peer.MemberInfo = &types.HAPeerMember{}
	}
	peer.MemberInfo.HaState = haState
	s.peers[ip] = peer
	s.mu.Unlock()
}

func (s *haStore) UpdatePeerHaState(ctx context.Context, ip string, haState string, reason types.ReasonString) {
	s.mu.Lock()
	peer, ok := s.peers[ip]
	if !ok {
		s.mu.Unlock()
		return
	}
	now := time.Now().Unix()
	changed := peer.HaState != haState
	reasonChanged := peer.HaStateReason != reason
	peer.HaState = haState
	peer.HaStateReason = reason
	if changed {
		peer.HaStateEpoch = now
	}
	s.peers[ip] = peer
	pushHaToNx := s.enabled == "enabled"
	handler := s.gnmiHandler
	s.mu.Unlock()
	// Not persisted — peer HA state is runtime state computed by the HA state machine.

	if handler != nil && pushHaToNx && (changed || reasonChanged) {
		if err := handler.Set(ctx, fmt.Sprintf(paths.HAStorePeerHaState, ip), haState); err != nil {
			logger.GetLogger().Warn("Failed to set peer ha state via gNMI", "peer", ip, "error", err)
		}
		if err := handler.Set(ctx, fmt.Sprintf(paths.HAStorePeerHaStateReason, ip), reason.String()); err != nil {
			logger.GetLogger().Warn("Failed to set peer ha state reason via gNMI", "peer", ip, "error", err)
		}
	}
}

func (s *haStore) UpdatePeerSvcState(ctx context.Context, ip string, svcState string, reason types.ReasonString) {
	s.mu.Lock()
	peer, ok := s.peers[ip]
	if !ok {
		s.mu.Unlock()
		return
	}
	now := time.Now().Unix()
	changed := peer.SvcState != svcState
	reasonChanged := peer.SvcStateReason != reason
	peer.SvcState = svcState
	peer.SvcStateReason = reason
	if changed {
		peer.SvcStateEpoch = now
	}
	s.peers[ip] = peer
	pushHaToNx := s.enabled == "enabled"
	handler := s.gnmiHandler
	s.mu.Unlock()
	// Not persisted — peer service state is runtime state rebuilt via HA protocol.

	if handler != nil && pushHaToNx && (changed || reasonChanged) {
		if err := handler.Set(ctx, fmt.Sprintf(paths.HAStorePeerSvcState, ip), svcState); err != nil {
			logger.GetLogger().Warn("Failed to set peer svc state via gNMI", "peer", ip, "error", err)
		}
		if err := handler.Set(ctx, fmt.Sprintf(paths.HAStorePeerSvcStateReason, ip), reason.String()); err != nil {
			logger.GetLogger().Warn("Failed to set peer svc state reason via gNMI", "peer", ip, "error", err)
		}
	}
}

func (s *haStore) UpdatePeerConnected(ctx context.Context, ip string, connected bool, epoch int64) {
	s.mu.Lock()
	peer, ok := s.peers[ip]
	if !ok {
		s.mu.Unlock()
		return
	}
	peer.Connected = connected
	peer.ConnectedEpoch = epoch
	if !connected {
		// Reset connection-managed criteria on disconnect.
		// IpConfigState is on the peer struct and unaffected.
		for k := range peer.MemberCriteria {
			peer.MemberCriteria[k] = false
		}
		peer.MemberCriteriaMet = false
		for k := range peer.ServiceCriteria {
			peer.ServiceCriteria[k] = false
		}
		peer.ServiceCriteriaMet = false
		for k := range peer.AdjacencyCriteria {
			peer.AdjacencyCriteria[k] = false
		}
		peer.AdjacencyCriteriaMet = false
	}
	s.peers[ip] = peer
	s.mu.Unlock()
	if !connected {
		s.notify(Event{Type: EventPeerCriteriaUpdated, PeerIP: ip})
	}
	// Not persisted — peer connected state is runtime state rebuilt via HA protocol.
}

func (s *haStore) UpdatePeerVrfGIDs(ctx context.Context, ip string, gids map[string]uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	peer, ok := s.peers[ip]
	if !ok {
		return
	}
	peer.VrfGIDs = gids
	s.peers[ip] = peer
}

func (s *haStore) UpdatePeerVlanIDs(ctx context.Context, ip string, ids map[string]uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	peer, ok := s.peers[ip]
	if !ok {
		return
	}
	peer.VlanIDs = ids
	s.peers[ip] = peer
}

func (s *haStore) UpdatePeerDPUStatuses(ctx context.Context, ip string, statuses map[string]types.DPUHAStatus) {
	s.mu.Lock()
	peer, ok := s.peers[ip]
	if !ok {
		s.mu.Unlock()
		return
	}
	cp := make(map[string]types.DPUHAStatus, len(statuses))
	for k, v := range statuses {
		cp[k] = v
	}
	peer.DPUStatuses = cp
	s.peers[ip] = peer
	s.mu.Unlock()
	// Not persisted — DPU HA statuses are runtime state rebuilt from DPU keepalive/bulk-sync events.
}

// SetLocalHaStateToNotReady writes HA state as "ha_not_ready" to NXOS via gNMI SET
// and updates the store state.
func (s *haStore) SetLocalHaStateToNotReady(ctx context.Context, reason types.ReasonString) error {
	s.mu.Lock()
	stateChanged := s.localState.HaState != types.HAStateNotReady
	reasonChanged := s.localState.HaStateReason != reason
	s.localState.HaState = types.HAStateNotReady
	s.localState.HaStateReason = reason
	pushHaToNx := s.enabled == "enabled"
	handler := s.gnmiHandler
	s.mu.Unlock()

	if handler == nil || !pushHaToNx || (!stateChanged && !reasonChanged) {
		return nil
	}
	if err := handler.Set(ctx, paths.HAStoreLocalHaState, types.HAStateNotReady); err != nil {
		return err
	}
	return handler.Set(ctx, paths.HAStoreLocalHaStateReason, reason.String())
}

// SetLocalSvcStateToFailure writes the local service state as "not_ready" to NXOS via gNMI SET
// and updates the store state.
func (s *haStore) SetLocalSvcStateToFailure(ctx context.Context, reason types.ReasonString) error {
	s.mu.Lock()
	stateChanged := s.localState.SvcState != types.SvcStateFailure
	reasonChanged := s.localState.SvcStateReason != reason
	s.localState.SvcState = types.SvcStateFailure
	s.localState.SvcStateReason = reason
	handler := s.gnmiHandler
	s.mu.Unlock()

	if handler == nil || (!stateChanged && !reasonChanged) {
		return nil
	}
	if err := handler.Set(ctx, paths.HAStoreLocalSvcState, types.SvcStateFailure); err != nil {
		return err
	}
	return handler.Set(ctx, paths.HAStoreLocalSvcStateReason, reason.String())
}

// SetRemoteStatesAdjDown writes both peer HA and service states for adjacency down
// to both the store and NX-OS via gNMI.
func (s *haStore) SetRemoteStatesAdjDown(ctx context.Context, peerIP string) error {
	reason := types.NewReasonString("adjacency down")

	s.mu.Lock()
	peer, ok := s.peers[peerIP]
	var haChanged, svcChanged bool
	if ok {
		haChanged = peer.HaState != types.PeerHAStateNoHa || peer.HaStateReason != reason
		svcChanged = peer.SvcState != types.SvcStateUnknown || peer.SvcStateReason != reason
		peer.HaState = types.PeerHAStateNoHa
		peer.HaStateReason = reason
		peer.SvcState = types.SvcStateUnknown
		peer.SvcStateReason = reason
		s.peers[peerIP] = peer
	}
	pushHaToNx := s.enabled == "enabled"
	handler := s.gnmiHandler
	s.mu.Unlock()

	if handler == nil || !pushHaToNx || (!haChanged && !svcChanged) {
		return nil
	}
	if haChanged {
		if err := handler.Set(ctx, fmt.Sprintf(paths.HAStorePeerHaState, peerIP), types.PeerHAStateNoHa); err != nil {
			logger.GetLogger().Warn("Failed to set remote peer ha state adj down", "peer", peerIP, "error", err)
		}
		if err := handler.Set(ctx, fmt.Sprintf(paths.HAStorePeerHaStateReason, peerIP), reason.String()); err != nil {
			logger.GetLogger().Warn("Failed to set remote peer ha state reason adj down", "peer", peerIP, "error", err)
		}
	}
	if svcChanged {
		if err := handler.Set(ctx, fmt.Sprintf(paths.HAStorePeerSvcState, peerIP), types.SvcStateUnknown); err != nil {
			logger.GetLogger().Warn("Failed to set remote peer svc state adj down", "peer", peerIP, "error", err)
		}
		if err := handler.Set(ctx, fmt.Sprintf(paths.HAStorePeerSvcStateReason, peerIP), reason.String()); err != nil {
			logger.GetLogger().Warn("Failed to set remote peer svc state reason adj down", "peer", peerIP, "error", err)
		}
	}
	return nil
}

// UpdatePeerIsLeader updates the peer's self-reported leader status.
func (s *haStore) UpdatePeerIsLeader(ctx context.Context, ip string, isLeader bool) {
	s.mu.Lock()
	peer, ok := s.peers[ip]
	if !ok {
		s.mu.Unlock()
		return
	}
	peer.IsLeader = isLeader
	s.peers[ip] = peer
	s.mu.Unlock()
}
