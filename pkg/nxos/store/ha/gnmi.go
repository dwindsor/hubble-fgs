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

	"github.com/cilium/tetragon/pkg/logger"
	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

// HandleGnmiNotification processes a gNMI notification for HA state.
func (s *haStore) HandleGnmiNotification(ctx context.Context, path string, update *gnmiproto.Update, isDelete bool) {
	if isDelete {
		s.handleDelete(ctx, path)
		return
	}

	s.handleUpdate(ctx, path, update.GetVal())
}

// handleDelete processes gNMI delete notifications for HA state.
func (s *haStore) handleDelete(ctx context.Context, path string) {
	// Delete of a specific HA peer: ha-items/peer-items/Peer-list[id=X]
	if peerIP, ok := paths.ExtractHAPeerIP(path); ok {
		s.RemovePeer(ctx, peerIP)
		logger.GetLogger().Debug("HA peer removed via gNMI notification", "ip", peerIP)
		return
	}

	// Delete of ha-items container (full HA config deleted).
	// Match the ha-items container path but not ext-items children (agent-managed).
	if paths.PathMatches(path, paths.HAStoreHaItems) {
		// Clear config fields before removing peers so isHAConfiguredLocked()
		// returns false once the peer list is also empty.
		s.SetEnabled(ctx, "")
		s.SetSwitchState(ctx, "")
		s.SetHaIP(ctx, "")
		// Remove peers — no gNMI writes since isHAConfiguredLocked() is now false.
		peerIPs := s.PeerIPs()
		for _, ip := range peerIPs {
			s.RemovePeer(ctx, ip)
		}
		// Reset HA-specific local state; preserves svc state.
		s.ResetLocalHaState(ctx)
		logger.GetLogger().Info("HA configuration deleted via gNMI notification")
		return
	}
}

// handleUpdate processes gNMI update notifications for HA state.
// NX-OS sends individual leaf-level updates with string values for each field.
func (s *haStore) handleUpdate(ctx context.Context, path string, value any) {
	switch {
	// adminState change
	case paths.PathMatches(path, paths.HAStoreEnabled):
		if strVal, ok := gnmi.ExtractStringValue(value); ok {
			s.SetEnabled(ctx, strVal)
			logger.GetLogger().Debug("HA adminState updated via gNMI notification", "state", strVal)
		}

	// agentHaSrcIntfAddr (local HA source IP)
	case paths.PathMatches(path, paths.HAStoreHaIp):
		if strVal, ok := gnmi.ExtractStringValue(value); ok {
			s.SetHaIP(ctx, strVal)
			logger.GetLogger().Debug("HA source IP updated via gNMI", "ip", strVal)
		}

	// nxHaOperState change
	case paths.PathMatches(path, paths.HAStoreSwitchState):
		if strVal, ok := gnmi.ExtractStringValue(value); ok {
			s.SetSwitchState(ctx, strVal)
			logger.GetLogger().Debug("HA operState updated via gNMI notification", "state", strVal)
		}

	// Individual peer ipAddr update — creates peer if it doesn't exist, skips if it does.
	case paths.PathMatches(path, paths.HAStorePeerIpAddr):
		if peerIP, ok := gnmi.ExtractStringValue(value); ok {
			if _, exists := s.Peer(peerIP); exists {
				return
			}
			s.SetPeer(ctx, peerIP, types.HAPeerState{
				IP:                peerIP,
				SvcState:          types.SvcStateUnknown,
				IpConfigState:     PeerIpCfgStateNotStarted,
				MemberCriteria:    make(types.HACriteria),
				ServiceCriteria:   make(types.HACriteria),
				AdjacencyCriteria: make(types.HACriteria),
			})
			logger.GetLogger().Debug("HA peer created via gNMI", "ip", peerIP)
		}

	// Individual peer ipConfigState update — updates existing peer, skips if peer unknown.
	case paths.PathMatches(path, paths.HAStorePeerIpConfigState):
		peerIP, ok := paths.ExtractHAPeerIP(path)
		if !ok {
			return
		}
		existing, exists := s.Peer(peerIP)
		if !exists {
			logger.GetLogger().Debug("HA peer ipConfigState update skipped, peer not found", "ip", peerIP)
			return
		}
		if strVal, ok := gnmi.ExtractStringValue(value); ok {
			existing.IpConfigState = strVal
			s.SetPeer(ctx, peerIP, existing)
			logger.GetLogger().Debug("HA peer ipConfigState updated via gNMI", "ip", peerIP, "state", strVal)
		}
	}
}
