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
	"encoding/json"

	"github.com/cilium/tetragon/pkg/logger"
	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

// HandleGnmiNotification processes a gNMI notification for HA state.
func (s *haStore) HandleGnmiNotification(ctx context.Context, path string, update *gnmiproto.Update, isDelete bool) {
	value := update.GetVal()
	if isDelete {
		s.handleDelete(ctx, path)
		return
	}

	s.handleUpdate(ctx, path, value)
}

// handleDelete processes gNMI delete notifications for HA state.
func (s *haStore) handleDelete(ctx context.Context, path string) {
	// Delete of a specific HA peer: ha-items/peer-items/Peer-list[id=X]
	if peerIP, ok := paths.ExtractHAPeerIP(path); ok {
		s.RemovePeer(ctx, peerIP)
		logger.GetLogger().Debug("HA peer removed via gNMI notification", "ip", peerIP)
		return
	}

	// Delete of ha-items (full HA config deleted)
	if paths.ContainsString(path, "ha-items") && !paths.ContainsString(path, "ext-items") {
		s.SetEnabled(ctx, "")
		s.SetSwitchState(ctx, "")
		// Clear all peers
		peerIPs := s.PeerIPs()
		for _, ip := range peerIPs {
			s.RemovePeer(ctx, ip)
		}
		logger.GetLogger().Info("HA configuration deleted via gNMI notification")
		return
	}
}

// handleUpdate processes gNMI update notifications for HA state.
func (s *haStore) handleUpdate(ctx context.Context, path string, value any) {
	// adminState change
	if paths.ContainsString(path, "adminState") {
		if strVal, ok := gnmi.ExtractStringValue(value); ok {
			s.SetEnabled(ctx, strVal)
			logger.GetLogger().Debug("HA adminState updated via gNMI notification", "state", strVal)
		}
		return
	}

	// agentHaSrcIntfAddr (local HA source IP)
	if paths.ContainsString(path, "agentHaSrcIntfAddr") {
		if strVal, ok := gnmi.ExtractStringValue(value); ok {
			s.SetHaIP(ctx, strVal)
			logger.GetLogger().Debug("HA source IP updated via gNMI", "ip", strVal)
		}
		return
	}

	// nxHaOperState change
	if paths.ContainsString(path, "nxHaOperState") {
		if strVal, ok := gnmi.ExtractStringValue(value); ok {
			s.SetSwitchState(ctx, strVal)
			logger.GetLogger().Debug("HA operState updated via gNMI notification", "state", strVal)
		}
		return
	}

	// Peer update: ha-items/peer-items/Peer-list[id=X] or HaPeer-list[ipAddr=X]
	if peerIP, ok := paths.ExtractHAPeerIP(path); ok {
		peer := parsePeerFromValue(value)
		peer.IP = peerIP
		s.SetPeer(ctx, peerIP, peer)
		logger.GetLogger().Debug("HA peer updated via gNMI notification", "ip", peerIP)
		return
	}

	// Bulk peer update from peer-items (contains the full peer list)
	lastElem := paths.GetLastPathElement(path)
	if lastElem == "peer-items" || lastElem == "HaPeer-list" {
		s.handlePeerListUpdate(ctx, value)
		return
	}
}

// handlePeerListUpdate processes a full peer list update from a gNMI notification.
func (s *haStore) handlePeerListUpdate(ctx context.Context, value any) {
	strVal, ok := gnmi.ExtractStringValue(value)
	if !ok {
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(strVal), &data); err != nil {
		logger.GetLogger().Debug("Failed to parse peer-items JSON", "error", err)
		return
	}

	peerList := extractPeerListFromData(data)
	for _, peerData := range peerList {
		peerMap, ok := peerData.(map[string]interface{})
		if !ok {
			continue
		}
		ip, _ := peerMap["ip"].(string)
		if ip == "" {
			ip, _ = peerMap["ipAddr"].(string)
		}
		if ip == "" {
			continue
		}
		peer := parsePeerFromMap(peerMap)
		peer.IP = ip
		s.SetPeer(ctx, ip, peer)
	}
}

// parsePeerFromValue extracts an HAPeerState from a gNMI notification value.
func parsePeerFromValue(value any) types.HAPeerState {
	defaultPeer := types.HAPeerState{
		SvcState:          types.SvcStateUnknown,
		MemberCriteria:    make(types.HACriteria),
		AdjacencyCriteria: make(types.HACriteria),
	}

	strVal, ok := gnmi.ExtractStringValue(value)
	if !ok {
		return defaultPeer
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(strVal), &data); err != nil {
		return defaultPeer
	}

	return parsePeerFromMap(data)
}

// parsePeerFromMap extracts an HAPeerState from a map.
func parsePeerFromMap(data map[string]interface{}) types.HAPeerState {
	peer := types.HAPeerState{
		SvcState:          types.SvcStateUnknown,
		MemberCriteria:    make(types.HACriteria),
		AdjacencyCriteria: make(types.HACriteria),
	}

	if state, ok := data["state"].(string); ok {
		peer.SvcState = state
	}

	if ipCfgOk, ok := data["ipConfigOk"].(bool); ok {
		peer.AdjacencyCriteria[types.HACritPeerIpConfig] = ipCfgOk
	}

	return peer
}

// extractPeerListFromData extracts the peer list from the HA peer-items JSON.
func extractPeerListFromData(data map[string]interface{}) []interface{} {
	if peerList, ok := data["HaPeer-list"].([]interface{}); ok {
		return peerList
	}
	if peerList, ok := data["Peer-list"].([]interface{}); ok {
		return peerList
	}
	return nil
}
