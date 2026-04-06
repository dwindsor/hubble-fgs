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
	"strconv"
	"strings"

	"github.com/cilium/tetragon/pkg/logger"

	hastore "github.com/isovalent/hubble-fgs/pkg/nxos/store/ha"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/vlan"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/vrf"
	hav1 "github.com/isovalent/hubble-fgs/pkg/proto/ha/v1"
)

// Reconciler handles GID and VLAN reconciliation between HA peers.
type Reconciler struct {
	haStore   hastore.Store
	vrfStore  vrf.Store
	vlanStore vlan.Store
}

// NewReconciler creates a new reconciler.
func NewReconciler(haStore hastore.Store, vrfStore vrf.Store, vlanStore vlan.Store) *Reconciler {
	return &Reconciler{
		haStore:   haStore,
		vrfStore:  vrfStore,
		vlanStore: vlanStore,
	}
}

// Reconcile performs GID and VLAN reconciliation between the local node and a peer.
// The peer's VRF and VLAN info comes from the adjacency exchange.
// Returns true if all reconciliation steps succeeded, false if any step failed.
func (r *Reconciler) Reconcile(ctx context.Context, peer string, peerMbrInfo *hav1.MbrInfo, localLbMode string) (bool, error) {
	if peerMbrInfo == nil {
		return false, nil
	}

	local := r.haStore.Local()
	isLeader := local.Leader

	// Build peer's GID map: vrf name -> gid
	peerGids := make(map[string]uint16)
	for _, vrfInfo := range peerMbrInfo.VrfInfo {
		peerGids[vrfInfo.Name] = uint16(vrfInfo.Id)
	}

	// Store peer GIDs for HA-aware allocation of new VRFs on non-leader.
	r.vrfStore.SetPeerGIDs(peerGids)

	reconCount := 0
	reconcileOk := true

	// Non-leader adopts peer's GIDs. SetGIDs sets the Preset for each peer VRF,
	// resolves collisions, and applies GID transitions via reconcilePresets.
	if !isLeader {
		if err := r.vrfStore.SetGIDs(ctx, peerGids); err != nil {
			logger.GetLogger().Error("Failed to apply peer GIDs", "peer", peer, "error", err)
			reconcileOk = false
		} else {
			reconCount += len(peerGids)
		}
	}

	// Phase 3: VLAN DPU pinning reconciliation (non-leader only, dpu_pinning mode only)
	if !isLeader && localLbMode == "dpu_pinning" && peerMbrInfo.VlanInfo != nil {
		for _, vlanInfo := range peerMbrInfo.VlanInfo {
			vlanName := fmt.Sprintf("vlan-%d", vlanInfo.Id)
			localVlan, ok := r.vlanStore.Get(vlanName)
			if !ok {
				continue
			}
			peerDPUPinned := uint16(vlanInfo.Affinity)
			if localVlan.DPUPinned != peerDPUPinned {
				logger.GetLogger().Warn("VLAN DPU pinning conflict detected",
					"vlan", vlanName,
					"localDPUPinned", localVlan.DPUPinned,
					"peerDPUPinned", peerDPUPinned,
					"isLeader", false)

				if err := r.vlanStore.SetPinning(ctx, vlanName, peerDPUPinned); err != nil {
					logger.GetLogger().Error("Failed to adopt peer VLAN DPU pinning",
						"vlan", vlanName, "error", err)
					continue
				}
				reconCount++
				logger.GetLogger().Info("Non-leader adopted peer's VLAN DPU pinning",
					"vlan", vlanName, "newDPUPinned", peerDPUPinned)
			}
		}
	}

	// Phase 4: Pinning mismatch warnings (when both peers are in dpu_pinning mode)
	if localLbMode == "dpu_pinning" {
		// Build local VRF DPUPinned map
		localVRFs := r.vrfStore.List()
		localVRFPinned := make(map[string]uint16)
		for _, vrf := range localVRFs {
			localVRFPinned[vrf.Name] = vrf.DPUPinned
		}

		// Warn about VRF DPUPinned mismatches
		for _, vrfInfo := range peerMbrInfo.VrfInfo {
			localPinned, exists := localVRFPinned[vrfInfo.Name]
			if !exists {
				continue
			}
			peerPinned := uint16(vrfInfo.Affinity)
			// Only warn if both are pinned (non-zero) and different
			if localPinned != 0 && peerPinned != 0 && localPinned != peerPinned {
				logger.GetLogger().Warn("VRF DPU pinning mismatch between peers",
					"vrf", vrfInfo.Name,
					"localDPUPinned", localPinned,
					"peerDPUPinned", peerPinned,
					"peer", peer)
			}
		}

		// Build local VLAN DPUPinned map
		localVLANs := r.vlanStore.ListActive()
		localVLANPinned := make(map[string]uint16)
		for _, vlan := range localVLANs {
			localVLANPinned[vlan.Name] = vlan.DPUPinned
		}

		// Warn about VLAN DPUPinned mismatches
		if peerMbrInfo.VlanInfo != nil {
			for _, vlanInfo := range peerMbrInfo.VlanInfo {
				vlanName := fmt.Sprintf("vlan-%d", vlanInfo.Id)
				localPinned, exists := localVLANPinned[vlanName]
				if !exists {
					continue
				}
				peerPinned := uint16(vlanInfo.Affinity)
				// Only warn if both are pinned (non-zero) and different
				if localPinned != 0 && peerPinned != 0 && localPinned != peerPinned {
					logger.GetLogger().Warn("VLAN DPU pinning mismatch between peers",
						"vlan", vlanName,
						"localDPUPinned", localPinned,
						"peerDPUPinned", peerPinned,
						"peer", peer)
				}
			}
		}
	}

	if reconCount > 0 {
		logger.GetLogger().Info("HA reconciliation complete", "peer", peer, "changes", reconCount)
	}
	return reconcileOk, nil
}

// ParseVLANName extracts the VLAN ID from a "vlan-N" name format.
func ParseVLANName(name string) (int, bool) {
	parts := strings.Split(name, "-")
	if len(parts) != 2 {
		return 0, false
	}
	id, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, false
	}
	return id, true
}

// BuildLocalVRFInfo builds the VRF info for adjacency exchange from the local VRF store.
// Includes all VRFs that have a GID (not just active ones) so the peer can cache them.
func BuildLocalVRFInfo(vrfStore vrf.Store) []*hav1.VrfInfo {
	vrfs := vrfStore.List()
	var vrfInfos []*hav1.VrfInfo
	for _, v := range vrfs {
		gid, ok := vrfStore.GetGID(v.Name)
		if !ok {
			continue
		}
		vrfInfos = append(vrfInfos, &hav1.VrfInfo{
			Name:     v.Name,
			Id:       uint32(gid),
			Affinity: uint32(v.DPUPinned),
		})
	}
	return vrfInfos
}

// BuildLocalVLANInfo builds the VLAN info for adjacency exchange from the local VLAN store.
func BuildLocalVLANInfo(vlanStore vlan.Store) []*hav1.VlanInfo {
	vlans := vlanStore.ListActive()
	var vlanInfos []*hav1.VlanInfo
	for _, v := range vlans {
		id, ok := ParseVLANName(v.Name)
		if !ok {
			continue
		}
		vlanInfos = append(vlanInfos, &hav1.VlanInfo{
			Id:       uint32(id),
			Affinity: uint32(v.DPUPinned),
		})
	}
	return vlanInfos
}
