// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package nxos

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/config/library"
	model "github.com/isovalent/hubble-fgs/pkg/nxosmodel"
	hav1 "github.com/isovalent/hubble-fgs/pkg/proto/ha/v1"
	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
	"github.com/openconfig/ygot/ytypes"
)

const (
	haTimeout       = 10 // in second
	haPort          = "8883"
	nxUpdateTimeout = 30 // in sec
	adjTimeout      = 30 // in sec
	mbrTimeout      = 30 // in sec
	isFuncHoldDown  = 30 // in sec, anti-flapping hold-down for IsFunc recovery
)

func (n *Nxos) haIsEnabled(_ context.Context, isLock bool) bool {
	if isLock {
		n.RLock()
		defer n.RUnlock()
	}

	enabled := false
	if n.GetHaEnabled() && n.GetHaOperUp() {
		enabled = true
	}
	logger.GetLogger().Debug("HaEnabled: ", "", enabled)
	return enabled
}

func (n *Nxos) haIsConfigured(_ context.Context, isLock bool) bool {
	if isLock {
		n.RLock()
		defer n.RUnlock()
	}

	logger.GetLogger().Debug("HaConfigured: ", "", n.GetHaConfigured())
	return n.GetHaConfigured()
}

func (n *Nxos) haIsConnected(_ context.Context, peer string) bool {
	logger.GetLogger().Debug("haIsConnected: ", "peer", peer)

	n.RLock()
	defer n.RUnlock()

	adj, ok := n.Ha.Adjacencies[peer]
	if !ok {
		logger.GetLogger().Debug("Adjacency not found:", "peer", peer)
		return false
	}
	return adj.Connected
}

func (n *Nxos) GetHaIp() string {
	return n.Ha.HaIp
}

func (n *Nxos) SetHaIp(ip string) {
	n.Ha.HaIp = ip
	n.updateHaConfig()
}

func (n *Nxos) GetHaConfigured() bool {
	return n.Ha.configured
}

func (n *Nxos) SetHaConfigured(configured bool) {
	n.Ha.configured = configured
	n.updateHaConfig()
}

func (n *Nxos) GetHaEnabled() bool {
	return n.Ha.enabled
}

func (n *Nxos) SetHaEnabled(enabled bool) {
	n.Ha.enabled = enabled
	n.updateHaConfig()
}

func (n *Nxos) GetHaOperUp() bool {
	return n.Ha.operUp
}

func (n *Nxos) SetHaOperUp(operUp bool) {
	n.Ha.operUp = operUp
	n.updateHaConfig()
}

func (n *Nxos) GetHaPeers() map[string]HaPeer {
	return n.Ha.peers
}

func (n *Nxos) SetHaPeers(peers map[string]HaPeer) {
	n.Ha.peers = peers
	n.updateHaConfig()
}

func (n *Nxos) GetHaPeer(ip string) (HaPeer, bool) {
	peer, ok := n.Ha.peers[ip]
	return peer, ok
}

func (n *Nxos) SetHaPeer(ip string, peer HaPeer) {
	if n.Ha.peers == nil {
		n.Ha.peers = make(map[string]HaPeer)
	}
	n.Ha.peers[ip] = peer
	n.updateHaConfig()
}

func (n *Nxos) updateHaConfig() {
	var peers []*v1alpha.HaPeer
	for ip := range n.Ha.peers {
		peers = append(peers, &v1alpha.HaPeer{
			Ip:      ip,
			MinPort: uint32(n.DpuPortLow),
			MaxPort: uint32(n.DpuPortHigh),
		})
	}

	haIp := n.GetHaIp()

	var enabled bool
	if len(peers) > 0 && haIp != "" && haIp != "0.0.0.0" {
		enabled = n.GetHaConfigured() && n.GetHaOperUp() && n.stableIsFunc()
	}
	var flow_sync bool
	flow_sync = enabled && n.GetHaEnabled()

	err := library.GetRepository().UpdateConfig(v1alpha.ConfigType_CONFIG_TYPE_HA, func(existing *v1alpha.ConfigObject) (*v1alpha.ConfigObject, error) {
		haConfig := &v1alpha.HaConfig{}
		haConfig.HaIp = haIp
		haConfig.Peers = peers
		haConfig.Enabled = enabled
		haConfig.FlowSync = flow_sync
		return &v1alpha.ConfigObject{
			Type:   v1alpha.ConfigType_CONFIG_TYPE_HA,
			Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
			Config: &v1alpha.ConfigObject_ConfigHa{ConfigHa: haConfig},
		}, nil
	})
	if err != nil {
		logger.GetLogger().Error("Failed to update HA config", "error", err)
	}
}

func (n *Nxos) HaSetMbrInfo(ctx context.Context, peer string, info hav1.MbrInfo) {
	n.Lock()
	defer n.Unlock()

	n.haSetMbrInfo(ctx, peer, info)
}

func (n *Nxos) haSetMbrInfo(ctx context.Context, peer string, info hav1.MbrInfo) {
	logger.GetLogger().Debug("haSetMbrInfo:", "peer", peer, "mbrInfo", info)

	// Always compute and update the policy peer criterion regardless of
	// whether HA is operationally enabled so that show_ha displays the
	// correct PolicyOk status even when no_shutdown is not configured.
	n.computeAndUpdatePeerPolicy(ctx, peer, info)

	if !n.haIsEnabled(ctx, false) {
		logger.GetLogger().Debug("skip setting peer mbr info")
		return
	}

	// Check if peer is signaling intentional HA removal via NO_HA state.
	// This allows us to transition to HA_NOTREADY (not SWITCHOVER) since
	// this is not a failure condition.
	if info.HaInfo != nil && info.HaInfo.Ha == hav1.HA_STATE_NO_HA {
		logger.GetLogger().Info("Peer signaled HA removal (NO_HA state)", "peer", peer)

		// Remove peer from runtime state (Partners, Members) but NOT from config (n.Ha.peers).
		// Peer stays in config so haSetup() will try to reconnect.
		delete(n.Ha.Partners, peer)
		delete(n.Ha.Members, peer)

		// Set peer state to NA (not FAIL - this isn't a failure)
		if haPeer, ok := n.GetHaPeer(peer); ok {
			haPeer.State = hav1.MBR_STATE_HA_NA
			haPeer.StateReason = "peer removed HA configuration"
			n.SetHaPeer(peer, haPeer)
			n.setRemoteMbrState(ctx, peer)
		}

		// Update HA state - go to NOTREADY if no partners (not SWITCHOVER)
		n.haUpdateNxStateForRemoval(ctx)

		// Wake up HA setup to try reconnecting to new members
		select {
		case n.WaitHa.In() <- WakeHa:
		default:
		}
		return
	}

	now := time.Now().Unix()
	v, ok := n.Ha.Adjacencies[peer]
	if !ok {
		n.Ha.Adjacencies[peer] = HaAdj{
			Epoch: now,
		}
	} else {
		v.Epoch = now
		n.Ha.Adjacencies[peer] = v
	}

	notify := false
	mbr, ok := n.Ha.Members[peer]
	if !ok {
		notify = true
	} else if info.HaInfo != nil && (mbr.Info.HaInfo == nil ||
		mbr.Info.HaInfo.Ha != info.HaInfo.Ha ||
		mbr.Info.HaInfo.Service != info.HaInfo.Service) {
		notify = true
	}

	n.Ha.Members[peer] = HaMbr{
		Info:  info,
		Epoch: now,
	}

	// skip vlan/vrf checking for now
	var isDel bool
	var haStateReason string
	if info.SysInfo == nil || info.HaInfo == nil ||
		info.PolInfo == nil {
		logger.GetLogger().Debug("Empty info")
		isDel = true
		haStateReason = "missing system/ha/policy info"
	} else if info.SysInfo.Model != n.Model {
		logger.GetLogger().Debug("Model mismatch:", "info", info.SysInfo.Model, "n", n.Model)
		isDel = true
		haStateReason = fmt.Sprintf("model mismatch: peer=%s local=%s", info.SysInfo.Model, n.Model)
	} else if info.SysInfo.SwVer != n.SwVer {
		logger.GetLogger().Debug("NxOS version mismatch:", "version", info.SysInfo.SwVer, "n", n.SwVer)
		isDel = true
		haStateReason = fmt.Sprintf("NxOS version mismatch: peer=%s local=%s", info.SysInfo.SwVer, n.SwVer)
	} else if info.SysInfo.Cpa != n.CpaVer {
		logger.GetLogger().Debug("CPA version mismatch:", "cpa", info.SysInfo.Cpa, "n", n.CpaVer)
		isDel = true
		haStateReason = fmt.Sprintf("CPA version mismatch: peer=%s local=%s", info.SysInfo.Cpa, n.CpaVer)
	} else if info.HaInfo.Service == hav1.SERVICE_STATE_SVC_FAILURE {
		logger.GetLogger().Debug("Peer cannot provide service")
		isDel = true
		haStateReason = "peer service failure"
	} else if n.Ha.Watching && n.Ha.PolRev != info.PolInfo.Revision {
		logger.GetLogger().Debug("Policy revision mismatch while watching")
		isDel = true
		haStateReason = fmt.Sprintf("policy revision mismatch while watching: peer=%s local=%s", info.PolInfo.Revision, n.Ha.PolRev)
	} else if len(info.SysInfo.Dpus) != len(n.Dpus) {
		logger.GetLogger().Debug("DPU number mismatch:", "DPUs", len(info.SysInfo.Dpus), "n", len(n.Dpus))
		isDel = true
		haStateReason = fmt.Sprintf("DPU count mismatch: peer=%d local=%d", len(info.SysInfo.Dpus), len(n.Dpus))
	} else {
		for _, dpu := range info.SysInfo.Dpus {
			d, ok := n.Dpus[dpu.Name]
			if !ok {
				logger.GetLogger().Debug("DPU not found", "name", dpu.Name)
				isDel = true
				haStateReason = fmt.Sprintf("DPU not found: %s", dpu.Name)
				break
			}
			if d.Version != dpu.Version {
				logger.GetLogger().Debug("DPU version mismatch", dpu.Version, d.Version)
				isDel = true
				haStateReason = fmt.Sprintf("DPU version mismatch: peer=%s local=%s for %s", dpu.Version, d.Version, dpu.Name)
				break
			}
		}
	}

	// Store reason on HaPeer before updating partner state
	if haPeer, ok := n.GetHaPeer(peer); ok {
		if isDel {
			haPeer.StateReason = haStateReason
		} else {
			haPeer.StateReason = ""
		}
		n.SetHaPeer(peer, haPeer)
	}
	n.HaUpdatePtnr(ctx, peer, isDel)

	// Update ServiceOk on peer criteria from peer's self-reported service state.
	// updatePeerServiceCrit will call setRemoteSvcState only if ServiceOk changes.
	svcOk := info.HaInfo != nil && info.HaInfo.Service == hav1.SERVICE_STATE_SVC_SUCCESS
	n.updatePeerServiceCrit(ctx, peer, svcOk)

	if notify {
		n.setRemoteSvcState(ctx, peer)
	}
}

func (n *Nxos) HaGetMbrInfo(ctx context.Context, peer string, isLock bool) hav1.MbrInfo {
	logger.GetLogger().Debug("HaGetMbrInfo")

	if isLock {
		n.RLock()
		defer n.RUnlock()
	}

	if !n.haIsEnabled(ctx, false) {
		logger.GetLogger().Debug("skip getting local mbr info")
		return hav1.MbrInfo{}
	}

	pol := hav1.PolInfo{
		Watching: n.Ha.Watching,
		Revision: n.Ha.PolRev,
		Hash:     n.Ha.PolHash,
	}

	var dpus []*hav1.DpuVer
	for name, dpu := range n.Dpus {
		d := &hav1.DpuVer{
			Name:    name,
			Version: dpu.Version,
		}
		dpus = append(dpus, d)
	}
	ver := hav1.SysInfo{
		SerNum: n.SerNum,
		Model:  n.Model,
		SwVer:  n.SwVer,
		Cpa:    n.CpaVer,
		Dpus:   dpus,
	}

	var ss hav1.SERVICE_STATE
	if n.stableIsFunc() {
		ss = hav1.SERVICE_STATE_SVC_SUCCESS
	} else {
		ss = hav1.SERVICE_STATE_SVC_FAILURE
	}

	ha := hav1.HaInfo{
		Service: ss,
		Ha:      n.Ha.NxStates.HaState,
	}
	var vrfs []*hav1.VrfInfo
	for _, vrf := range n.Vrfs {
		if !vrf.IsGlobal || !vrf.IsService {
			continue
		}
		gid, ok := n.Alloc.Gids[vrf.Name]
		if !ok {
			logger.GetLogger().Debug("Missing Gid:", "VRF", vrf.Name)
			continue
		}
		v := &hav1.VrfInfo{
			Name: vrf.Name,
			Id:   uint32(gid),
			Dpu:  uint32(vrf.DpuPinned),
		}
		vrfs = append(vrfs, v)
	}
	var vlans []*hav1.VlanInfo
	for _, vlan := range n.Bds {
		if !vlan.IsGlobal || !vlan.IsService {
			continue
		}
		strs := strings.Split(vlan.Name, "-")
		if len(strs) != 2 {
			logger.GetLogger().Error("unexpected vlan name", "vlan", vlan.Name)
			continue
		}
		vid, err := strconv.Atoi(strs[1])
		if err != nil {
			logger.GetLogger().Error("unexpected vlan id in name", "vlanID", vlan.Name)
			continue
		}
		v := &hav1.VlanInfo{
			Id: uint32(vid), Dpu: uint32(vlan.DpuPinned),
		}
		vlans = append(vlans, v)
	}
	info := hav1.MbrInfo{
		PolInfo:  &pol,
		SysInfo:  &ver,
		HaInfo:   &ha,
		VrfInfo:  vrfs,
		VlanInfo: vlans,
	}

	return info
}

func (n *Nxos) haConnect(_ context.Context, peer string) {
	logger.GetLogger().Debug("haConnect:", "local", n.Ha.HaIp, "peer", peer)

	n.Lock()
	defer n.Unlock()

	if !n.Ha.IsLeader {
		logger.GetLogger().Debug("haConnect: not leader, skip")
		return
	}

	p, ok := n.GetHaPeer(peer)
	if !ok {
		logger.GetLogger().Error("Fail to connect: Peer not found")
		return
	}
	if !p.IpConfigOk {
		logger.GetLogger().Debug("Peer IP config not ok: skip")

		// HACK: return once NX fixes
		// return
	}

	adj, ok := n.Ha.Adjacencies[peer]
	if !ok {
		adj = HaAdj{}
	}

	addr := peer + ":" + haPort
	logger.GetLogger().Debug("haConnect: connecting peer addr", "ip", addr)
	err := adj.GrpcClient.Connect(addr, n.Ha.ClientCa, n.Ha.ClientCert, n.Ha.ClientKey /*p.SkipAuth*/, true)
	if err != nil {
		logger.GetLogger().Error("Failed to setup ha client connection", logfields.Error, err)
		return
	}
	now := time.Now().Unix()
	adj.Connected = true
	adj.Epoch = now
	n.Ha.Adjacencies[peer] = adj
}

func (n *Nxos) haDisconnect(_ context.Context, peer string) {
	logger.GetLogger().Debug("haDisconnect:", "peer", peer)

	n.Lock()
	defer n.Unlock()

	n.haDisconnectLocked(peer)
}

// haDisconnectLocked is the lock-free variant of haDisconnect.
// Caller must hold n.Lock().
func (n *Nxos) haDisconnectLocked(peer string) {
	delete(n.Ha.Members, peer)

	if !n.Ha.IsLeader {
		logger.GetLogger().Debug("haDisconnect: not leader, skip")
		return
	}

	adj, ok := n.Ha.Adjacencies[peer]
	if !ok {
		logger.GetLogger().Error("Fail to disconnect: Adj not found")
		return
	}
	adj.GrpcClient.Close()
	delete(n.Ha.Adjacencies, peer)
}

// haBuildRemovalMbrInfo builds member info for intentional HA removal.
// Caller should hold either n.RLock() or n.Lock().
func (n *Nxos) haBuildRemovalMbrInfo(ctx context.Context, peer string) hav1.MbrInfo {
	info := n.HaGetMbrInfo(ctx, peer, false)
	if info.HaInfo == nil {
		svcState := hav1.SERVICE_STATE_SVC_FAILURE
		if n.stableIsFunc() {
			svcState = hav1.SERVICE_STATE_SVC_SUCCESS
		}
		info.HaInfo = &hav1.HaInfo{Service: svcState}
	}
	info.HaInfo.Ha = hav1.HA_STATE_NO_HA
	return info
}

// haNotifyRemoval sends a final adjacency call with NO_HA state to notify
// the peer that HA is being intentionally removed. This allows the peer to
// transition to HA_NOTREADY instead of waiting for adjacency timeout and
// incorrectly going to HA_SWITCHOVER.
// If no active adjacency client exists (e.g. follower), the notification is
// skipped; the follower's gRPC server will return NO_HA in the AdjResponse
// when the leader sends its next adjacency tick.
func (n *Nxos) haNotifyRemoval(ctx context.Context, peer string) {
	logger.GetLogger().Debug("haNotifyRemoval:", "peer", peer)

	n.RLock()
	adj, ok := n.Ha.Adjacencies[peer]
	if !ok || !adj.Connected {
		n.RUnlock()
		logger.GetLogger().Debug("haNotifyRemoval: peer not connected, skip")
		return
	}
	grpcClient := adj.GrpcClient.Client
	if grpcClient == nil {
		n.RUnlock()
		logger.GetLogger().Debug("haNotifyRemoval: grpc client is nil, skip")
		return
	}
	haIp := n.Ha.HaIp
	info := n.haBuildRemovalMbrInfo(ctx, peer)
	n.RUnlock()

	req := &hav1.AdjRequest{
		HaIp:    haIp,
		MbrInfo: &info,
	}
	logger.GetLogger().Debug("Sending removal notification to peer", "peer", peer)
	_, err := grpcClient.Adjacency(ctx, req)
	if err != nil {
		logger.GetLogger().Error("Failed to send removal notification", "peer", peer, "error", err)
	}
}

// haNotifyRemovalLocked is the lock-free variant of haNotifyRemoval.
// Caller must hold n.Lock(). The gRPC call is made without re-acquiring
// the lock since the caller already holds the write lock.
// If no active adjacency client exists (e.g. follower), the notification is
// skipped; the follower's gRPC server will return NO_HA in the AdjResponse
// when the leader sends its next adjacency tick.
func (n *Nxos) haNotifyRemovalLocked(ctx context.Context, peer string) {
	logger.GetLogger().Debug("haNotifyRemovalLocked:", "peer", peer)

	adj, ok := n.Ha.Adjacencies[peer]
	if !ok || !adj.Connected {
		logger.GetLogger().Debug("haNotifyRemovalLocked: peer not connected, skip")
		return
	}
	grpcClient := adj.GrpcClient.Client
	if grpcClient == nil {
		logger.GetLogger().Debug("haNotifyRemovalLocked: grpc client is nil, skip")
		return
	}

	info := n.haBuildRemovalMbrInfo(ctx, peer)
	req := &hav1.AdjRequest{
		HaIp:    n.Ha.HaIp,
		MbrInfo: &info,
	}
	logger.GetLogger().Debug("Sending removal notification to peer", "peer", peer)
	_, err := grpcClient.Adjacency(ctx, req)
	if err != nil {
		logger.GetLogger().Error("Failed to send removal notification", "peer", peer, "error", err)
	}
}

func (n *Nxos) haAdjacency(ctx context.Context, peer string) {
	logger.GetLogger().Debug("haAdjacency:", "peer", peer)

	// 1. Collect data under read lock - no writes allowed
	n.RLock()
	if !n.Ha.IsLeader {
		logger.GetLogger().Debug("haAdjacency: not leader, skip")
		n.RUnlock()
		return
	}
	if n.Ha.HaIp == "" {
		logger.GetLogger().Debug("haAdjacency: HaIp not set yet")
		n.RUnlock()
		return
	}
	adj, ok := n.Ha.Adjacencies[peer]
	if !ok || !adj.Connected {
		logger.GetLogger().Debug("haAdjacency: adjacency not found or not connected", "peer", peer)
		n.RUnlock()
		return
	}
	// Copy gRPC client reference and local state for use after releasing lock
	grpcClient := adj.GrpcClient.Client
	if grpcClient == nil {
		logger.GetLogger().Debug("haAdjacency: grpc client is nil, skip")
		n.RUnlock()
		return
	}
	haIp := n.Ha.HaIp
	watching := n.Ha.Watching
	polRev := n.Ha.PolRev
	info := n.HaGetMbrInfo(ctx, peer, false)
	n.RUnlock()

	// 2. Make gRPC call WITHOUT holding any lock to prevent deadlock
	req := &hav1.AdjRequest{
		HaIp:    haIp,
		MbrInfo: &info,
	}
	logger.GetLogger().Debug("Adjacency request:", "req", req)
	rsp, err := grpcClient.Adjacency(ctx, req)
	if err != nil || rsp.Status == hav1.ADJ_RESPONSE_STATUS_ADJ_FAILURE {
		logger.GetLogger().Error("Adjacency fails", logfields.Error, err)
		// Check if the peer signaled intentional HA removal via NO_HA
		// in the failure response. This lets us transition to HA_NOTREADY
		// immediately instead of waiting for adjacency timeout.
		if err == nil && rsp.MbrInfo != nil &&
			rsp.MbrInfo.HaInfo != nil &&
			rsp.MbrInfo.HaInfo.Ha == hav1.HA_STATE_NO_HA {
			logger.GetLogger().Info("Peer signaled HA removal in adjacency response", "peer", peer)
			n.HaSetMbrInfo(ctx, peer, *rsp.MbrInfo)
		}
		return
	}
	logger.GetLogger().Debug("Adjacency response:", "rsp", rsp)

	// 3. Check policy revision mismatch (using copied values)
	if watching && rsp.MbrInfo.PolInfo != nil && polRev != rsp.MbrInfo.PolInfo.Revision {
		logger.GetLogger().Error("Adjacency policy revision mismatch while watching",
			"localRev", polRev, "peerRev", rsp.MbrInfo.PolInfo.Revision)
		return
	}

	// 4. Update state with write lock
	n.Lock()
	// Update adjacency epoch if still exists
	if v, ok := n.Ha.Adjacencies[peer]; ok {
		v.Epoch = time.Now().Unix()
		n.Ha.Adjacencies[peer] = v
	}
	// Construct and store HA alloc
	alloc := map[string]uint16{}
	for _, vrf := range rsp.MbrInfo.VrfInfo {
		alloc[vrf.Name] = uint16(vrf.Id)
	}
	n.Ha.Alloc[peer] = HaAlloc{
		Gids: alloc,
	}
	logger.GetLogger().Debug("HA alloc:", "alloc", alloc)
	n.Unlock()

	// 5. Process peer member info (HaSetMbrInfo handles its own locking)
	n.HaSetMbrInfo(ctx, peer, *rsp.MbrInfo)

	// 6. Leader-side reconciliation: resolve alloc tracking against follower's state.
	// HaReconcile takes its own write lock.
	n.HaReconcile(ctx, peer, *rsp.MbrInfo)
}

func (n *Nxos) haGetPeers(_ context.Context) []string {
	n.RLock()
	defer n.RUnlock()
	var peers []string
	for peer := range n.GetHaPeers() {
		peers = append(peers, peer)
	}
	logger.GetLogger().Debug("Peers found:", "peers", peers)
	return peers
}

// anyPeerCriteriaOk returns true if at least one peer has all per-peer criteria passing.
func (n *Nxos) anyPeerCriteriaOk() bool {
	for _, crit := range n.Ha.PeerCriteria {
		if crit.IsOk() {
			return true
		}
	}
	return false
}

// anyPeerInHaReady returns true if at least one peer member has reported HA_READY state.
// This indicates the local switch still has an active-active partner.
func (n *Nxos) anyPeerInHaReady() bool {
	for _, mbr := range n.Ha.Members {
		if mbr.Info.HaInfo != nil && mbr.Info.HaInfo.Ha == hav1.HA_STATE_HA_READY {
			return true
		}
	}
	return false
}

func (n *Nxos) haUpdateNxState(_ context.Context) {
	now := time.Now().Unix()
	logger.GetLogger().Debug("haUpdateNxState", "timestamp", now)

	var svcState hav1.SERVICE_STATE
	var haState hav1.HA_STATE
	if n.stableIsFunc() {
		svcState = hav1.SERVICE_STATE_SVC_SUCCESS
		if len(n.Ha.Partners) > 0 && n.anyPeerCriteriaOk() {
			haState = hav1.HA_STATE_HA_READY
			if !n.Ha.EverReady {
				n.Ha.EverReady = true
				logger.GetLogger().Info("HA_READY reached for the first time")
			}
		} else if n.Ha.EverReady {
			if n.anyPeerInHaReady() {
				// At least one peer is still HA_READY — stay in active-active mode
				haState = hav1.HA_STATE_HA_READY
				logger.GetLogger().Debug("Staying in HA_READY (at least one peer still HA_READY)")
			} else {
				// No peer is HA_READY — no longer in active-active mode
				haState = hav1.HA_STATE_HA_NOTREADY
				n.Ha.EverReady = false
				logger.GetLogger().Info("Transitioning to HA_NOTREADY (no peer in HA_READY)")
			}
		} else {
			haState = hav1.HA_STATE_HA_NOTREADY
		}
	} else {
		svcState = hav1.SERVICE_STATE_SVC_FAILURE
		if n.Ha.NxStates.HaState == hav1.HA_STATE_HA_READY {
			// Was actively in HA_READY with a peer — switchover so peer takes over
			haState = hav1.HA_STATE_HA_SWITCHOVER
			n.Ha.EverReady = false
			logger.GetLogger().Info("Transitioning to HA_SWITCHOVER (was in HA_READY)")
		} else {
			// Already HA_NOTREADY or initializing — no peer to take over, stay NOTREADY
			haState = hav1.HA_STATE_HA_NOTREADY
			n.Ha.EverReady = false
			logger.GetLogger().Debug("Staying in HA_NOTREADY (no active peer to switchover to)")
		}
	}
	logger.GetLogger().Debug("Derived states", "svcState", svcState, "haState", haState)

	if n.Ha.NxStates.HaState != haState {
		logger.GetLogger().Debug("update haState", "prev", n.Ha.NxStates.HaState, "next", haState)
		n.Ha.NxStates.HaState = haState
		n.Ha.NxStates.HaStateEpoch = now
	}
	if n.Ha.NxStates.SvcState != svcState {
		logger.GetLogger().Debug("update SvcState", "prev", n.Ha.NxStates.SvcState, "next", svcState)
		n.Ha.NxStates.SvcState = svcState
		n.Ha.NxStates.SvcStateEpoch = now
	}
}

// haUpdateNxStateForRemoval handles state transition when peer intentionally removes HA.
// Unlike haUpdateNxState(), this always goes to HA_NOTREADY (not SWITCHOVER) when no partners remain,
// because peer removal is not a failure condition - it's intentional.
func (n *Nxos) haUpdateNxStateForRemoval(_ context.Context) {
	now := time.Now().Unix()
	logger.GetLogger().Debug("haUpdateNxStateForRemoval", "timestamp", now)

	var svcState hav1.SERVICE_STATE
	var haState hav1.HA_STATE

	if n.stableIsFunc() {
		svcState = hav1.SERVICE_STATE_SVC_SUCCESS
		if len(n.Ha.Partners) > 0 && n.anyPeerCriteriaOk() {
			haState = hav1.HA_STATE_HA_READY
			if !n.Ha.EverReady {
				n.Ha.EverReady = true
				logger.GetLogger().Info("HA_READY reached for the first time (during removal)")
			}
		} else {
			// Key difference from haUpdateNxState: always go to NOTREADY, not SWITCHOVER
			// This allows the switch to try reconnecting to new peers
			haState = hav1.HA_STATE_HA_NOTREADY
		}
	} else {
		// Service failure - but since this is intentional removal, still go to NOTREADY
		svcState = hav1.SERVICE_STATE_SVC_FAILURE
		haState = hav1.HA_STATE_HA_NOTREADY
	}

	logger.GetLogger().Debug("Derived states for removal", "svcState", svcState, "haState", haState)

	if n.Ha.NxStates.HaState != haState {
		logger.GetLogger().Debug("update haState for removal", "prev", n.Ha.NxStates.HaState, "next", haState)
		n.Ha.NxStates.HaState = haState
		n.Ha.NxStates.HaStateEpoch = now
	}
	if n.Ha.NxStates.SvcState != svcState {
		logger.GetLogger().Debug("update SvcState for removal", "prev", n.Ha.NxStates.SvcState, "next", svcState)
		n.Ha.NxStates.SvcState = svcState
		n.Ha.NxStates.SvcStateEpoch = now
	}
}

func (n *Nxos) haCheckAdjMbr(ctx context.Context) {
	now := time.Now().Unix()
	logger.GetLogger().Debug("haCheckAdjMbr", "timestamp", now)

	n.Lock()
	defer n.Unlock()

	for ip, mbr := range n.Ha.Members {
		if now-mbr.Epoch > mbrTimeout {
			logger.GetLogger().Debug("Member timed out", "ip", ip)
			delete(n.Ha.Members, ip)
			n.HaUpdatePtnr(ctx, ip, true)
		}
	}
	for ip, adj := range n.Ha.Adjacencies {
		if now-adj.Epoch > adjTimeout {
			logger.GetLogger().Debug("Adjacency timed out", "ip", ip)
			delete(n.Ha.Adjacencies, ip)
			peer, ok := n.GetHaPeer(ip)
			if ok {
				peer.State = hav1.MBR_STATE_HA_FAIL
				// Preserve the original reason if HA config removal caused the disconnect;
				// only overwrite with "adjacency timeout" when no prior reason exists.
				if peer.StateReason == "" {
					peer.StateReason = "adjacency timeout"
				}
				n.SetHaPeer(ip, peer)
			}
			n.setRemoteStatesAdjDown(ctx, ip)
		}
	}
}

func (n *Nxos) haUpdateNx(ctx context.Context) {
	n.Lock()
	defer n.Unlock()
	now := time.Now().Unix()

	// ALWAYS process service state BEFORE HA state
	// Service state must be updated first to ensure proper state ordering
	if n.isConfigured(ctx, false) {
		if n.Ha.NxStates.SvcStateEpoch != 0 &&
			now-n.Ha.NxStates.SvcStateEpoch > nxUpdateTimeout {
			n.Ha.NxStates.SvcStateEpoch = 0
			switch n.Ha.NxStates.SvcState {
			case hav1.SERVICE_STATE_SVC_SUCCESS:
				logger.GetLogger().Debug("Program service redir")
				n.setSystemState(ctx)
				n.setFwPolicyStateAll(ctx, false)
				n.setServiceRedirAll(ctx, false)
				n.setLocalSvcState(ctx)
				// Notify peers of service state
				for peer := range n.Ha.Members {
					n.setRemoteSvcState(ctx, peer)
				}

			case hav1.SERVICE_STATE_SVC_FAILURE:
				logger.GetLogger().Debug("Cleanup service redir")
				n.cleanup(ctx)
			}
		}
	}

	// THEN process HA state
	if n.haIsConfigured(ctx, false) {
		if n.Ha.NxStates.HaStateEpoch != 0 &&
			now-n.Ha.NxStates.HaStateEpoch > nxUpdateTimeout {
			logger.GetLogger().Debug("haUpdateNx:", "haState",
				n.Ha.NxStates.HaState, "epoch",
				n.Ha.NxStates.HaStateEpoch)
			n.Ha.NxStates.HaStateEpoch = 0
			// update nx
			n.setLocalHaState(ctx)
		}
	}
}

func (n *Nxos) HaUpdateCrit(ctx context.Context, crit HaCrit, val bool) {
	n.Lock()
	defer n.Unlock()

	n.haUpdateCrit(ctx, crit, val)
}

func (n *Nxos) haUpdateCrit(ctx context.Context, crit HaCrit, val bool) {
	if n.SkipDpu && (crit == HaCritDpuHealth || crit == HaCritDpuInSync) {
		logger.GetLogger().Debug("in dpuless mode, ignore", "crit", crit)
		return
	}
	prev := n.Ha.Local.Criteria[crit]
	if prev != val {
		logger.GetLogger().Debug("haUpdateCrit", "crit", crit, "val", val)
		n.Ha.Local.Criteria[crit] = val
		n.recalculateIsFuncAndState(ctx)
	}
}

// computeIsFunc returns true if all local criteria pass.
func (n *Nxos) computeIsFunc() bool {
	for _, v := range n.Ha.Local.Criteria {
		if !v {
			return false
		}
	}
	return true
}

// stableIsFunc returns the effective IsFunc value that respects the
// anti-flapping hold-down.  During a pending recovery (PendingIsFunc
// is true but hold-down has not yet expired), this returns false even
// though the raw criteria may all be passing.  All consumers that
// derive state from IsFunc (HA config, NX state, member info) must
// use this method instead of reading n.Ha.Local.IsFunc directly.
func (n *Nxos) stableIsFunc() bool {
	if n.Ha.Local.PendingIsFunc {
		return false
	}
	return n.Ha.Local.IsFunc
}

// recalculateIsFuncAndState recalculates IsFunc based on local criteria,
// then updates NX state.  HA state depends on both local criteria (IsFunc)
// and peer criteria, so we always re-evaluate NX state.
//
// Anti-flapping: degradation (true->false) is applied immediately so the
// system fails fast.  Recovery (false->true) is held down for
// isFuncHoldDown seconds — criteria must remain all-true for the entire
// period before IsFunc actually transitions.  If any criterion flips back
// to false during the hold-down, the pending recovery is cancelled and
// the flap counter is incremented.
// Caller must hold the lock.
func (n *Nxos) recalculateIsFuncAndState(ctx context.Context) {
	now := time.Now().Unix()
	isFunc := n.computeIsFunc()

	if n.Ha.Local.IsFunc && !isFunc {
		// Degradation: apply immediately (fail-fast).
		logger.GetLogger().Debug("Local HA State degraded", "prev", true, "new", false)
		n.Ha.Local.IsFunc = false
		n.Ha.Local.Epoch = now
		// Cancel any stale pending recovery.
		n.Ha.Local.PendingIsFunc = false
		n.Ha.Local.PendingEpoch = 0
		n.updateHaConfig()
	} else if !n.Ha.Local.IsFunc && isFunc {
		// Recovery: start or maintain hold-down.
		if !n.Ha.Local.PendingIsFunc {
			logger.GetLogger().Info("Local HA State recovery pending, starting hold-down",
				"holdDown", isFuncHoldDown)
			n.Ha.Local.PendingIsFunc = true
			n.Ha.Local.PendingEpoch = now
		}
		// Promotion is handled by haCheckIsFuncHoldDown in the periodic loop.
	} else if !n.Ha.Local.IsFunc && !isFunc {
		// Still degraded — cancel any pending recovery if criteria flapped
		// back to false during the hold-down window.
		if n.Ha.Local.PendingIsFunc {
			logger.GetLogger().Info("Local HA State hold-down cancelled, criteria failed again",
				"flapCount", n.Ha.Local.FlapCount+1)
			n.Ha.Local.PendingIsFunc = false
			n.Ha.Local.PendingEpoch = 0
			n.Ha.Local.FlapCount++
		}
	}

	n.haUpdateNxState(ctx)
}

// haCheckIsFuncHoldDown checks whether a pending IsFunc recovery has
// satisfied the hold-down period and, if so, promotes IsFunc to true.
// Called from the periodic haSetup loop.
// Caller must hold the lock.
func (n *Nxos) haCheckIsFuncHoldDown(ctx context.Context) {
	if !n.Ha.Local.PendingIsFunc {
		return
	}

	now := time.Now().Unix()
	elapsed := now - n.Ha.Local.PendingEpoch
	if elapsed < isFuncHoldDown {
		logger.GetLogger().Debug("Local HA State hold-down in progress",
			"elapsed", elapsed, "remaining", isFuncHoldDown-elapsed)
		return
	}

	// Verify criteria still pass before promoting.
	if !n.computeIsFunc() {
		logger.GetLogger().Info("Local HA State hold-down expired but criteria no longer pass, cancelling")
		n.Ha.Local.PendingIsFunc = false
		n.Ha.Local.PendingEpoch = 0
		n.Ha.Local.FlapCount++
		return
	}

	// Promote: hold-down satisfied and criteria still all-true.
	logger.GetLogger().Info("Local HA State hold-down complete, HA state set to true",
		"holdDown", isFuncHoldDown, "flapCount", n.Ha.Local.FlapCount)
	n.Ha.Local.IsFunc = true
	n.Ha.Local.Epoch = now
	n.Ha.Local.PendingIsFunc = false
	n.Ha.Local.PendingEpoch = 0
	n.Ha.Local.FlapCount = 0
	n.updateHaConfig()
	n.haUpdateNxState(ctx)
}

// computeAndUpdatePeerPolicy computes the PolicyOk value for a peer based on
// the current watching state and policy revisions, then updates the peer
// criterion.  This is called unconditionally (even when HA is not enabled) so
// that show_ha always reflects the correct policy status.
// Caller must hold the lock.
func (n *Nxos) computeAndUpdatePeerPolicy(ctx context.Context, peer string, info hav1.MbrInfo) {
	var polOk bool
	if n.Ha.Watching {
		if info.PolInfo != nil && n.Ha.PolRev == info.PolInfo.Revision {
			logger.GetLogger().Debug("Watching and revision matches")
			polOk = true
		} else {
			logger.GetLogger().Debug("Watching and revision mismatch or missing")
		}
	} else {
		logger.GetLogger().Debug("Not Watching")
		if info.PolInfo != nil {
			if info.PolInfo.Watching &&
				n.Ha.PolRev == info.PolInfo.Revision {
				logger.GetLogger().Debug("Peer watching and revision matches")
				polOk = true
			} else if !info.PolInfo.Watching && n.Ha.PolRev >= info.PolInfo.Revision {
				logger.GetLogger().Debug("Peer not watching and revision not higher")
				polOk = true
			}
		} else {
			logger.GetLogger().Debug("Peer has no policyInfo")
			polOk = true
		}
	}
	n.updatePeerPolicyCrit(ctx, peer, polOk)
}

// updatePeerPolicyCrit updates PolicyOk for a specific peer and recalculates IsFunc.
// Caller must hold the lock.
func (n *Nxos) updatePeerPolicyCrit(ctx context.Context, peer string, polOk bool) {
	if n.Ha.PeerCriteria == nil {
		return
	}
	crit, ok := n.Ha.PeerCriteria[peer]
	if !ok {
		// Peer not in PeerCriteria yet - initialize with current aggregate DPU state
		crit = HaPeerCriteria{
			ServiceOk:   false,
			PolicyOk:    polOk,
			KeepaliveOk: n.aggregateDpuKeepalive(),
			BulkSyncOk:  n.aggregateDpuBulkSync(),
		}
		n.Ha.PeerCriteria[peer] = crit
		n.setRemoteSvcState(ctx, peer)
		n.recalculateIsFuncAndState(ctx)
		return
	}
	if crit.PolicyOk != polOk {
		crit.PolicyOk = polOk
		n.Ha.PeerCriteria[peer] = crit
		n.setRemoteSvcState(ctx, peer)
		n.recalculateIsFuncAndState(ctx)
	}
}

// updatePeerServiceCrit updates ServiceOk for a specific peer.
// Caller must hold the lock.
func (n *Nxos) updatePeerServiceCrit(ctx context.Context, peer string, svcOk bool) {
	if n.Ha.PeerCriteria == nil {
		return
	}
	crit, ok := n.Ha.PeerCriteria[peer]
	if !ok {
		return
	}
	if crit.ServiceOk != svcOk {
		crit.ServiceOk = svcOk
		n.Ha.PeerCriteria[peer] = crit
		n.setRemoteSvcState(ctx, peer)
		n.recalculateIsFuncAndState(ctx)
	}
}

// recomputeAllPeerPolicyCrit recomputes PolicyOk for all peers based on current
// watching state and policy revision, then recalculates IsFunc.
// Caller must hold the lock.
func (n *Nxos) recomputeAllPeerPolicyCrit(ctx context.Context) {
	if n.Ha.PeerCriteria == nil {
		return
	}
	changed := false
	for peer, crit := range n.Ha.PeerCriteria {
		polOk := n.computePolicyOkForPeer(peer)
		if crit.PolicyOk != polOk {
			crit.PolicyOk = polOk
			n.Ha.PeerCriteria[peer] = crit
			changed = true
			n.setRemoteSvcState(ctx, peer)
		}
	}
	if changed {
		n.recalculateIsFuncAndState(ctx)
	}
}

// computePolicyOkForPeer computes whether policy is OK for a specific peer
// based on current watching state and member info.
func (n *Nxos) computePolicyOkForPeer(peer string) bool {
	mbr, ok := n.Ha.Members[peer]
	if !ok {
		return true // No member info yet, assume OK
	}
	if n.Ha.Watching {
		if mbr.Info.PolInfo != nil && n.Ha.PolRev == mbr.Info.PolInfo.Revision {
			return true
		}
		return false
	}
	// Not watching
	if mbr.Info.PolInfo != nil {
		if mbr.Info.PolInfo.Watching && n.Ha.PolRev == mbr.Info.PolInfo.Revision {
			return true
		}
		if !mbr.Info.PolInfo.Watching && n.Ha.PolRev >= mbr.Info.PolInfo.Revision {
			return true
		}
	} else {
		return true // No policy info from peer
	}
	return false
}

func (n *Nxos) HaUpdatePtnr(ctx context.Context, ptnr string, isDel bool) {
	logger.GetLogger().Debug("HaUpdatePtnr", "ptnr", ptnr, "isDel", isDel)

	peer, ok := n.GetHaPeer(ptnr)
	if ok {
		prev := peer.State
		if isDel {
			peer.State = hav1.MBR_STATE_HA_FAIL
		} else {
			peer.State = hav1.MBR_STATE_HA_OK
		}
		if peer.State != prev {
			n.SetHaPeer(ptnr, peer)
			n.setRemoteMbrState(ctx, ptnr)
		}
	} else {
		logger.GetLogger().Debug("Peer not found")
	}

	_, ok = n.Ha.Partners[ptnr]
	if isDel && ok {
		delete(n.Ha.Partners, ptnr)
		n.haUpdateNxState(ctx)
	} else if !isDel && !ok {
		n.Ha.Partners[ptnr] = struct{}{}
		n.haUpdateNxState(ctx)
	}
}

func (n *Nxos) haInit(ctx context.Context) {
	logger.GetLogger().Debug("haInit")

	n.getLocalSvcState(ctx)
	n.getLocalHaState(ctx)
	err := n.getHaIp(ctx)
	if err != nil {
		logger.GetLogger().Debug("haInit")
		logger.GetLogger().Error("Failed to get HA IP", logfields.Error, err)
		// Still push empty HA config so DPUs get the correct (disabled) state
		n.updateHaConfig()
		return
	} else if n.Ha.HaIp == "" {
		logger.GetLogger().Debug("Empty HA IP")
		// Still push empty HA config so DPUs get the correct (disabled) state
		n.updateHaConfig()
		return
	}

	jstrs, err := n.gnmiGet(ctx, svcInst+"/ha-items")
	if err != nil {
		logger.GetLogger().Error("Failed to get ha-items", logfields.Error, err)
		// Still push empty HA config so DPUs get the correct (disabled) state
		n.updateHaConfig()
		return
	}
	if len(jstrs) > 0 && len(jstrs[0]) > 0 {
		items := &model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_HaItems{}
		opts := []ytypes.UnmarshalOpt{&ytypes.IgnoreExtraFields{}}
		err = model.Unmarshal([]byte(jstrs[0]), items, opts...)
		if err != nil {
			logger.GetLogger().Error("Failed to unmarshal ha-items", logfields.Error, err)
			// Still push empty HA config so DPUs get the correct (disabled) state
			n.updateHaConfig()
			return
		}
		n.updtSasSvcSvcinstSvcInstanceHa(ctx, items)

		enabled := n.haIsEnabled(ctx, false)
		if !enabled {
			logger.GetLogger().Debug("haInit: HA not enabled")
			return
		}

		for peer := range n.GetHaPeers() {
			logger.GetLogger().Debug("haInit: initial adj")
			n.haConnect(ctx, peer)
			if n.haIsConnected(ctx, peer) {
				n.haAdjacency(ctx, peer)
			}
		}
	} else {
		logger.GetLogger().Debug("haInit: HA not configured, pushing empty HA config")
		n.updateHaConfig()
	}
}

func (n *Nxos) haSetup(ctx context.Context) {
	n.Ha.Start = time.Now().Unix()
	logger.GetLogger().Debug("haSetup", "epoch", n.Ha.Start)

	enabled := n.haIsEnabled(ctx, true)
	for {
		select {
		case <-ctx.Done():
			logger.GetLogger().Info("HA setup context canceled, exiting")
			return
		case wait := <-n.WaitHa.Out():
			logger.GetLogger().Debug("HA waked up", "wait", wait)

			n.setLocalHaState(ctx)
			n.haSetLeader(ctx)
			peers := n.haGetPeers(ctx)
			prevEnabled := enabled
			enabled = n.haIsEnabled(ctx, true)
			if prevEnabled && !enabled {
				// shutdown
				logger.GetLogger().Debug("HA disabled")
				for _, peer := range peers {
					n.haDisconnect(ctx, peer)
				}
			} else if !prevEnabled && enabled {
				// connect
				logger.GetLogger().Debug("HA enabled")
				for _, peer := range peers {
					n.haConnect(ctx, peer)
					if n.haIsConnected(ctx, peer) {
						n.haAdjacency(ctx, peer)
					}

				}
			}

		case <-time.After(haTimeout * time.Second):
			// logger.GetLogger().Debug("haTimeout at", "epoch", time.Now().Unix())
			n.haUpdateNx(ctx)
			n.Lock()
			n.haCheckIsFuncHoldDown(ctx)
			n.Unlock()
			if enabled {
				peers := n.haGetPeers(ctx)
				for _, peer := range peers {
					if !n.haIsConnected(ctx, peer) {
						n.haConnect(ctx, peer)
					}
					if n.haIsConnected(ctx, peer) {
						n.haAdjacency(ctx, peer)
					}
				}
				n.haCheckAdjMbr(ctx)
			}
		}
	}
}

func (n *Nxos) haSetLeader(ctx context.Context) {
	n.RLock()
	defer n.RUnlock()

	isLeader := true
	for peer := range n.GetHaPeers() {
		if n.Ha.HaIp < peer {
			isLeader = false
			break
		}
	}
	n.Ha.IsLeader = isLeader
	logger.GetLogger().Debug("haSetLeader:", "isLeader", isLeader)
}

func (n *Nxos) HaReconcile(ctx context.Context, peer string, info hav1.MbrInfo) {
	logger.GetLogger().Debug("HaReconcile:", "peer", peer, "mbrInfo", info)

	n.Lock()
	defer n.Unlock()

	// construct ha alloc from peer's VRF info
	alloc := map[string]uint16{}
	recon := map[string]uint16{}
	for _, vrf := range info.VrfInfo {
		alloc[vrf.Name] = uint16(vrf.Id)
	}

	// Check for GID conflicts and resolve based on leader status
	for vrf, gid := range n.Alloc.Gids {
		peerGid, hasPeerGid := alloc[vrf]
		if hasPeerGid && gid != peerGid {
			logger.GetLogger().Warn("GID conflict detected",
				"vrf", vrf,
				"localGid", gid,
				"peerGid", peerGid,
				"isLeader", n.Ha.IsLeader)

			if !n.Ha.IsLeader {
				// Non-leader adopts peer's GID (leader wins)
				n.Alloc.Gids[vrf] = peerGid
				n.GidsInUse[peerGid] = vrf
				delete(n.GidsInUse, gid)
				recon[vrf] = peerGid
				logger.GetLogger().Info("Non-leader adopted peer's GID",
					"vrf", vrf, "newGid", peerGid)
			}
			// Leader keeps its own GID - no action needed
		}
	}

	// Build reverse map of peer's GIDs (gid -> vrf name) to detect
	// cross-peer overlaps: local VRFs whose GID is used by a different
	// VRF on the peer.
	peerGidToVrf := map[uint16]string{}
	for vrfName, gid := range alloc {
		peerGidToVrf[gid] = vrfName
	}

	// Reserve peer's GIDs in GidsInUse so that future getGid() calls on
	// either side won't allocate a GID the peer already owns. This prevents
	// new overlaps that would cause reconciliation loops. Only add peer GIDs
	// not already tracked locally to avoid overwriting local VRF entries.
	for vrfName, gid := range alloc {
		if _, exists := n.GidsInUse[gid]; !exists {
			n.GidsInUse[gid] = vrfName
		}
	}

	// Check local-only VRFs for GID overlap with peer's different VRFs.
	// For example: local has brown:11, peer has vrf-ixia1:11 — same GID,
	// different VRF names. The non-leader must reallocate to avoid the
	// overlap since the peer (leader) owns that GID.
	for vrf, gid := range n.Alloc.Gids {
		_, hasPeerVrf := alloc[vrf]
		if hasPeerVrf {
			// Same VRF name on both peers — already handled in Phase 1
			continue
		}
		peerVrf, peerUsesGid := peerGidToVrf[gid]
		if peerUsesGid && peerVrf != vrf {
			logger.GetLogger().Warn("Cross-peer GID overlap detected",
				"localVrf", vrf,
				"peerVrf", peerVrf,
				"gid", gid,
				"isLeader", n.Ha.IsLeader)

			if !n.Ha.IsLeader {
				// Non-leader must reallocate since peer owns this GID.
				// Reserve the GID for the peer's VRF so getGid() won't
				// pick it during reallocation.
				n.GidsInUse[gid] = peerVrf
				gid2 := n.getGid(ctx, vrf)
				if gid2 != 0 {
					n.Alloc.Gids[vrf] = gid2
					recon[vrf] = gid2
					logger.GetLogger().Info("Non-leader reallocated GID for cross-peer overlap",
						"vrf", vrf, "oldGid", gid, "newGid", gid2)
				}
			}
		}
	}

	n.Ha.Alloc[peer] = HaAlloc{
		Gids: alloc,
	}
	logger.GetLogger().Debug("HA alloc:", "alloc", alloc)

	// Apply VRF reconciliation if needed
	if len(recon) > 0 {
		logger.GetLogger().Debug("HA reconcile VRFs:", "recon", recon)
		n.setGlobalId(ctx, recon)
		n.store(ctx, allocFname, n.Alloc)
		err := n.doVRFPolicyMapUpdate()
		if err != nil {
			logger.GetLogger().Error("Failed to update VRF policy map after HA reconciliation", "error", err)
		}
	}

	// VLAN reconciliation - handle DPU pinning conflicts
	vlanRecon := map[string]uint16{}
	for _, vlanInfo := range info.VlanInfo {
		vlanName := fmt.Sprintf("vlan-%d", vlanInfo.Id)
		localVlan, ok := n.Bds[vlanName]
		if ok && localVlan.DpuPinned != uint16(vlanInfo.Dpu) {
			logger.GetLogger().Warn("VLAN DPU pinning conflict detected",
				"vlan", vlanName,
				"localDpu", localVlan.DpuPinned,
				"peerDpu", vlanInfo.Dpu,
				"isLeader", n.Ha.IsLeader)

			if !n.Ha.IsLeader {
				// Non-leader adopts peer's DPU pinning (leader wins)
				localVlan.DpuPinned = uint16(vlanInfo.Dpu)
				n.Bds[vlanName] = localVlan
				vlanRecon[vlanName] = uint16(vlanInfo.Dpu)
				logger.GetLogger().Info("Non-leader adopted peer's VLAN DPU pinning",
					"vlan", vlanName, "newDpu", vlanInfo.Dpu)
			}
		}
	}
	if len(vlanRecon) > 0 {
		logger.GetLogger().Debug("HA reconcile VLANs:", "vlanRecon", vlanRecon)
		n.store(ctx, allocFname, n.Alloc)
		err := n.doVlanPolicyMapUpdate()
		if err != nil {
			logger.GetLogger().Error("Failed to update VLAN policy map after HA reconciliation", "error", err)
		}
		// Reprogram service redirects for reconciled VLANs if already in normal stage
		if n.Stage == StageNormal {
			reconBds := []VrfBd{}
			for vlanName := range vlanRecon {
				if bd, ok := n.Bds[vlanName]; ok {
					reconBds = append(reconBds, bd)
				}
			}
			if len(reconBds) > 0 {
				err = n.setFwPolicyState(ctx, true, reconBds)
				if err != nil {
					logger.GetLogger().Error("Failed to reprogram VLAN fw policy state after HA reconciliation", "error", err)
				}
				err = n.setServiceRedir(ctx, true, reconBds)
				if err != nil {
					logger.GetLogger().Error("Failed to reprogram VLAN service redir after HA reconciliation", "error", err)
				}
			}
		}
	}
}

func (n *Nxos) IsPolRevMatch(peer string, peerPolInfo *hav1.PolInfo) (bool, string) {
	n.RLock()
	defer n.RUnlock()

	if !n.Ha.Watching {
		return true, ""
	}
	if peerPolInfo == nil {
		return false, "peer has no policy info while local is watching"
	}
	if n.Ha.PolRev != peerPolInfo.Revision {
		reason := fmt.Sprintf("policy revision mismatch while watching: peer=%s local=%s", peerPolInfo.Revision, n.Ha.PolRev)
		logger.GetLogger().Error("Policy revision mismatch on adjacency",
			"peer", peer, "localRev", n.Ha.PolRev, "peerRev", peerPolInfo.Revision)
		return false, reason
	}
	return true, ""
}

func (n *Nxos) IsPeerOk(ctx context.Context, peer string) bool {
	n.RLock()
	defer n.RUnlock()

	for p := range n.GetHaPeers() {
		if p == peer {
			return true
		}
	}
	return false
}

// TriggerHAReconciliation triggers HA reconciliation with all connected peers.
// This should be called when transitioning from out-of-service to in-service
// to ensure GID and VLAN allocations are consistent across the HA pair.
// For leaders, this initiates adjacency (which now includes reconciliation).
// For followers, this reconciles against the leader's last-known member info.
func (n *Nxos) TriggerHAReconciliation(ctx context.Context) {
	logger.GetLogger().Info("Triggering HA reconciliation for all peers")

	n.RLock()
	enabled := n.haIsEnabled(ctx, false)
	isLeader := n.Ha.IsLeader
	peers := make([]string, 0)
	memberInfos := make(map[string]hav1.MbrInfo)
	for peer, mbr := range n.Ha.Members {
		peers = append(peers, peer)
		memberInfos[peer] = mbr.Info
	}
	n.RUnlock()

	if !enabled {
		logger.GetLogger().Debug("HA not enabled, skipping reconciliation")
		return
	}

	if isLeader {
		// Leader: initiate adjacency which now includes reconciliation (Step 5)
		for _, peer := range peers {
			logger.GetLogger().Debug("Triggering adjacency with peer for reconciliation", "peer", peer)
			if n.haIsConnected(ctx, peer) {
				n.haAdjacency(ctx, peer)
			}
		}
	} else {
		// Follower: reconcile against leader's last-known member info
		for _, peer := range peers {
			info, ok := memberInfos[peer]
			if !ok {
				continue
			}
			logger.GetLogger().Debug("Follower reconciling against leader's member info", "peer", peer)
			n.HaReconcile(ctx, peer, info)
		}
	}
}

func (n *Nxos) NotifyWatching(ctx context.Context, watching bool) {
	logger.GetLogger().Debug("NotifyWatching", "watching", watching)

	n.Lock()
	defer n.Unlock()

	prev := n.Ha.Watching
	if watching != prev {
		logger.GetLogger().Debug("Watching changed")
		n.Ha.Watching = watching
		// Recompute policy status for all peers based on new watching state
		n.recomputeAllPeerPolicyCrit(ctx)
	}
}

func (n *Nxos) NotifyPolRev(ctx context.Context, rev string) {
	logger.GetLogger().Debug("NotifyPolRev", "revision", rev)

	n.Lock()
	defer n.Unlock()

	prev := n.Ha.PolRev
	if rev != prev {
		logger.GetLogger().Debug("Policy revision changed")
		n.Ha.PolRev = rev
		// Recompute policy status for all peers based on new revision
		n.recomputeAllPeerPolicyCrit(ctx)
	}
}

// HaSetDebugFail injects or removes the debug override criteria.
// When fail=true, adds the debug criteria set to false (causes HA failure).
// When fail=false, removes the debug criteria (restores normal operation).
func (n *Nxos) HaSetDebugFail(ctx context.Context, fail bool) {
	n.Lock()
	defer n.Unlock()

	logger.GetLogger().Info("HaSetDebugFail", "fail", fail)
	if fail {
		// Add the debug criteria set to false to cause failure
		n.Ha.Local.Criteria[HaCritDebugFail] = false
		n.recalculateIsFuncAndState(ctx)
	} else {
		// Remove the debug criteria to restore normal operation
		delete(n.Ha.Local.Criteria, HaCritDebugFail)
		n.recalculateIsFuncAndState(ctx)
	}
}
