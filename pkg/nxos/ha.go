package nxos

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"

	hav1 "github.com/isovalent/hubble-fgs/pkg/proto/v1/ha"
)

const (
	haTimeout       = 10 // in second
	haPort          = "8883"
	nxUpdateTimeout = 30 // in sec
	adjTimeout      = 30 // in sec
	mbrTimeout      = 30 // in sec
)

func (n *Nxos) haIsEnabled(_ context.Context, isLock bool) bool {
	if isLock {
		n.RLock()
		defer n.RUnlock()
	}

	logger.GetLogger().Debug("HaEnabled: ", "", n.Ha.Enabled)
	return n.Ha.Enabled && n.Ha.OperUp
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

func (n *Nxos) HaSetMbrInfo(ctx context.Context, peer string, info hav1.MbrInfo) {
	n.Lock()
	defer n.Unlock()

	n.haSetMbrInfo(ctx, peer, info)
}

func (n *Nxos) haSetMbrInfo(ctx context.Context, peer string, info hav1.MbrInfo) {
	logger.GetLogger().Debug("haSetMbrInfo:", "peer", peer, "mbrInfo", info)

	now := time.Now().Unix()
	_, ok := n.Ha.Adjacencies[peer]
	if !ok {
		n.Ha.Adjacencies[peer] = HaAdj{
			Epoch: now,
		}
	}

	notify := false
	mbr, ok := n.Ha.Members[peer]
	if !ok {
		notify = true
	} else if mbr.Info.HaInfo.Ha != info.HaInfo.Ha ||
		mbr.Info.HaInfo.Service != info.HaInfo.Service {
		notify = true
	}

	n.Ha.Members[peer] = HaMbr{
		Info:  info,
		Epoch: now,
	}

	// skip vlan/vrf checking for now
	var isDel bool
	if info.SysInfo.Model != n.Model {
		logger.GetLogger().Debug("Model mismatch:", "info", info.SysInfo.Model, "n", n.Model)
		isDel = true
	} else if info.SysInfo.SwVer != n.SwVer {
		logger.GetLogger().Debug("NxOS version mismatch:", "version", info.SysInfo.SwVer, "n", n.SwVer)
		isDel = true
	} else if info.SysInfo.Cpa != n.CpaVer {
		logger.GetLogger().Debug("CPA version mismatch:", "cpa", info.SysInfo.Cpa, "n", n.CpaVer)
		isDel = true
	} else if info.HaInfo.FlowSync == hav1.FLOW_SYNC_STATE_SYNC_FAILURE {
		logger.GetLogger().Debug("Peer cannot get flow sync")
		isDel = true
	} else if info.HaInfo.Service == hav1.SERVICE_STATE_SVC_FAILURE {
		logger.GetLogger().Debug("Peer cannot provide service")
		isDel = true
	} else if n.Ha.Watching && !info.PolInfo.Watching &&
		n.Ha.PolRev != info.PolInfo.Revision {
		logger.GetLogger().Debug("Peer not watching and has diff policy revision")
		isDel = true
	} else if len(info.SysInfo.Dpus) != len(n.Dpus) {
		logger.GetLogger().Debug("DPU number mismatch:", "DPUs", len(info.SysInfo.Dpus), "n", len(n.Dpus))
		isDel = true
	} else {
		for _, dpu := range info.SysInfo.Dpus {
			d, ok := n.Dpus[dpu.Name]
			if !ok {
				logger.GetLogger().Debug("DPU not found", "name", dpu.Name)
				isDel = true
				break
			}
			if d.Version != dpu.Version {
				logger.GetLogger().Debug("DPU version mismatch", dpu.Version, d.Version)
				isDel = true
				break
			}
		}
	}
	n.HaUpdatePtnr(ctx, peer, isDel)

	var polOk bool
	if !n.Ha.Watching {
		logger.GetLogger().Debug("Not Watching")
		if info.PolInfo.Watching &&
			n.Ha.PolRev == info.PolInfo.Revision {
			logger.GetLogger().Debug("Peer watching and revision matches")
			polOk = true
		} else if !info.PolInfo.Watching && n.Ha.PolRev > info.PolInfo.Revision {
			logger.GetLogger().Debug("Peer not watching and revision lower")
			polOk = true
		}
	}
	if polOk {
		n.haUpdateCrit(ctx, HaCritPolicy, true)
	}
	if notify {
		n.setRemoteStates(ctx, peer)
	}
}

func (n *Nxos) HaGetMbrInfo(_ context.Context, peer string) hav1.MbrInfo {
	logger.GetLogger().Debug("HaGetMbrInfo")

	n.RLock()
	defer n.RUnlock()

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

	var fs hav1.FLOW_SYNC_STATE
	s, ok := n.Ha.FlowSync[peer]
	if ok && s {
		fs = hav1.FLOW_SYNC_STATE_SYNC_SUCCESS
	} else {
		fs = hav1.FLOW_SYNC_STATE_SYNC_FAILURE
	}

	var ss hav1.SERVICE_STATE
	if n.Ha.Local.IsFunc {
		ss = hav1.SERVICE_STATE_SVC_SUCCESS
	} else {
		ss = hav1.SERVICE_STATE_SVC_FAILURE
	}

	ha := hav1.HaInfo{
		FlowSync: fs,
		Service:  ss,
		Ha:       n.Ha.NxStates.HaState,
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

	if n.Ha.HaIp < peer {
		logger.GetLogger().Debug("haConnect: skip", "local", n.Ha.HaIp, "peer", peer)
		return
	}

	n.Lock()
	defer n.Unlock()

	p, ok := n.Ha.Peers[peer]
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

	delete(n.Ha.Adjacencies, peer)
	delete(n.Ha.Members, peer)

	if n.Ha.HaIp < peer {
		logger.GetLogger().Debug("haDisconnect: skip", "localIP", n.Ha.HaIp, "peerIP", peer)
		return
	}

	adj, ok := n.Ha.Adjacencies[peer]
	if !ok {
		logger.GetLogger().Error("Fail to disconnect: Adj not found")
		return
	}
	adj.GrpcClient.Close()
}

func (n *Nxos) haAdjacency(ctx context.Context, peer string) {
	logger.GetLogger().Debug("haAdjacency:", "peer", peer)

	if n.Ha.HaIp < peer {
		logger.GetLogger().Debug("haAdjacency: skip", "localIP", n.Ha.HaIp, "peer", peer)
		return
	}

	n.RLock()
	defer n.RUnlock()

	adj, ok := n.Ha.Adjacencies[peer]
	if !ok {
		n.Ha.Adjacencies[peer] = HaAdj{}
		adj = n.Ha.Adjacencies[peer]
	}

	info := n.HaGetMbrInfo(ctx, peer)
	req := &hav1.AdjRequest{
		HaIp:    n.Ha.HaIp,
		MbrInfo: &info,
	}
	logger.GetLogger().Debug("Adjacency request:", "req", req)
	rsp, err := adj.GrpcClient.Client.Adjacency(ctx, req)
	if err != nil {
		logger.GetLogger().Error("Adjacency fails", logfields.Error, err)
	} else {
		logger.GetLogger().Debug("Adjacency response:", "rsp", rsp)
		n.haSetMbrInfo(ctx, peer, *rsp.MbrInfo)
	}
}

func (n *Nxos) haGetPeers(_ context.Context) []string {
	n.RLock()
	defer n.RUnlock()
	var peers []string
	for a := range n.Ha.Peers {
		logger.GetLogger().Debug("Peer found:", "peer", a)
		peers = append(peers, a)
	}
	return peers
}

func (n *Nxos) haUpdateNxState(_ context.Context) {
	now := time.Now().Unix()
	logger.GetLogger().Debug("haUpdateNxState:", "time", now)

	var svcState hav1.SERVICE_STATE
	var haState hav1.HA_STATE
	if n.Ha.Local.IsFunc {
		svcState = hav1.SERVICE_STATE_SVC_SUCCESS
		if len(n.Ha.Partners) > 0 {
			haState = hav1.HA_STATE_HA_READY
		} else {
			haState = hav1.HA_STATE_HA_NOTREADY
		}
	} else {
		svcState = hav1.SERVICE_STATE_SVC_FAILURE
		haState = hav1.HA_STATE_HA_SWITCHOVER
	}
	// logger.GetLogger().Debug("svcState %v haState %v", svcState, haState)

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

func (n *Nxos) haCheckAdjMbr(ctx context.Context) {
	now := time.Now().Unix()
	logger.GetLogger().Debug("haCheckAdjMbr", "time", now)

	n.Lock()
	defer n.Unlock()

	for ip, adj := range n.Ha.Adjacencies {
		if now-adj.Epoch > adjTimeout {
			logger.GetLogger().Debug("Adjacency timed out", "ip", ip)
			delete(n.Ha.Adjacencies, ip)
			n.HaUpdatePtnr(ctx, ip, true)
		}
	}
	for ip, mbr := range n.Ha.Members {
		if now-mbr.Epoch > mbrTimeout {
			logger.GetLogger().Debug("Member timed out", "ip", ip)
			delete(n.Ha.Members, ip)
			n.HaUpdatePtnr(ctx, ip, true)
		}
	}
}

func (n *Nxos) haUpdateNx(ctx context.Context) {
	/*
		logger.GetLogger().Debug("haUpdateNx: haState %v epoch %v svcState %v epoch %v",
			n.Ha.NxStates.HaState, n.Ha.NxStates.HaStateEpoch,
			n.Ha.NxStates.SvcState, n.Ha.NxStates.SvcStateEpoch)
	*/

	now := time.Now().Unix()

	n.Lock()
	defer n.Unlock()

	if n.Ha.NxStates.HaStateEpoch != 0 &&
		now-n.Ha.NxStates.HaStateEpoch > nxUpdateTimeout {
		n.Ha.NxStates.HaStateEpoch = 0
		// update nx
		n.setLocalHaState(ctx)
	}
	if n.Ha.NxStates.SvcStateEpoch != 0 &&
		now-n.Ha.NxStates.SvcStateEpoch > nxUpdateTimeout {
		n.Ha.NxStates.SvcStateEpoch = 0

		switch n.Ha.NxStates.SvcState {
		case hav1.SERVICE_STATE_SVC_UNKNOWN:
			logger.GetLogger().Debug("Skip unknown state")

		case hav1.SERVICE_STATE_SVC_SUCCESS:
			logger.GetLogger().Debug("Program service redir")
			n.setServiceRedirAll(ctx, false)
			n.setLocalSvcState(ctx)

		case hav1.SERVICE_STATE_SVC_FAILURE:
			logger.GetLogger().Debug("Cleanup service redir")
			n.cleanup(ctx)
		}
	}
}

func (n *Nxos) HaUpdateCrit(ctx context.Context, crit HaCrit, val bool) {
	n.Lock()
	defer n.Unlock()

	n.haUpdateCrit(ctx, crit, val)
}

func (n *Nxos) haUpdateCrit(ctx context.Context, crit HaCrit, val bool) {
	now := time.Now().Unix()
	prev := n.Ha.Local.Criteria[crit]
	var updated bool
	if prev != val {
		logger.GetLogger().Debug("haUpdateCrit", "crit", crit, "val", val)
		n.Ha.Local.Criteria[crit] = val
		if val {
			isFunc := true
			for _, v := range n.Ha.Local.Criteria {
				if !v {
					isFunc = false
					break
				}
			}
			if isFunc {
				n.Ha.Local.IsFunc = true
				n.Ha.Local.Epoch = now
				updated = true
			}
		} else if n.Ha.Local.IsFunc {
			n.Ha.Local.IsFunc = false
			n.Ha.Local.Epoch = now
			updated = true
		}
	}
	if updated {
		n.haUpdateNxState(ctx)
	}
}

func (n *Nxos) HaUpdatePtnr(ctx context.Context, ptnr string, isDel bool) {
	logger.GetLogger().Debug("HaUpdatePtnr", "ptnr", ptnr, "isDel", isDel)

	_, ok := n.Ha.Partners[ptnr]
	if isDel && ok {
		delete(n.Ha.Partners, ptnr)
		n.haUpdateNxState(ctx)
	} else if !isDel && !ok {
		n.Ha.Partners[ptnr] = struct{}{}
		n.haUpdateNxState(ctx)
	}
}

func (n *Nxos) haSetup(ctx context.Context) {
	logger.GetLogger().Debug("haSetup")

	enabled := n.haIsEnabled(ctx, true)
	for {
		select {
		case wait := <-n.WaitHa.Out():
			logger.GetLogger().Debug("HA waked up", "wait", wait)
			peers := n.haGetPeers(ctx)
			if len(peers) == 0 {
				logger.GetLogger().Debug("No peers configured")
				break
			} else if len(peers) > 1 {
				logger.GetLogger().Debug("At most one peer: skip", "peers", peers)
				break
			} else {
				logger.GetLogger().Debug("Peers found", "peers", peers)
			}

			prevEnabled := enabled
			enabled = n.haIsEnabled(ctx, true)
			if prevEnabled && !enabled {
				// shutdown
				for _, peer := range peers {
					n.haDisconnect(ctx, peer)
				}
			} else if !prevEnabled && enabled {
				// connect
				for _, peer := range peers {
					n.haConnect(ctx, peer)
				}
			}

		case <-time.After(haTimeout * time.Second):
			if enabled {
				logger.GetLogger().Debug("haTimeout")
				peers := n.haGetPeers(ctx)
				if len(peers) == 0 {
					break
				} else if len(peers) > 1 {
					logger.GetLogger().Debug("At most one peer: skip", "peers", peers)
					break
				} else {
					logger.GetLogger().Debug("Peers found", "peers", peers)
				}

				for _, peer := range peers {
					if !n.haIsConnected(ctx, peer) {
						n.haConnect(ctx, peer)
					}
					if n.haIsConnected(ctx, peer) {
						n.haAdjacency(ctx, peer)
					}
				}
				n.haUpdateNx(ctx)
				n.haCheckAdjMbr(ctx)
			}
		}
	}
}
