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
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"

	hav1 "github.com/isovalent/hubble-fgs/pkg/proto/ha/v1"
)

func (n *Nxos) ShowStatus(_ context.Context) string {
	logger.GetLogger().Debug("show operational status")

	n.RLock()
	defer n.RUnlock()

	status := "\n" + "Stage: " + string(n.Stage)
	ts := time.Unix(n.LastNotif, 0)
	tsStr := ts.Format("2006-01-02 15:04:05")
	status += "\n" + "Last NX notification: " + tsStr
	status += "\n" + "Headless mode configured: " + strconv.FormatBool(n.SkipCtrlr)
	status += "\n" + "DPUless mode: " + strconv.FormatBool(n.SkipDpu)
	if !n.SkipDpu {
		status += "\n" + "Number of DPUs: " +
			strconv.FormatInt(int64(n.NumDpu), 10)

		// Calculating number of DPUs in sync for policy
		inSync := 0
		if n.dpuListener != nil {
			csum := n.dpuListener.Checksum()
			hexChecksum := hex.EncodeToString(csum[:])
			statuses, err := n.dpuListener.GetDPUStatus()
			if err != nil {
				logger.GetLogger().Error("failed to get dpu status", logfields.Error, err)
			} else {
				for _, s := range statuses {
					if s.PolicyChecksum == hexChecksum {
						inSync += 1
					}
				}
			}
		}
		status += "\n" + "Number of DPUs in sync of policies: " +
			strconv.FormatInt(int64(inSync), 10)
	}
	status += "\n" + "Next global ID to be allocated: " +
		strconv.FormatUint(uint64(n.Alloc.Next), 10)
	status += "\n"

	return status
}

func (n *Nxos) DelTokens(_ context.Context) string {
	logger.GetLogger().Debug("del tokens")

	err := os.Remove("/iox_data/k8sauth_token")
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err.Error()
	}
	return "Tokens deleted"
}

func (n *Nxos) ShowHa(_ context.Context) string {
	logger.GetLogger().Debug("show high availability")

	n.RLock()
	defer n.RUnlock()

	okOrFail := func(v bool) string {
		if v {
			return "OK"
		}
		return "FAIL"
	}

	haStateName := func(s hav1.HA_STATE) string {
		switch s {
		case hav1.HA_STATE_HA_READY:
			return "active/active"
		case hav1.HA_STATE_HA_NOTREADY:
			return "standalone"
		case hav1.HA_STATE_HA_TAKEOVER:
			return "active/standby (active)"
		case hav1.HA_STATE_HA_SWITCHOVER:
			return "active/standby (standby)"
		case hav1.HA_STATE_HA_DEGRADED:
			return "unavailable"
		case hav1.HA_STATE_NO_HA:
			return "no-ha"
		default:
			return "unknown"
		}
	}

	// NX states (local + peer)
	status := "\n=== NX States ==="
	localSvcName := "not-ready"
	if n.Ha.NxStates.SvcState == hav1.SERVICE_STATE_SVC_SUCCESS {
		localSvcName = "ready"
	}
	status += fmt.Sprintf("\n  Local HA: %v (%v)  Svc: %v",
		n.Ha.NxStates.HaState, haStateName(n.Ha.NxStates.HaState), localSvcName)
	for ip := range n.GetHaPeers() {
		peerSvc := "unknown"
		if ps, ok := n.Ha.PeerSvcStates[ip]; ok {
			switch ps {
			case PeerSvcReady:
				peerSvc = "ready"
			case PeerSvcNotReady:
				peerSvc = "not-ready"
			}
		}
		peerHA := "ha-fail"
		if pc, ok := n.Ha.PeerCriteria[ip]; ok && pc.IsOk() {
			peerHA = "ha-ok"
		}
		status += fmt.Sprintf("\n  Peer %v: Svc=%v  HA=%v", ip, peerSvc, peerHA)
	}

	// Local state
	status += "\n\n=== Local State ==="
	status += fmt.Sprintf("\n  IP: %v  Leader: %v  Enabled: %v  Oper Ready: %v",
		n.Ha.HaIp, n.Ha.IsLeader, n.GetHaEnabled(), n.GetHaOperUp())
	localSvc := "not-ready"
	if n.Ha.Local.IsFunc {
		localSvc = "ready"
	}
	status += fmt.Sprintf("\n  Local Service: %v  IsFunc: %v  Recovery Pending: %v  Flaps: %v",
		localSvc, n.Ha.Local.IsFunc, n.Ha.Local.IsFuncRecoveryPending, n.Ha.Local.FlapCount)
	status += fmt.Sprintf("\n  Model: %v  SerNum: %v  SwVer: %v  CpaVer: %v  LbMode: %v  DPUs: %v",
		n.Model, n.SerNum, n.SwVer, n.CpaVer, n.LbMode, len(n.Dpus))
	if n.Ha.Watching {
		status += fmt.Sprintf("\n  Policy Revision: %v", n.Ha.PolRev)
	} else {
		status += "\n  Policy Revision: not checking"
	}
	status += "\n  Criteria:"
	for crit, val := range n.Ha.Local.Criteria {
		status += fmt.Sprintf("\n    [%s] %v", okOrFail(val), crit)
	}

	if len(n.Ha.DpuKeepalive) > 0 || len(n.Ha.DpuBulkSync) > 0 {
		status += "\n  DPUs:"
		dpuUIDs := make(map[string]struct{})
		for uid := range n.Ha.DpuKeepalive {
			dpuUIDs[uid] = struct{}{}
		}
		for uid := range n.Ha.DpuBulkSync {
			dpuUIDs[uid] = struct{}{}
		}
		for uid := range dpuUIDs {
			bs := n.Ha.DpuBulkSync[uid]
			status += fmt.Sprintf("\n    %v: [%s] Keepalive  [%s] Bulk Sync (local=%s peer=%s)",
				uid, okOrFail(n.Ha.DpuKeepalive[uid]), okOrFail(bs.Done()),
				okOrFail(bs.LocalDone), okOrFail(bs.PeerDone))
		}
	}

	// Peer state
	status += "\n\n=== Peers ==="
	peers := n.GetHaPeers()
	if len(peers) == 0 {
		status += "\n  (no peers configured)"
	}
	for ip, peer := range peers {
		reason := ""
		if peer.StateReason != "" {
			reason = fmt.Sprintf("  Reason: %v", peer.StateReason)
		}
		status += fmt.Sprintf("\n  %v HA State: %v  IP Config OK: %v%s", ip, peer.State, peer.IpConfigOk, reason)
		if peerCrit, ok := n.Ha.PeerCriteria[ip]; ok {
			status += fmt.Sprintf("\n    [%s] Membership  [%s] Policy  [%s] Keepalive  [%s] Bulk Sync",
				okOrFail(peerCrit.MembershipOk), okOrFail(peerCrit.PolicyOk),
				okOrFail(peerCrit.KeepaliveOk), okOrFail(peerCrit.BulkSyncOk))
		}
	}

	status += "\n"
	return status
}

func (n *Nxos) ShowAdj(_ context.Context) string {
	logger.GetLogger().Debug("show HA adjacencies")

	n.RLock()
	defer n.RUnlock()

	var status string
	for ip, adj := range n.Ha.Adjacencies {
		status += fmt.Sprintf("\n IP: %v, connection initiated: %v, updated at %v",
			ip, adj.Connected, adj.Epoch)
	}
	status += "\n"

	return status
}

func (n *Nxos) ShowMbr(_ context.Context) string {
	logger.GetLogger().Debug("show HA members")

	n.RLock()
	defer n.RUnlock()

	var status string
	for ip, mbr := range n.Ha.Members {
		status += fmt.Sprintf("\n IP: %v, updated at: %v, info: %+v",
			ip, mbr.Epoch, mbr.Info)
	}
	if len(n.Ha.PeerSvcStates) > 0 {
		status += "\n Peer service states:"
		for ip, svc := range n.Ha.PeerSvcStates {
			svcStr := "unknown"
			switch svc {
			case PeerSvcReady:
				svcStr = "ready"
			case PeerSvcNotReady:
				svcStr = "not-ready"
			}
			status += fmt.Sprintf(" %s=%s", ip, svcStr)
		}
	}
	status += "\n"
	return status
}

func (n *Nxos) ShowGid(_ context.Context) string {
	logger.GetLogger().Debug("show global IDs")

	n.RLock()
	defer n.RUnlock()

	var status string
	status += fmt.Sprintf("\n local global ID allocation: %+v", n.Alloc.Gids)
	status += fmt.Sprintf("\n local global ID in use: %+v", n.GidsInUse)
	status += fmt.Sprintf("\n HA global ID allocation: %+v", n.Ha.Alloc)
	status += "\n"
	return status
}
