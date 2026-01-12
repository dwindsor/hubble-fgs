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

	status := fmt.Sprintf("\n HA local IP: %v", n.Ha.HaIp)
	status += "\n HA Peers: "
	for ip, peer := range n.GetHaPeers() {
		status += fmt.Sprintf("ip: %v ok: %v,", ip, peer.IpConfigOk)
	}
	status += fmt.Sprintf("\n HA enabled: %v", n.GetHaEnabled())
	status += fmt.Sprintf("\n HA operational: %v", n.GetHaOperUp())
	status += fmt.Sprintf("\n HA leader: %v", n.Ha.IsLeader)
	status += fmt.Sprintf("\n Policy watching: %v, hash: %v, revision: %v",
		n.Ha.Watching, n.Ha.PolHash, n.Ha.PolRev)
	status += fmt.Sprintf("\n Local service functional: %v, updated at: %v",
		n.Ha.Local.IsFunc, n.Ha.Local.Epoch)
	status += "\n  Criteria: "
	for crit, val := range n.Ha.Local.Criteria {
		status += fmt.Sprintf("%v: %v, ", crit, val)
	}
	status += fmt.Sprintf("\n NX HA state: %v, updated at: %v",
		n.Ha.NxStates.HaState, n.Ha.NxStates.HaStateEpoch)
	status += fmt.Sprintf("\n NX service state: %v, updated at: %v",
		n.Ha.NxStates.SvcState, n.Ha.NxStates.SvcStateEpoch)
	status += "\n Flow sync from "
	for ip, val := range n.Ha.FlowSync {
		status += fmt.Sprintf("ip: %v ok: %v,", ip, val)
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
	if len(n.Ha.Partners) > 0 {

		status += "\n HA parteners:"
		for ip := range n.Ha.Partners {
			status += " " + ip
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
