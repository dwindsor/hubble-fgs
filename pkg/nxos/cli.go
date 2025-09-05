package nxos

import (
	"context"
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
		status += "\n" + "Number of DPUs in sync of policies: " +
			strconv.FormatInt(int64(len(n.InSync)), 10)
	}
	status += "\n" + "Next global ID to be allocated: " +
		strconv.FormatUint(uint64(n.Alloc.Next), 10)
	status += "\n"

	return status
}

func (n *Nxos) ShowDpu(_ context.Context) map[string]string {
	logger.GetLogger().Debug("show dpu")

	n.RLock()
	defer n.RUnlock()

	dpus := map[string]string{}
	for k, v := range n.Dpus {
		var found bool
		for _, ip := range n.InSync {
			if ip == v.Ip {
				found = true
			}
		}
		if found {
			dpus[v.Ip] = "IP " + v.Ip + ", Number " + k + ", InSync true"
		} else {
			dpus[v.Ip] = "IP " + v.Ip + ", Number " + k + ", InSync false"
		}
	}
	return dpus
}

func (n *Nxos) ShowVrf(ctx context.Context) string {
	logger.GetLogger().Debug("show vrf")

	n.RLock()
	defer n.RUnlock()

	vrf := ""
	for k, v := range n.Vrfs {
		vrf += "\n" + "Name " + k
		vrf += ", IsGlobal " + strconv.FormatBool(v.IsGlobal)
		vrf += ", IsService " + strconv.FormatBool(v.IsService)
		vrf += ", IsStaticPinned " + strconv.FormatBool(v.IsStatic)
		if v.IsStatic {
			vrf += ", StaticAffinity " +
				strconv.FormatUint(uint64(v.Affinity), 10)
		}
		if v.IsGlobal && v.IsService {
			if n.isLbModePinning(ctx) {
				vrf += ", DPU pinned " +
					strconv.FormatUint(uint64(v.DpuPinned), 10)
			} else {
				vrf += ", DPU pinned N/A (sh)"
			}
			gid, ok := n.Alloc.Gids[k]
			if ok {
				vrf += ", GloabId assigned " +
					strconv.FormatUint(uint64(gid), 10)
			}
		}
	}
	vrf += "\n"

	return vrf
}

func (n *Nxos) DelTokens(_ context.Context) string {
	logger.GetLogger().Debug("del tokens")

	err := os.Remove("/iox_data/cpa_tokens")
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
	for ip, peer := range n.Ha.Peers {
		status += fmt.Sprintf("ip: %v ok: %v,", ip, peer.IpConfigOk)
	}
	status += fmt.Sprintf("\n HA enabled: %v", n.Ha.Enabled)
	status += fmt.Sprintf("\n HA operational: %v", n.Ha.OperUp)
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
