// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package agwctl

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/isovalent/hubble-fgs/pkg/agw"
	"github.com/isovalent/hubble-fgs/pkg/ipc"

	"github.com/isovalent/hubble-fgs/pkg/model/switchevents"
	"github.com/isovalent/hubble-fgs/pkg/model/switchmetrics"
	"github.com/isovalent/hubble-fgs/pkg/model/switchtechsupport"
)

// Commands
const (
	CMD_LOAD_POLICY = iota
	CMD_SHOW_POLICY
	CMD_SHOW_STATUS
	CMD_SHOW_DPU
	CMD_SHOW_VRF
	CMD_DEL_TOKENS
	CMD_HEALTH
	CMD_SHOW_LOG
	CMD_SHOW_TOKENS
	CMD_SHOW_TECH
	CMD_TAC_PAC
	CMD_TECH_SUPPORT_DPU
	CMD_PING_FWA
	CMD_RESTART_FWA
	CMD_LOAD_SYSLOG_CFG
	CMD_SHOW_SYSLOG_CFG
	CMD_SHOW_HA
	CMD_SHOW_ADJ
	CMD_SHOW_MBR
	CMD_SHOW_GID
	CMD_POLICIES_SHOW
	CMD_POLICIES_ADD
	CMD_POLICIES_DEL
	CMD_POLICIES_CLEAR
	CMD_POLICIES_TRANSLATE
	CMD_POLICIES_INFO
	CMD_LOGGING
	CMD_LOAD_DPU_CFG
	CMD_CONFIG_SHOW
	CMD_CONFIG_ADD_HA
	CMD_CONFIG_REMOVE_HA
	CMD_CONFIG_ADD_DPU
	CMD_CONFIG_REMOVE_DPU
	CMD_SHOW_TIMESCAPE_CONFIG
	CMD_SHOW_METRICS
	CMD_VRF_SHOW
	CMD_VLAN_SHOW
	CMD_DEVICE_SHOW
	CMD_DPU_SHOW
	CMD_HA_SHOW
	CMD_MOCK_GNMI_SHOW
	CMD_MOCK_GNMI_GET
	CMD_MOCK_GNMI_SET
	CMD_MOCK_GNMI_DELETE
	CMD_HA_CRITERIA_FAIL
	CMD_HA_CRITERIA_OK
	CMD_VRF_LIST
	CMD_VRF_INFO
	CMD_VRF_GIDS
	CMD_VRF_PEERS
	CMD_VLAN_LIST
	CMD_VLAN_INFO
	CMD_DPU_STATUS
	CMD_HA_PEERS
	CMD_HA_CRITERIA_SHOW
	CMD_MOCK_VRF_ADD
	CMD_MOCK_VRF_DELETE
	CMD_MOCK_VLAN_ADD
	CMD_MOCK_VLAN_DELETE
	CMD_MOCK_GNMI_SET_BULK
	CMD_MOCK_GNMI_LOG
	CMD_HA_INFO
	CMD_HA_PEER_FAIL
	CMD_HA_PEER_OK
	CMD_HA_GIDS
	CMD_HA_VLANS
)

const (
	logHead = 500
	logTail = 500
)

func Handler(ctx context.Context, agwAgent *agw.AgentGateway, command map[string]interface{}) (ipc.ReturnCode, error) {
	response := ipc.ReturnCode{}
	cmd, ok := command["command"].(float64)
	if !ok {
		response.ReturnCode = "fail"
		response.Data = "Invalid command format"
		return response, nil
	}
	dataMap, ok := command["data"].(map[string]interface{})
	if !ok {
		response.ReturnCode = "fail"
		response.Data = "Invalid data format"
		return response, nil
	}
	datajson, err := json.Marshal(dataMap)
	if err != nil {
		response.ReturnCode = "fail"
		response.Data = "Invalid data format"
		return response, nil
	}
	var data ipc.MessageData
	err = json.Unmarshal(datajson, &data)
	if err != nil {
		response.ReturnCode = "fail"
		response.Data = "Invalid data format"
		return response, nil
	}

	switch int(cmd) {
	case CMD_LOAD_POLICY:
		response.ReturnCode = "ok"
		response.Data = "Not implemented"

	case CMD_SHOW_POLICY:
		response.ReturnCode = "ok"
		response.Data = "Not implemented"

	case CMD_HEALTH:
		response.ReturnCode = "ok"
		response.Data = "healthy"

	case CMD_SHOW_STATUS:
		status := agwAgent.NxosManager().ShowStatus(ctx)
		response.ReturnCode = "ok"
		response.Data = status

	case CMD_SHOW_DPU:
		dpu := agwAgent.ShowDpu(ctx, data)
		response.ReturnCode = "ok"
		response.Data = dpu

	case CMD_SHOW_VRF:
		vrf := agwAgent.ShowVrf(ctx)
		response.ReturnCode = "ok"
		response.Data = vrf

	case CMD_SHOW_LOG:
		fname := "/data/volatile/logs/agw.log"

		file, err := os.Open(fname)
		if err != nil {
			response.Data = err.Error()
			response.ReturnCode = "ok"
			return response, nil
		}
		defer file.Close()

		total := 0
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			total++
		}
		if err := scanner.Err(); err != nil {
			response.Data = err.Error()
			response.ReturnCode = "ok"
			return response, nil
		}
		head := logHead
		if total < head {
			head = total
		}
		lines := strconv.Itoa(head)
		out, err := exec.Command("head", "-n", lines, fname).Output()
		if err != nil {
			response.Data = err.Error()
			response.ReturnCode = "ok"
			return response, nil
		}
		response.Data = string(out)

		if head == total {
			response.ReturnCode = "ok"
			return response, nil
		}
		response.Data += "----------------------------------------\n"
		tail := total - logHead
		if tail > logTail {
			tail = logTail
		}
		lines = strconv.Itoa(tail)
		out, err = exec.Command("tail", "-n", lines, fname).Output()
		if err != nil {
			response.Data = err.Error()
		} else {
			response.Data += string(out)
		}
		response.ReturnCode = "ok"

	case CMD_DEL_TOKENS:
		rsp := agwAgent.NxosManager().DelTokens(ctx)
		response.ReturnCode = "ok"
		response.Data = rsp

	case CMD_SHOW_TOKENS:
		tokens := agwAgent.ShowTokens(ctx)
		response.ReturnCode = "ok"
		response.Data = tokens

	case CMD_SHOW_TECH:
		pol := agwAgent.PoliciesShow(ctx, ipc.MessageData{})
		status := agwAgent.NxosManager().ShowStatus(ctx)
		dpu := agwAgent.ShowDpu(ctx, ipc.MessageData{})
		vrf := agwAgent.ShowVrf(ctx)
		gid := agwAgent.GnmiShowVrfGids(ctx, ipc.MessageData{})
		ha := agwAgent.NxosManager().ShowHa(ctx)
		mbr := agwAgent.NxosManager().ShowMbr(ctx)
		adj := agwAgent.NxosManager().ShowAdj(ctx)
		syslog, err := agwAgent.ShowSyslog(ctx)
		if err != nil {
			syslog = "Syslog: " + err.Error()
		}
		cfg := agwAgent.ConfigShow(ctx, data)
		vrfStore := agwAgent.GnmiShowVrf(ctx, ipc.MessageData{})
		vlanStore := agwAgent.GnmiShowVlan(ctx, ipc.MessageData{})
		dpuStore := agwAgent.GnmiShowDpu(ctx, ipc.MessageData{})
		haStore := agwAgent.GnmiShowHa(ctx, ipc.MessageData{})
		deviceStore := agwAgent.GnmiShowDevice(ctx, ipc.MessageData{})
		haPeers := agwAgent.GnmiShowHaPeers(ctx, ipc.MessageData{})
		response.ReturnCode = "ok"
		response.Data = "`agwctl show_status`\n" + status + "\n" +
			"`agwctl policies show`\n" + pol + "\n" +
			"`agwctl show_dpu`\n" + dpu + "\n" +
			"`agwctl show_vrf`\n" + vrf + "\n" +
			"`agwctl show_gid`\n" + gid + "\n" +
			"`agwctl show_ha`\n" + ha + "\n" +
			"`agwctl show_mbr`\n" + mbr + "\n" +
			"`agwctl show_adj`\n" + adj + "\n" +
			"`agwctl show_syslog`\n" + syslog + "\n" +
			"`agwctl config show`\n" + cfg + "\n" +
			"`agwctl vrf show`\n" + vrfStore + "\n" +
			"`agwctl vlan show`\n" + vlanStore + "\n" +
			"`agwctl dpu show`\n" + dpuStore + "\n" +
			"`agwctl ha show`\n" + haStore + "\n" +
			"`agwctl device show`\n" + deviceStore + "\n" +
			"`agwctl ha peers`\n" + haPeers + "\n"

	case CMD_TECH_SUPPORT_DPU:
		// Parse includeCores flag from request data
		includeCores := false
		if len(data.Args) > 0 && data.Args[0] == "--with-cores" {
			includeCores = true
		}

		// Use tech support service directly
		service := switchtechsupport.NewService(agwAgent)
		result := service.CollectDpuTechSupport(ctx, includeCores)
		response = result

	case CMD_TAC_PAC:
		logsDir := "/data/volatile/logs"
		tarFile := "/iox_data/logs.tgz"

		// Check if logs directory exists
		if _, err := os.Stat(logsDir); os.IsNotExist(err) {
			response.ReturnCode = "fail"
			response.Data = fmt.Sprintf("Logs directory does not exist: %s", logsDir)
			break
		}

		// Get list of log files before archiving for informational purposes
		var logFiles []string
		if files, err := os.ReadDir(logsDir); err == nil {
			for _, file := range files {
				logFiles = append(logFiles, file.Name())
			}
		}

		out, err := exec.Command("tar", "cfz", tarFile, "-C", "/data/volatile", "logs").Output()
		if err != nil {
			response.ReturnCode = "fail"
			response.Data = fmt.Sprintf("Failed to create TAC package: %v\nOutput: %s", err, string(out))
		} else {
			// Get file info to provide meaningful feedback
			if stat, err := os.Stat(tarFile); err == nil {
				var fileList string
				if len(logFiles) > 0 {
					fileList = fmt.Sprintf("\n Files archived: %v", logFiles)
				}
				response.ReturnCode = "ok"
				response.Data = fmt.Sprintf("TAC package created successfully:\n File: %s\n Size: %d bytes\n Created: %v%s",
					tarFile, stat.Size(), stat.ModTime().Format("2006-01-02 15:04:05"), fileList)
			} else {
				response.ReturnCode = "ok"
				response.Data = fmt.Sprintf("TAC package created at: %s\nWarning: Could not stat file: %v", tarFile, err)
			}
		}

	case CMD_PING_FWA:
		// out := agwAgent.PingFwa(ctx, data)
		response.ReturnCode = "ok"
		response.Data = "Not implemented"

	case CMD_RESTART_FWA:
		var ip string
		if len(data.Args) < 1 {
			response.ReturnCode = "fail"
			response.Data = "Invalid arguments"
			return response, nil
		}
		ip = data.Args[0]

		out, err := exec.Command("/usr/src/app/restart-fwa.sh", "-i", ip, "-p", "pen123", "-u", "root").Output()
		if err != nil {
			response.ReturnCode = "fail"
			response.Data = err.Error() + "\n" + string(out)
		} else {
			response.ReturnCode = "ok"
			response.Data = string(out)
		}

	case CMD_LOAD_DPU_CFG:
		cfg, err := os.ReadFile(data.Flags["file"])
		if err != nil {
			response.ReturnCode = "fail"
			response.Data = err.Error()
			return response, nil
		}
		err = agwAgent.LoadConfigDpu(ctx, string(cfg))
		if err != nil {
			response.ReturnCode = "fail"
			response.Data = err.Error()
			return response, nil
		}
		response.ReturnCode = "ok"
		response.Data = "DPU config loaded"

	case CMD_LOAD_SYSLOG_CFG:
		var file string
		if len(data.Args) < 1 {
			response.ReturnCode = "fail"
			response.Data = "Invalid arguments"
			return response, nil
		}
		file = data.Args[0]

		cfg, err := os.ReadFile(file)
		if err != nil {
			response.ReturnCode = "fail"
			response.Data = err.Error()
			return response, nil
		}

		err = agwAgent.LoadSyslog(ctx, string(cfg))
		if err != nil {
			response.ReturnCode = "fail"
			response.Data = err.Error()
			return response, nil
		}
		response.ReturnCode = "ok"
		response.Data = "Syslog loaded"

	case CMD_SHOW_SYSLOG_CFG:
		out, err := agwAgent.ShowSyslog(ctx)
		if err != nil {
			response.ReturnCode = "fail"
			response.Data = err.Error()
		} else {
			response.ReturnCode = "ok"
			response.Data = out
		}

	case CMD_SHOW_HA:
		ha := agwAgent.NxosManager().ShowHa(ctx)
		response.ReturnCode = "ok"
		response.Data = ha

	case CMD_SHOW_ADJ:
		adj := agwAgent.NxosManager().ShowAdj(ctx)
		response.ReturnCode = "ok"
		response.Data = adj

	case CMD_SHOW_MBR:
		mbr := agwAgent.NxosManager().ShowMbr(ctx)
		response.ReturnCode = "ok"
		response.Data = mbr

	case CMD_SHOW_GID:
		res := agwAgent.GnmiShowVrfGids(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_POLICIES_ADD:
		res := agwAgent.PoliciesAdd(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res
		response.ReturnCode = "ok"

	case CMD_POLICIES_DEL:
		res := agwAgent.PoliciesRemove(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_POLICIES_SHOW:
		pols := agwAgent.PoliciesShow(ctx, data)
		response.ReturnCode = "ok"
		response.Data = pols

	case CMD_POLICIES_CLEAR:
		err := agwAgent.PoliciesClear(ctx)
		if err != nil {
			response.ReturnCode = "fail"
			response.Data = err.Error()
			return response, nil
		}
		response.ReturnCode = "ok"
		response.Data = "Policies cleared"

	case CMD_POLICIES_TRANSLATE:
		str, err := agwAgent.PoliciesTranslate(ctx, data)
		if err != nil {
			response.ReturnCode = "fail"
			response.Data = err.Error()
			return response, nil
		}
		response.ReturnCode = "ok"
		response.Data = str

	case CMD_POLICIES_INFO:
		info := agwAgent.PoliciesInfo(ctx, data)
		response.ReturnCode = "ok"
		response.Data = info

	case CMD_LOGGING:
		err := agwAgent.Logging(ctx, data)
		if err != nil {
			response.ReturnCode = "fail"
			response.Data = err.Error()
			return response, nil
		}
		response.ReturnCode = "ok"
		response.Data = "Logging updated"

	case CMD_CONFIG_SHOW:
		cfg := agwAgent.ConfigShow(ctx, data)
		response.ReturnCode = "ok"
		response.Data = cfg

	case CMD_CONFIG_ADD_HA:
		res := agwAgent.ConfigAddHa(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_CONFIG_REMOVE_HA:
		res := agwAgent.ConfigRemoveHa(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_CONFIG_ADD_DPU:
		res := agwAgent.ConfigAddDpu(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_CONFIG_REMOVE_DPU:
		res := agwAgent.ConfigRemoveDpu(ctx)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_SHOW_TIMESCAPE_CONFIG:
		displayConfig := switchevents.GetConfigForDisplay()

		// Marshal the displayConfig to JSON
		jsonData, err := json.Marshal(displayConfig)
		if err != nil {
			response.ReturnCode = "fail"
			response.Data = err.Error()
		} else {
			response.ReturnCode = "ok"
			response.Data = string(jsonData)
		}

	case CMD_SHOW_METRICS:
		mc := switchmetrics.GetInstance(ctx)
		if mc == nil {
			response.ReturnCode = "fail"
			response.Data = "Metrics collector not running"
			return response, nil
		}
		metrics := mc.GetCurrentMetrics()
		// Marshal the metrics to JSON
		jsonData, err := json.Marshal(metrics)
		if err != nil {
			response.ReturnCode = "fail"
			response.Data = err.Error()
		} else {
			response.ReturnCode = "ok"
			response.Data = string(jsonData)
		}

	case CMD_VRF_SHOW:
		res := agwAgent.GnmiShowVrf(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_VLAN_SHOW:
		res := agwAgent.GnmiShowVlan(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_DPU_SHOW:
		res := agwAgent.GnmiShowDpu(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_HA_INFO:
		res := agwAgent.GnmiShowHaInfo(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_HA_SHOW:
		res := agwAgent.GnmiShowHa(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_DEVICE_SHOW:
		res := agwAgent.GnmiShowDevice(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_MOCK_GNMI_SHOW:
		res := agwAgent.MockGnmiShow(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_MOCK_GNMI_GET:
		res := agwAgent.MockGnmiGet(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_MOCK_GNMI_SET:
		res := agwAgent.MockGnmiSet(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_MOCK_GNMI_DELETE:
		res := agwAgent.MockGnmiDelete(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_MOCK_GNMI_SET_BULK:
		res := agwAgent.MockGnmiSetBulk(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_HA_CRITERIA_FAIL:
		res := agwAgent.HaCriteriaFail(ctx)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_HA_CRITERIA_OK:
		res := agwAgent.HaCriteriaOk(ctx)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_VRF_LIST:
		res := agwAgent.GnmiShowVrfList(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_VRF_INFO:
		res := agwAgent.GnmiShowVrfInfo(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_VRF_GIDS:
		res := agwAgent.GnmiShowVrfGids(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_VLAN_LIST:
		res := agwAgent.GnmiShowVlanList(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_VLAN_INFO:
		res := agwAgent.GnmiShowVlanInfo(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_DPU_STATUS:
		res := agwAgent.GnmiShowDpuStatus(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_HA_PEERS:
		res := agwAgent.GnmiShowHaPeers(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_HA_CRITERIA_SHOW:
		res := agwAgent.GnmiShowHaCriteria(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_MOCK_VRF_ADD:
		res := agwAgent.MockVrfAdd(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_MOCK_GNMI_LOG:
		res := agwAgent.MockGnmiLog(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_MOCK_VRF_DELETE:
		res := agwAgent.MockVrfDelete(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_MOCK_VLAN_ADD:
		res := agwAgent.MockVlanAdd(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_MOCK_VLAN_DELETE:
		res := agwAgent.MockVlanDelete(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_HA_PEER_FAIL:
		peer := data.Flags["peer"]
		if peer == "" {
			response.ReturnCode = "fail"
			response.Data = "--peer is required"
			return response, nil
		}
		membership := data.Flags["membership"] == "true"
		adjacency := data.Flags["adjacency"] == "true"
		res := agwAgent.HaSetDebugPeerFail(ctx, peer, membership, adjacency)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_HA_PEER_OK:
		peer := data.Flags["peer"]
		if peer == "" {
			response.ReturnCode = "fail"
			response.Data = "--peer is required"
			return response, nil
		}
		membership := data.Flags["membership"] == "true"
		adjacency := data.Flags["adjacency"] == "true"
		res := agwAgent.HaSetDebugPeerOk(ctx, peer, membership, adjacency)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_HA_GIDS:
		res := agwAgent.GnmiShowHaGids(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	case CMD_HA_VLANS:
		res := agwAgent.GnmiShowHaVlans(ctx, data)
		response.ReturnCode = "ok"
		response.Data = res

	default:
		response.ReturnCode = "fail"
		response.Data = "Unknown command"
	}
	return response, nil
}
