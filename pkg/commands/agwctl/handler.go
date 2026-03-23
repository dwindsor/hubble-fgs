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
	"github.com/isovalent/hubble-fgs/pkg/nxos"
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
	CMD_HA_SHOW
	CMD_HA_FAIL
	CMD_HA_OK
	CMD_HA_PEER_FAIL
	CMD_HA_PEER_OK
	CMD_SHOW_METRICS
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
		status := nxos.Nexus.ShowStatus(ctx)
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
		rsp := nxos.Nexus.DelTokens(ctx)
		response.ReturnCode = "ok"
		response.Data = rsp

	case CMD_SHOW_TOKENS:
		tokens := agwAgent.ShowTokens(ctx)
		response.ReturnCode = "ok"
		response.Data = tokens

	case CMD_SHOW_TECH:
		pol := agwAgent.PoliciesShow(ctx, ipc.MessageData{})
		status := nxos.Nexus.ShowStatus(ctx)
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
			"`agwctl config show`\n" + cfg + "\n"

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
		ha := nxos.Nexus.ShowHa(ctx)
		response.ReturnCode = "ok"
		response.Data = ha

	case CMD_SHOW_ADJ:
		adj := nxos.Nexus.ShowAdj(ctx)
		response.ReturnCode = "ok"
		response.Data = adj

	case CMD_SHOW_MBR:
		mbr := nxos.Nexus.ShowMbr(ctx)
		response.ReturnCode = "ok"
		response.Data = mbr

	case CMD_SHOW_GID:
		res := agwAgent.GnmiShowVrfGids(ctx, data)
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

	case CMD_HA_SHOW:
		ha := nxos.Nexus.ShowHa(ctx)
		response.ReturnCode = "ok"
		response.Data = ha

	case CMD_HA_FAIL:
		nxos.Nexus.HaSetDebugFail(ctx, true)
		response.ReturnCode = "ok"
		response.Data = "Debug failure injected - HA state will fail"

	case CMD_HA_OK:
		nxos.Nexus.HaSetDebugFail(ctx, false)
		response.ReturnCode = "ok"
		response.Data = "Debug failure cleared - normal operation restored"

	case CMD_HA_PEER_FAIL:
		peer := data.Flags["peer"]
		if peer == "" {
			response.ReturnCode = "fail"
			response.Data = "--peer is required"
			return response, nil
		}
		membership := data.Flags["membership"] == "true"
		adjacency := data.Flags["adjacency"] == "true"
		nxos.Nexus.HaSetDebugPeerFail(ctx, peer, membership, adjacency)
		response.ReturnCode = "ok"
		response.Data = fmt.Sprintf("Debug peer failure injected for %s", peer)

	case CMD_HA_PEER_OK:
		peer := data.Flags["peer"]
		if peer == "" {
			response.ReturnCode = "fail"
			response.Data = "--peer is required"
			return response, nil
		}
		nxos.Nexus.HaSetDebugPeerOk(ctx, peer)
		response.ReturnCode = "ok"
		response.Data = fmt.Sprintf("Debug peer failure cleared for %s", peer)

	default:
		response.ReturnCode = "fail"
		response.Data = "Unknown command"
	}
	return response, nil
}
