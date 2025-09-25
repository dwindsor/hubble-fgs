package agwctl

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strconv"

	"github.com/isovalent/hubble-fgs/pkg/fwa"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
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
	CMD_PING_FWA
	CMD_RESTART_FWA
	CMD_LOAD_SYSLOG_CFG
	CMD_SHOW_SYSLOG_CFG
	CMD_SHOW_HA
	CMD_SHOW_ADJ
	CMD_SHOW_MBR
	CMD_SHOW_GID
)

const (
	logHead = 500
	logTail = 500
)

func Handler(ctx context.Context, fwaAgent *fwa.FWAgent, command map[string]interface{}) (ipc.ReturnCode, error) {
	response := ipc.ReturnCode{}
	cmd, ok := command["command"].(float64)
	if !ok {
		response.ReturnCode = "fail"
		response.Data = "Invalid command format"
		return response, nil
	}
	data, ok := command["data"].(string)
	if !ok {
		response.ReturnCode = "fail"
		response.Data = "Invalid data format"
		return response, nil
	}

	switch int(cmd) {
	case CMD_LOAD_POLICY:
		pols, err := os.ReadFile(data)
		if err != nil {
			response.ReturnCode = "fail"
			response.Data = err.Error()
			return response, nil
		}

		data := fwaAgent.LoadPolicies(ctx, string(pols))
		response.ReturnCode = "ok"
		response.Data = data

	case CMD_SHOW_POLICY:
		// HACK: add back data once ready
		pol := fwaAgent.ShowPolicies(ctx /*, data*/)
		response.ReturnCode = "ok"
		response.Data = pol

	case CMD_HEALTH:
		response.ReturnCode = "ok"
		response.Data = "healthy"

	case CMD_SHOW_STATUS:
		status := nxos.Nexus.ShowStatus(ctx)
		response.ReturnCode = "ok"
		response.Data = status

	case CMD_SHOW_DPU:
		dpu := fwaAgent.ShowDpu(ctx)
		response.ReturnCode = "ok"
		response.Data = dpu

	case CMD_SHOW_VRF:
		vrf := nxos.Nexus.ShowVrf(ctx)
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
		tokens := fwaAgent.ShowTokens(ctx)
		response.ReturnCode = "ok"
		response.Data = tokens

	case CMD_SHOW_TECH:
		pol := fwaAgent.ShowPolicies(ctx)
		status := nxos.Nexus.ShowStatus(ctx)
		dpu := fwaAgent.ShowDpu(ctx)
		vrf := nxos.Nexus.ShowVrf(ctx)
		response.ReturnCode = "ok"
		response.Data = status + "\n" + pol + "\n" +
			dpu + "\n" + vrf

	case CMD_TAC_PAC:
		out, err := exec.Command("tar", "cfz", "/iox_data/logs.tgz", "-C", "/data/volatile", "logs").Output()
		if err != nil {
			response.ReturnCode = "fail"
			response.Data = err.Error()
		} else {
			response.ReturnCode = "ok"
			response.Data = string(out)
		}

	case CMD_PING_FWA:
		out := fwaAgent.PingFwa(ctx, data)
		response.ReturnCode = "ok"
		response.Data = out

	case CMD_RESTART_FWA:
		out, err := exec.Command("/usr/src/app/restart-fwa.sh", "-i", data, "-p", "pen123", "-u", "root").Output()
		if err != nil {
			response.ReturnCode = "fail"
			response.Data = err.Error() + "\n" + string(out)
		} else {
			response.ReturnCode = "ok"
			response.Data = string(out)
		}

	case CMD_LOAD_SYSLOG_CFG:
		cfg, err := os.ReadFile(data)
		if err != nil {
			response.ReturnCode = "fail"
			response.Data = err.Error()
			return response, nil
		}

		err = fwaAgent.LoadSyslog(ctx, string(cfg))
		if err != nil {
			response.ReturnCode = "fail"
			response.Data = err.Error()
			return response, nil
		}
		response.ReturnCode = "ok"
		response.Data = "Syslog loaded"

	case CMD_SHOW_SYSLOG_CFG:
		out, err := fwaAgent.ShowSyslog(ctx)
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
		mbr := nxos.Nexus.ShowGid(ctx)
		response.ReturnCode = "ok"
		response.Data = mbr

	default:
		response.ReturnCode = "fail"
		response.Data = "Unknown command"
	}
	return response, nil
}
