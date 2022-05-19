// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package encoder

import (
	"fmt"
	"io"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/dustin/go-humanize"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
)

// EventEncoder is an interface for encoding fgs.GetEventsResponse.
type EventEncoder interface {
	Encode(v interface{}) error
}

// ColorMode defines color mode flags for compact output.
type ColorMode string

const (
	Always ColorMode = "always" // always enable colored output.
	Never  ColorMode = "never"  // disable colored output.
	Auto   ColorMode = "auto"   // automatically enable / disable colored output based on terminal settings.
)

// CompactEncoder encodes fgs.GetEventsResponse in a short format with emojis and colors.
type CompactEncoder struct {
	writer  io.Writer
	colorer *colorer
}

// NewCompactEncoder initializes and returns a pointer to CompactEncoder.
func NewCompactEncoder(w io.Writer, colorMode ColorMode) *CompactEncoder {
	return &CompactEncoder{
		writer:  w,
		colorer: newColorer(colorMode),
	}
}

// Encode implements EventEncoder.Encode.
func (p *CompactEncoder) Encode(v interface{}) error {
	event, ok := v.(*fgs.GetEventsResponse)
	if !ok {
		return fmt.Errorf("invalid event")
	}
	logger.GetLogger().WithField("event", v).Debug("Processing event")
	str, err := p.eventToString(event)
	if err != nil {
		return err
	}
	fmt.Fprintln(p.writer, str)
	return nil
}

const (
	capsPad = 120
)

func capTrailorPrinter(str string, caps string) string {
	if len(caps) == 0 {
		return fmt.Sprintf("%s", str)
	}
	padding := 0
	if len(str) < capsPad {
		padding = capsPad - len(str)
	}
	return fmt.Sprintf("%s %*s", str, padding, caps)
}

var (
	CLONE_NEWCGROUP = 0x2000000
	CLONE_NEWIPC    = 0x8000000
	CLONE_NEWNET    = 0x40000000
	CLONE_NEWNS     = 0x20000
	CLONE_NEWPID    = 0x20000000
	CLONE_NEWTIME   = 0x80
	CLONE_NEWUSER   = 0x10000000
	CLONE_NEWUTS    = 0x4000000
)

var nsId = map[int32]string{
	int32(0):               "any",
	int32(CLONE_NEWCGROUP): "cgroup",
	int32(CLONE_NEWIPC):    "ipc",
	int32(CLONE_NEWNET):    "net",
	int32(CLONE_NEWNS):     "mnt",
	int32(CLONE_NEWPID):    "pid",
	int32(CLONE_NEWTIME):   "time",
	int32(CLONE_NEWUSER):   "user",
	int32(CLONE_NEWUTS):    "uts",
}

func printNS(ns int32) string {
	return nsId[ns]
}

func (p *CompactEncoder) eventToString(response *fgs.GetEventsResponse) (string, error) {
	switch response.Event.(type) {
	case *fgs.GetEventsResponse_ProcessExec:
		exec := response.GetProcessExec()
		if exec.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		event := p.colorer.blue.Sprintf("🚀 %-7s", "process")
		processInfo, caps := p.colorer.processInfo(response.NodeName, exec.Process)
		args := p.colorer.cyan.Sprint(exec.Process.Arguments)
		return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, args), caps), nil
	case *fgs.GetEventsResponse_ProcessConnect:
		connect := response.GetProcessConnect()
		if connect.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		event := p.colorer.blue.Sprintf("🔌 %-7s", "connect")
		processInfo, caps := p.colorer.processInfo(response.NodeName, connect.Process)
		destination := p.colorer.fiveTuple(
			connect.Protocol,
			connect.SourceIp,
			connect.SourcePort,
			connect.DestinationIp,
			connect.DestinationPort,
			connect.DestinationNames)
		return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, destination), caps), nil
	case *fgs.GetEventsResponse_ProcessListen:
		listen := response.GetProcessListen()
		if listen.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		event := p.colorer.blue.Sprintf("🎧 %-7s", "listen")
		processInfo, caps := p.colorer.processInfo(response.NodeName, listen.Process)
		hostPort := p.colorer.hostPort(listen.Protocol, listen.Ip, listen.Port)
		return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, hostPort), caps), nil
	case *fgs.GetEventsResponse_ProcessAccept:
		accept := response.GetProcessAccept()
		if accept.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		event := p.colorer.blue.Sprintf("💡 %-7s", "accept")
		processInfo, caps := p.colorer.processInfo(response.NodeName, accept.Process)
		fiveTuple := p.colorer.fiveTuple(
			accept.Protocol,
			accept.DestinationIp,
			accept.DestinationPort,
			accept.SourceIp,
			accept.SourcePort,
			accept.DestinationNames)
		return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, fiveTuple), caps), nil
	case *fgs.GetEventsResponse_ProcessHttp:
		http := response.GetProcessHttp()
		if http.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		if http.Http == nil {
			return "", fmt.Errorf("http field is not set")
		}
		event := p.colorer.blue.Sprintf("🌐 %-7s", "http")
		processInfo, caps := p.colorer.processInfo(response.NodeName, http.Process)
		httpInfo := p.colorer.http(http.Http)
		return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, httpInfo), caps), nil
	case *fgs.GetEventsResponse_Tls:
		tls := response.GetTls()
		if tls.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		event := p.colorer.blue.Sprintf("🔐 %-7s", "tls")
		processInfo, caps := p.colorer.processInfo(response.NodeName, tls.Process)
		tlsInfo := p.colorer.tls(tls)
		return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, tlsInfo), caps), nil
	case *fgs.GetEventsResponse_ProcessClose:
		processClose := response.GetProcessClose()
		if processClose.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		event := p.colorer.blue.Sprintf("\U0001F9F9 %-7s", "close")
		processInfo, caps := p.colorer.processInfo(response.NodeName, processClose.Process)
		closeInfo := p.colorer.close(processClose)
		return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, closeInfo), caps), nil
	case *fgs.GetEventsResponse_ProcessExit:
		exit := response.GetProcessExit()
		if exit.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		event := p.colorer.blue.Sprintf("💥 %-7s", "exit")
		processInfo, caps := p.colorer.processInfo(response.NodeName, exit.Process)
		args := p.colorer.cyan.Sprint(exit.Process.Arguments)
		var status string
		if exit.Signal != "" {
			status = p.colorer.red.Sprint(exit.Signal)
		} else {
			status = p.colorer.red.Sprint(exit.Status)
		}
		return capTrailorPrinter(fmt.Sprintf("%s %s %s %s", event, processInfo, args, status), caps), nil
	case *fgs.GetEventsResponse_ProcessKprobe:
		kprobe := response.GetProcessKprobe()
		if kprobe.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		processInfo, caps := p.colorer.processInfo(response.NodeName, kprobe.Process)
		switch kprobe.FunctionName {
		case "__x64_sys_write":
			event := p.colorer.blue.Sprintf("📝 %-7s", "write")
			file := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil && kprobe.Args[0].GetFileArg() != nil {
				file = p.colorer.cyan.Sprint(kprobe.Args[0].GetFileArg().Path)
			}
			bytes := ""
			if len(kprobe.Args) > 2 && kprobe.Args[2] != nil {
				bytes = p.colorer.cyan.Sprint(kprobe.Args[2].GetSizeArg(), " bytes")
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s %v", event, processInfo, file, bytes), caps), nil
		case "__x64_sys_read":
			event := p.colorer.blue.Sprintf("📚 %-7s", "read")
			file := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil && kprobe.Args[0].GetFileArg() != nil {
				file = p.colorer.cyan.Sprint(kprobe.Args[0].GetFileArg().Path)
			}
			bytes := ""
			if len(kprobe.Args) > 2 && kprobe.Args[2] != nil {
				bytes = p.colorer.cyan.Sprint(kprobe.Args[2].GetSizeArg(), " bytes")
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s %v", event, processInfo, file, bytes), caps), nil
		case "fd_install":
			event := p.colorer.blue.Sprintf("📬 %-7s", "open")
			file := ""
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil && kprobe.Args[1].GetFileArg() != nil {
				file = p.colorer.cyan.Sprint(kprobe.Args[1].GetFileArg().Path)
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, file), caps), nil
		case "__x64_sys_close":
			event := p.colorer.blue.Sprintf("📪 %-7s", "close")
			file := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil && kprobe.Args[0].GetFileArg() != nil {
				file = p.colorer.cyan.Sprint(kprobe.Args[0].GetFileArg().Path)
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, file), caps), nil
		case "__x64_sys_mount":
			event := p.colorer.blue.Sprintf("💾 %-7s", "mount")
			src := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				src = p.colorer.cyan.Sprint(kprobe.Args[0].GetStringArg())
			}
			dst := ""
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil {
				dst = p.colorer.cyan.Sprint(kprobe.Args[1].GetStringArg())
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s %s", event, processInfo, src, dst), caps), nil
		case "__x64_sys_setuid":
			event := p.colorer.blue.Sprintf("🔑 %-7s", "setuid")
			uid := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				uidInt := p.colorer.cyan.Sprint(kprobe.Args[0].GetIntArg())
				uid = string(uidInt)
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, uid), caps), nil
		case "__x64_sys_clock_settime":
			event := p.colorer.blue.Sprintf("⏰ %-7s", "clock_settime")
			return capTrailorPrinter(fmt.Sprintf("%s %s", event, processInfo), caps), nil
		case "__x64_sys_pivot_root":
			event := p.colorer.blue.Sprintf("💾 %-7s", "pivot_root")
			src := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				src = p.colorer.cyan.Sprint(kprobe.Args[0].GetStringArg())
			}
			dst := ""
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil {
				dst = p.colorer.cyan.Sprint(kprobe.Args[1].GetStringArg())
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s %s", event, processInfo, src, dst), caps), nil
		case "proc_exec_connector":
			event := p.colorer.blue.Sprintf("🔧 %-7s", "proc_exec_connector")
			return capTrailorPrinter(fmt.Sprintf("%s %s", event, processInfo), caps), nil
		case "__x64_sys_setns":
			netns := ""
			event := p.colorer.blue.Sprintf("🔧 %-7s", "setns")
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil {
				netns = printNS(kprobe.Args[1].GetIntArg())
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, netns), caps), nil
		case "tcp_connect":
			event := p.colorer.blue.Sprintf("🔧 %-7s", "tcp_connect")
			sock := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				sa := kprobe.Args[0].GetSockArg()
				sock = p.colorer.cyan.Sprintf("%s:%d -> %s:%d", sa.Saddr, sa.Sport, sa.Daddr, sa.Dport)
			}
			return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, sock), caps), nil
		default:
			event := p.colorer.blue.Sprintf("⁉️ %-7s", "syscall")
			return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, kprobe.FunctionName), caps), nil
		}
	case *fgs.GetEventsResponse_ProcessDns:
		dns := response.GetProcessDns()
		if dns.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		if dns.Dns == nil {
			return "", fmt.Errorf("dns field is not set")
		}
		event := p.colorer.blue.Sprintf("📖 %-7s", "dns")
		processInfo, caps := p.colorer.processInfo(response.NodeName, dns.Process)
		args := p.colorer.cyan.Sprint(dns.GetDns().Names, " => ", dns.GetDns().Ips)
		return capTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, args), caps), nil
	case *fgs.GetEventsResponse_ProcessSockStats:
		stats := response.GetProcessSockStats()
		if stats.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		if stats.Socket == nil {
			return "", fmt.Errorf("socket field is not set")
		}
		if stats.Stats == nil {
			return "", fmt.Errorf("stats field is not set")
		}
		event := p.colorer.blue.Sprintf("🧮 %-7s", "socket")
		processInfo, _ := p.colorer.processInfo(response.NodeName, stats.Process)
		destination := p.colorer.fiveTuple(
			stats.Socket.Protocol,
			stats.Socket.SourceIp,
			stats.Socket.SourcePort,
			stats.Socket.DestinationIp,
			stats.Socket.DestinationPort,
			stats.Socket.DestinationNames)
		txBytes := humanize.Bytes(stats.Stats.BytesSent)
		rxBytes := humanize.Bytes(stats.Stats.BytesReceived)
		return fmt.Sprintf("%s %s %s tx %s rx %s", event, processInfo, destination, txBytes, rxBytes), nil
	case *fgs.GetEventsResponse_InterfaceStats:
		stats := response.GetInterfaceStats()
		interfaceInfo := p.colorer.interfaceInfo(response.NodeName, stats)
		txBytes := humanize.Bytes(stats.BytesSent)
		rxBytes := humanize.Bytes(stats.BytesReceived)
		event := p.colorer.blue.Sprintf("📒 %-7s", "netstat")
		return fmt.Sprintf("%s %s tx %s rx %s", event, interfaceInfo, txBytes, rxBytes), nil
	}
	return "", fmt.Errorf("unknown event type")
}
