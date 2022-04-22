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

	"github.com/dustin/go-humanize"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/logger"
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

func (p *CompactEncoder) eventToString(response *fgs.GetEventsResponse) (string, error) {
	switch response.Event.(type) {
	case *fgs.GetEventsResponse_ProcessExec:
		exec := response.GetProcessExec()
		if exec.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		event := p.colorer.blue.Sprintf("🚀 %-7s", "process")
		processInfo := p.colorer.processInfo(response.NodeName, exec.Process)
		args := p.colorer.cyan.Sprint(exec.Process.Arguments)
		return fmt.Sprintf("%s %s %s", event, processInfo, args), nil
	case *fgs.GetEventsResponse_ProcessConnect:
		connect := response.GetProcessConnect()
		if connect.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		event := p.colorer.blue.Sprintf("🔌 %-7s", "connect")
		processInfo := p.colorer.processInfo(response.NodeName, connect.Process)
		destination := p.colorer.fiveTuple(
			connect.Protocol,
			connect.SourceIp,
			connect.SourcePort,
			connect.DestinationIp,
			connect.DestinationPort,
			connect.DestinationNames)
		return fmt.Sprintf("%s %s %s", event, processInfo, destination), nil
	case *fgs.GetEventsResponse_ProcessListen:
		listen := response.GetProcessListen()
		if listen.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		event := p.colorer.blue.Sprintf("🎧 %-7s", "listen")
		processInfo := p.colorer.processInfo(response.NodeName, listen.Process)
		hostPort := p.colorer.hostPort(listen.Protocol, listen.Ip, listen.Port)
		return fmt.Sprintf("%s %s %s", event, processInfo, hostPort), nil
	case *fgs.GetEventsResponse_ProcessAccept:
		accept := response.GetProcessAccept()
		if accept.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		event := p.colorer.blue.Sprintf("💡 %-7s", "accept")
		processInfo := p.colorer.processInfo(response.NodeName, accept.Process)
		fiveTuple := p.colorer.fiveTuple(
			accept.Protocol,
			accept.DestinationIp,
			accept.DestinationPort,
			accept.SourceIp,
			accept.SourcePort,
			accept.DestinationNames)
		return fmt.Sprintf("%s %s %s", event, processInfo, fiveTuple), nil
	case *fgs.GetEventsResponse_ProcessHttp:
		http := response.GetProcessHttp()
		if http.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		if http.Http == nil {
			return "", fmt.Errorf("http field is not set")
		}
		event := p.colorer.blue.Sprintf("🌐 %-7s", "http")
		processInfo := p.colorer.processInfo(response.NodeName, http.Process)
		httpInfo := p.colorer.http(http.Http)
		return fmt.Sprintf("%s %s %s", event, processInfo, httpInfo), nil
	case *fgs.GetEventsResponse_Tls:
		tls := response.GetTls()
		if tls.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		event := p.colorer.blue.Sprintf("🔐 %-7s", "tls")
		processInfo := p.colorer.processInfo(response.NodeName, tls.Process)
		tlsInfo := p.colorer.tls(tls)
		return fmt.Sprintf("%s %s %s", event, processInfo, tlsInfo), nil
	case *fgs.GetEventsResponse_ProcessClose:
		processClose := response.GetProcessClose()
		if processClose.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		event := p.colorer.blue.Sprintf("\U0001F9F9 %-7s", "close")
		processInfo := p.colorer.processInfo(response.NodeName, processClose.Process)
		closeInfo := p.colorer.close(processClose)
		return fmt.Sprintf("%s %s %s", event, processInfo, closeInfo), nil
	case *fgs.GetEventsResponse_ProcessExit:
		exit := response.GetProcessExit()
		if exit.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		event := p.colorer.blue.Sprintf("💥 %-7s", "exit")
		processInfo := p.colorer.processInfo(response.NodeName, exit.Process)
		args := p.colorer.cyan.Sprint(exit.Process.Arguments)
		var status string
		if exit.Signal != "" {
			status = p.colorer.red.Sprint(exit.Signal)
		} else {
			status = p.colorer.red.Sprint(exit.Status)
		}
		return fmt.Sprintf("%s %s %s %s", event, processInfo, args, status), nil
	case *fgs.GetEventsResponse_ProcessKprobe:
		kprobe := response.GetProcessKprobe()
		if kprobe.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		processInfo := p.colorer.processInfo(response.NodeName, kprobe.Process)
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
			return fmt.Sprintf("%s %s %s %v", event, processInfo, file, bytes), nil
		case "fd_install":
			event := p.colorer.blue.Sprintf("📬 %-7s", "open")
			file := ""
			if len(kprobe.Args) > 1 && kprobe.Args[1] != nil && kprobe.Args[1].GetFileArg() != nil {
				file = p.colorer.cyan.Sprint(kprobe.Args[1].GetFileArg().Path)
			}
			return fmt.Sprintf("%s %s %s", event, processInfo, file), nil
		case "__x64_sys_close":
			event := p.colorer.blue.Sprintf("📪 %-7s", "close")
			file := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil && kprobe.Args[0].GetFileArg() != nil {
				file = p.colorer.cyan.Sprint(kprobe.Args[0].GetFileArg().Path)
			}
			return fmt.Sprintf("%s %s %s", event, processInfo, file), nil
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
			return fmt.Sprintf("%s %s %s %s", event, processInfo, src, dst), nil
		case "__x64_sys_setuid":
			event := p.colorer.blue.Sprintf("🔑 %-7s", "setuid")
			uid := ""
			if len(kprobe.Args) > 0 && kprobe.Args[0] != nil {
				uidInt := p.colorer.cyan.Sprint(kprobe.Args[0].GetIntArg())
				uid = string(uidInt)
			}
			return fmt.Sprintf("%s %s %s", event, processInfo, uid), nil
		default:
			event := p.colorer.blue.Sprintf("⁉️ %-7s", "syscall")
			return fmt.Sprintf("%s %s %s", event, processInfo, kprobe.FunctionName), nil
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
		processInfo := p.colorer.processInfo(response.NodeName, dns.Process)
		args := p.colorer.cyan.Sprint(dns.GetDns().Names, " => ", dns.GetDns().Ips)
		return fmt.Sprintf("%s %s %s", event, processInfo, args), nil
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
		processInfo := p.colorer.processInfo(response.NodeName, stats.Process)
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
