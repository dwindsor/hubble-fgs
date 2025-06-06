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
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/encoder"
	"github.com/dustin/go-humanize"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/miekg/dns"
)

const rfc3339Nano = "2006-01-02T15:04:05.000000000Z07:00"

var (
	ErrInvalidEvent       = encoder.ErrInvalidEvent
	ErrMissingProcessInfo = encoder.ErrMissingProcessInfo
	ErrUnknownEventType   = encoder.ErrUnknownEventType
	ErrMissingSocketInfo  = errors.New("socket field is not set")
	ErrMissingDNSInfo     = errors.New("dns field is not set")
	ErrMissingStatsInfo   = errors.New("stats field is not set")
	ErrMissingHTTPInfo    = errors.New("http field is not set")
)

// CompactEncoder encodes tetragon.GetEventsResponse in a short format with emojis and colors.
type EnterpriseEncoder struct {
	inner   *encoder.CompactEncoder
	colorer colorer
}

// NewEnterpriseEncoder initializes and returns a pointer to CompactEncoder.
func NewEnterpriseEncoder(w io.Writer, colorMode encoder.ColorMode, timestamps bool) *EnterpriseEncoder {
	return &EnterpriseEncoder{
		inner:   encoder.NewCompactEncoder(w, colorMode, timestamps, false, false),
		colorer: *newColorer(colorMode),
	}
}

// Encode implements EventEncoder.Encode.
func (p *EnterpriseEncoder) EncodePrefix(prefix string, v interface{}) error {
	event, ok := v.(*tetragon.GetEventsResponse)
	if !ok {
		return encoder.ErrInvalidEvent
	}

	str, err := p.eventToString(event)
	if err != nil {
		return err
	}

	if p.inner.Timestamps {
		ts := event.Time.AsTime().UTC().Format(rfc3339Nano)
		str = fmt.Sprintf("%s%s %s", prefix, ts, str)
	}
	fmt.Fprintln(p.inner.Writer, str)
	return nil
}

func (p *EnterpriseEncoder) Encode(v interface{}) error {
	return p.EncodePrefix("", v)
}

func (p *EnterpriseEncoder) AppModelEventToString(event *appModelV1.NetworkConnectTelemetry) (string, error) {
	switch event.EventType {
	case appModelV1.TelemetryType_TELEMETRY_TYPE_NETWORK_CONNECT:
		connect := p.colorer.Blue.Sprintf("🔌 %-7s", "connect")
		processInfo := p.colorer.flatProcessInfo(event.NodeName, event.ProcessName, event.KubernetesNamespace, event.KubernetesWorkloadName)
		destination := p.colorer.simpleTuple(
			event.DestinationName,
			event.DestinationPort)
		stats := ""
		if event.PolicyName != "" {
			stats = p.colorer.Cyan.Sprintf("tx %d rx %d policy %s -> %s", event.TxBytes, event.RxBytes, event.PolicyName, appModelV1.PolicyVerdict_name[int32(event.Verdict)])
		} else {
			stats = p.colorer.Cyan.Sprintf("tx %d rx %d", event.TxBytes, event.RxBytes)
		}
		return fmt.Sprintf("%s %s %s (%s)", connect, processInfo, destination, stats), nil

	}
	return "", fmt.Errorf("%w: %s", ErrUnknownEventType, event.EventType.String())
}

func (p *EnterpriseEncoder) eventToString(response *tetragon.GetEventsResponse) (string, error) {
	if s, err := p.inner.EventToString(response); err == nil {
		return s, nil
	}

	switch response.Event.(type) {

	case *tetragon.GetEventsResponse_ProcessIcmp:
		icmp := response.GetProcessIcmp()
		if icmp.Process == nil {
			return "", ErrMissingProcessInfo
		}
		event := p.colorer.Blue.Sprintf("📶 %-7s", "icmp")
		processInfo, caps := p.colorer.ProcessInfo(response.NodeName, icmp.Process)
		destination := p.colorer.Cyan.Sprint(icmp.Protocol, " ", icmp.SourceIp, "=>", icmp.DestinationIp)
		dns := ""
		if len(icmp.DestinationNames) > 0 {
			dns = strings.Join(icmp.DestinationNames, ",")
		}
		info := p.colorer.Cyan.Sprint(icmp.IcmpType, " (", icmp.IcmpTypeValue, ")")
		return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s %s %s", event, processInfo, destination, info, dns), caps), nil

	case *tetragon.GetEventsResponse_ProcessIpError:
		processInfo := ""
		caps := ""

		ipError := response.GetProcessIpError()
		if ipError.Process != nil {
			processInfo, caps = p.colorer.ProcessInfo(response.NodeName, ipError.Process)
		} else {
			processInfo = "(unknown process)"
			caps = ""
		}
		event := p.colorer.Blue.Sprintf("💢 %-7s", "IP-Error")
		errDetails := p.colorer.Cyan.Sprint(ipError.SourceIp, "->", ipError.DestinationIp,
			":", ipError.Version,
			" Error:", ipError.Details)

		return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, errDetails), caps), nil

	case *tetragon.GetEventsResponse_ProcessNetworkWatermark:
		wm := response.GetProcessNetworkWatermark()
		if wm.Process == nil {
			return "", ErrMissingProcessInfo
		}
		event := p.colorer.Blue.Sprintf("➖ %-7s", "watermark")
		processInfo, caps := p.colorer.ProcessInfo(response.NodeName, wm.Process)
		wmDetails := p.colorer.Cyan.Sprint(wm.Protocol, " ", wm.WatermarksState, " ", wm.Direction, " ", wm.WatermarksType)
		return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, wmDetails), caps), nil

	case *tetragon.GetEventsResponse_ProcessConnect:
		connect := response.GetProcessConnect()
		if connect.Process == nil {
			return "", ErrMissingProcessInfo
		}
		event := p.colorer.Blue.Sprintf("🔌 %-7s", "connect")
		processInfo, caps := p.colorer.ProcessInfo(response.NodeName, connect.Process)
		destination := p.colorer.fiveTuple(
			connect.Protocol,
			connect.SourceIp,
			connect.SourcePort,
			connect.DestinationIp,
			connect.DestinationPort,
			connect.DestinationNames)
		return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, destination), caps), nil
	case *tetragon.GetEventsResponse_ProcessFile:
		file := response.GetProcessFile()
		if file.Process == nil {
			return "", fmt.Errorf("process field is not set")
		}
		event := p.colorer.Blue.Sprintf("📁 %-7s", "file")
		processInfo, caps := p.colorer.ProcessInfo(response.NodeName, file.Process)
		processFileAction := p.colorer.Cyan.Sprint(file.Action)
		functionHook := p.colorer.Cyan.Sprint(file.Hook)
		args := p.colorer.Cyan.Sprint(file.Process.Arguments)
		arg := file.GetArgs().Arg
		switch v := arg.(type) {
		case *tetragon.FileArgument_GenericArg:
			fileName := p.colorer.Cyan.Sprintf("%s", v.GenericArg.File.GetStr())
			inodeNumber := p.colorer.Cyan.Sprintf("%d", v.GenericArg.File.Inode.Number)
			return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s %s %s %s %s", event, processInfo, args, processFileAction, functionHook, fileName, inodeNumber), caps), nil
		case *tetragon.FileArgument_ReaddirArg:
			dirName := p.colorer.Cyan.Sprintf("%s", v.ReaddirArg.File.GetStr())
			inodeNumber := p.colorer.Cyan.Sprintf("%d", v.ReaddirArg.File.Inode.Number)
			return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s %s %s %s %s", event, processInfo, args, processFileAction, functionHook, dirName, inodeNumber), caps), nil
		case *tetragon.FileArgument_RenameArg:
			srcName := p.colorer.Cyan.Sprintf("%s", v.RenameArg.Src.GetStr())
			srcInodeNumber := p.colorer.Cyan.Sprintf("%d", v.RenameArg.Src.Inode.Number)
			dstName := p.colorer.Cyan.Sprintf("%s", v.RenameArg.Dst.GetStr())
			dstInodeNumber := p.colorer.Cyan.Sprintf("%d", v.RenameArg.Dst.Inode.Number)
			return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s %s %s %s %s %s %s", event, processInfo, args, processFileAction, functionHook, srcName, srcInodeNumber, dstName, dstInodeNumber), caps), nil
		case *tetragon.FileArgument_AttrArg:
			var allChanges []string
			fileName := p.colorer.Cyan.Sprintf("%s", v.AttrArg.File.GetStr())
			inodeNumber := p.colorer.Cyan.Sprintf("%d", v.AttrArg.File.Inode.Number)

			attr := v.AttrArg.Attr
			if attr.Permissions != nil && attr.Permissions.New != attr.Permissions.Old {
				allChanges = append(allChanges, strings.Join([]string{"permissions", attr.Permissions.Old, attr.Permissions.New}, " "))
			}
			if attr.Uid != nil && attr.Uid.New != attr.Uid.Old {
				allChanges = append(allChanges, strings.Join([]string{"uid", attr.Uid.Old, attr.Uid.New}, " "))
			}
			if attr.Gid != nil && attr.Gid.New != attr.Gid.Old {
				allChanges = append(allChanges, strings.Join([]string{"gid", attr.Gid.Old, attr.Gid.New}, " "))
			}
			return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s %s %s %s %s %s", event, processInfo, args, processFileAction, functionHook, fileName, inodeNumber, strings.Join(allChanges, " ")), caps), nil
		default:
			return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s %s %s [unknown: %T]", event, processInfo, args, processFileAction, functionHook, v), caps), nil
		}
	case *tetragon.GetEventsResponse_ProcessListen:
		listen := response.GetProcessListen()
		if listen.Process == nil {
			return "", ErrMissingProcessInfo
		}
		event := p.colorer.Blue.Sprintf("🎧 %-7s", "listen")
		processInfo, caps := p.colorer.ProcessInfo(response.NodeName, listen.Process)
		hostPort := p.colorer.hostPort(listen.Protocol, listen.Ip, listen.Port)
		return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, hostPort), caps), nil
	case *tetragon.GetEventsResponse_ProcessAccept:
		accept := response.GetProcessAccept()
		if accept.Process == nil {
			return "", ErrMissingProcessInfo
		}
		event := p.colorer.Blue.Sprintf("💡 %-7s", "accept")
		processInfo, caps := p.colorer.ProcessInfo(response.NodeName, accept.Process)
		fiveTuple := p.colorer.fiveTuple(
			accept.Protocol,
			accept.DestinationIp,
			accept.DestinationPort,
			accept.SourceIp,
			accept.SourcePort,
			accept.DestinationNames)
		return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, fiveTuple), caps), nil
	case *tetragon.GetEventsResponse_ProcessHttp:
		http := response.GetProcessHttp()
		if http.Process == nil {
			return "", ErrMissingProcessInfo
		}
		if http.Http == nil {
			return "", ErrMissingHTTPInfo
		}
		event := p.colorer.Blue.Sprintf("🌐 %-7s", "http")
		processInfo, caps := p.colorer.ProcessInfo(response.NodeName, http.Process)
		httpInfo := p.colorer.http(http.Http)
		return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, httpInfo), caps), nil
	case *tetragon.GetEventsResponse_Tls:
		tls := response.GetTls()
		if tls.Process == nil {
			return "", ErrMissingProcessInfo
		}
		event := p.colorer.Blue.Sprintf("🔐 %-7s", "tls")
		processInfo, caps := p.colorer.ProcessInfo(response.NodeName, tls.Process)
		tlsInfo := p.colorer.tls(tls)
		return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, tlsInfo), caps), nil
	case *tetragon.GetEventsResponse_ProcessClose:
		processClose := response.GetProcessClose()
		if processClose.Process == nil {
			return "", ErrMissingProcessInfo
		}
		event := p.colorer.Blue.Sprintf("\U0001F9F9 %-7s", "close")
		processInfo, caps := p.colorer.ProcessInfo(response.NodeName, processClose.Process)
		closeInfo := p.colorer.close(processClose)
		return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, closeInfo), caps), nil
	case *tetragon.GetEventsResponse_ProcessUdpSeqCheckError:
		event := response.GetProcessUdpSeqCheckError()
		if event.Process == nil {
			return "", ErrMissingProcessInfo
		}
		processInfo, caps := p.colorer.ProcessInfo(response.NodeName, event.Process)

		eventName := p.colorer.Blue.Sprintf("💢 %-7s", "udp-seq-err")
		details := p.colorer.Cyan.Sprint(event.Socket.SourceIp, "->", event.Socket.DestinationIp, fmt.Sprintf("%d(expected)", event.SeqNumExpected), fmt.Sprintf("%d(received)", event.SeqNumReceived))

		return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s", eventName, processInfo, details), caps), nil
	case *tetragon.GetEventsResponse_ProcessFileExec:
		event := response.GetProcessFileExec()
		if event.Process == nil {
			return "", ErrMissingProcessInfo
		}
		eventName := p.colorer.Blue.Sprintf("🚀 %-7s", "file-exec")
		processInfo, caps := p.colorer.ProcessInfo(response.NodeName, event.Process)
		fileName := "(unknown)"
		inodeNumber := "(unknown)"
		if event.File != nil {
			if n, ok := event.File.GetFilename().(*tetragon.FileDetails_Str); ok {
				fileName = n.Str
			}

			if event.File.Inode != nil {
				inodeNumber = fmt.Sprint(event.File.Inode.Number)
			}
		}
		fileName = p.colorer.Cyan.Sprint(fileName)
		inodeNumber = p.colorer.Cyan.Sprint(inodeNumber)

		return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s %s", eventName, processInfo, fileName, inodeNumber), caps), nil
	case *tetragon.GetEventsResponse_ProcessRawsockCreate:
		event := response.GetProcessRawsockCreate()
		if event.Process == nil {
			return "", ErrMissingProcessInfo
		}
		eventName := p.colorer.Blue.Sprintf("🔌 %-7s", "rawsock-create")
		processInfo, caps := p.colorer.ProcessInfo(response.NodeName, event.Process)
		cookie := p.colorer.Cyan.Sprint(event.SockCookie)

		return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s", eventName, processInfo, cookie), caps), nil
	case *tetragon.GetEventsResponse_ProcessRawsockClose:
		event := response.GetProcessRawsockClose()
		if event.Process == nil {
			return "", ErrMissingProcessInfo
		}
		eventName := p.colorer.Blue.Sprintf("\U0001F9F9 %-7s", "rawsock-close")
		processInfo, caps := p.colorer.ProcessInfo(response.NodeName, event.Process)
		cookie := p.colorer.Cyan.Sprint(event.SockCookie)

		return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s", eventName, processInfo, cookie), caps), nil
	case *tetragon.GetEventsResponse_ProcessNetworkBurst:
		event := response.GetProcessNetworkBurst()
		if event.Process == nil {
			return "", ErrMissingProcessInfo
		}
		eventName := p.colorer.Blue.Sprintf("🤯 %-7s", "netburst")
		processInfo, caps := p.colorer.ProcessInfo(response.NodeName, event.Process)
		protocol := p.colorer.Cyan.Sprint(event.Protocol)
		direction := p.colorer.Green.Sprint(event.Protocol)
		burstState := p.colorer.Red.Sprint(event.BurstState)

		return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s %s %s", eventName, processInfo, protocol, direction, burstState), caps), nil
	case *tetragon.GetEventsResponse_ProcessSandboxSyscall:
		event := response.GetProcessSandboxSyscall()
		if event.Process == nil {
			return "", ErrMissingProcessInfo
		}
		processInfo, caps := p.colorer.ProcessInfo(response.NodeName, event.Process)

		eventName := p.colorer.Blue.Sprintf("❌ %-7s", "sandbox")
		syscall := p.colorer.Cyan.Sprintf("sys_%s", event.Name)
		policy := p.colorer.Green.Sprintf("(%s)", event.Policy)

		return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s %s", eventName, processInfo, syscall, policy), caps), nil
	case *tetragon.GetEventsResponse_ProcessDns:
		dns := response.GetProcessDns()
		if dns.Process == nil {
			return "", ErrMissingProcessInfo
		}
		if dns.Dns == nil {
			return "", ErrMissingDNSInfo
		}
		event := p.colorer.Blue.Sprintf("📖 %-7s", "dns")
		processInfo, caps := p.colorer.ProcessInfo(response.NodeName, dns.Process)
		args := p.colorer.Cyan.Sprint(dnsToString(dns.Dns))
		return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, args), caps), nil
	case *tetragon.GetEventsResponse_ProcessSockStats:
		stats := response.GetProcessSockStats()
		if stats.Process == nil {
			return "", ErrMissingProcessInfo
		}
		if stats.Socket == nil {
			return "", ErrMissingSocketInfo
		}
		if stats.Stats == nil {
			return "", ErrMissingStatsInfo
		}
		event := p.colorer.Blue.Sprintf("🧮 %-7s", "socket")
		processInfo, _ := p.colorer.ProcessInfo(response.NodeName, stats.Process)
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
	case *tetragon.GetEventsResponse_InterfaceStats:
		stats := response.GetInterfaceStats()
		interfaceInfo := p.colorer.interfaceInfo(response.NodeName, stats)
		txBytes := humanize.Bytes(stats.BytesSent)
		rxBytes := humanize.Bytes(stats.BytesReceived)
		event := p.colorer.Blue.Sprintf("📒 %-7s", "netstat")
		return fmt.Sprintf("%s %s tx %s rx %s", event, interfaceInfo, txBytes, rxBytes), nil
	}
	return "", fmt.Errorf("%w: %s", ErrUnknownEventType, response.EventType())
}

func dnsToString(dnsInfo *tetragon.DnsInfo) string {
	if dnsInfo.Response {
		var answerTypes []string
		for _, answerType := range dnsInfo.ResponseTypes {
			answerTypes = append(answerTypes, dns.TypeToString[uint16(answerType)])
		}

		rcode := "unknown"
		if dnsInfo.ReturnCode != nil {
			rcode = dns.RcodeToString[int(dnsInfo.ReturnCode.Value)]
		}
		return fmt.Sprintf("%s %s %s %s", rcode, dnsInfo.Names, answerTypes, dnsInfo.Ips)
	}
	var questionTypes []string
	for _, questionType := range dnsInfo.QueryTypes {
		questionTypes = append(questionTypes, dns.TypeToString[uint16(questionType)])
	}

	return fmt.Sprintf("%s %s", dnsInfo.Names, questionTypes)
}
