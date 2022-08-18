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

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/encoder"
	"github.com/dustin/go-humanize"
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
		inner:   encoder.NewCompactEncoder(w, colorMode, timestamps),
		colorer: *newColorer(colorMode),
	}
}

// Encode implements EventEncoder.Encode.
func (p *EnterpriseEncoder) Encode(v interface{}) error {
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
		str = fmt.Sprintf("%s %s", ts, str)
	}
	fmt.Fprintln(p.inner.Writer, str)
	return nil
}

func (p *EnterpriseEncoder) eventToString(response *tetragon.GetEventsResponse) (string, error) {
	if s, err := p.inner.EventToString(response); err == nil {
		return s, nil
	}

	switch response.Event.(type) {
	case *tetragon.GetEventsResponse_ProcessConnect:
		connect := response.GetProcessConnect()
		if connect.Process == nil {
			return "", ErrMissingProcessInfo
		}
		event := p.colorer.Blue.Sprintf("🔌 %-7s", "connect")
		processInfo, caps := p.colorer.processInfo(response.NodeName, connect.Process)
		destination := p.colorer.fiveTuple(
			connect.Protocol,
			connect.SourceIp,
			connect.SourcePort,
			connect.DestinationIp,
			connect.DestinationPort,
			connect.DestinationNames)
		return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, destination), caps), nil
	case *tetragon.GetEventsResponse_ProcessListen:
		listen := response.GetProcessListen()
		if listen.Process == nil {
			return "", ErrMissingProcessInfo
		}
		event := p.colorer.Blue.Sprintf("🎧 %-7s", "listen")
		processInfo, caps := p.colorer.processInfo(response.NodeName, listen.Process)
		hostPort := p.colorer.hostPort(listen.Protocol, listen.Ip, listen.Port)
		return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, hostPort), caps), nil
	case *tetragon.GetEventsResponse_ProcessAccept:
		accept := response.GetProcessAccept()
		if accept.Process == nil {
			return "", ErrMissingProcessInfo
		}
		event := p.colorer.Blue.Sprintf("💡 %-7s", "accept")
		processInfo, caps := p.colorer.processInfo(response.NodeName, accept.Process)
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
		processInfo, caps := p.colorer.processInfo(response.NodeName, http.Process)
		httpInfo := p.colorer.http(http.Http)
		return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, httpInfo), caps), nil
	case *tetragon.GetEventsResponse_Tls:
		tls := response.GetTls()
		if tls.Process == nil {
			return "", ErrMissingProcessInfo
		}
		event := p.colorer.Blue.Sprintf("🔐 %-7s", "tls")
		processInfo, caps := p.colorer.processInfo(response.NodeName, tls.Process)
		tlsInfo := p.colorer.tls(tls)
		return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, tlsInfo), caps), nil
	case *tetragon.GetEventsResponse_ProcessClose:
		processClose := response.GetProcessClose()
		if processClose.Process == nil {
			return "", ErrMissingProcessInfo
		}
		event := p.colorer.Blue.Sprintf("\U0001F9F9 %-7s", "close")
		processInfo, caps := p.colorer.processInfo(response.NodeName, processClose.Process)
		closeInfo := p.colorer.close(processClose)
		return encoder.CapTrailorPrinter(fmt.Sprintf("%s %s %s", event, processInfo, closeInfo), caps), nil
	case *tetragon.GetEventsResponse_ProcessDns:
		dns := response.GetProcessDns()
		if dns.Process == nil {
			return "", ErrMissingProcessInfo
		}
		if dns.Dns == nil {
			return "", ErrMissingDNSInfo
		}
		event := p.colorer.Blue.Sprintf("📖 %-7s", "dns")
		processInfo, caps := p.colorer.processInfo(response.NodeName, dns.Process)
		args := p.colorer.Cyan.Sprint(dns.GetDns().Names, " => ", dns.GetDns().Ips)
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
	case *tetragon.GetEventsResponse_InterfaceStats:
		stats := response.GetInterfaceStats()
		interfaceInfo := p.colorer.interfaceInfo(response.NodeName, stats)
		txBytes := humanize.Bytes(stats.BytesSent)
		rxBytes := humanize.Bytes(stats.BytesReceived)
		event := p.colorer.Blue.Sprintf("📒 %-7s", "netstat")
		return fmt.Sprintf("%s %s tx %s rx %s", event, interfaceInfo, txBytes, rxBytes), nil
	}
	return "", encoder.ErrUnknownEventType
}
