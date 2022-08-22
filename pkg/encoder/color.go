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
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/encoder"
	"github.com/dustin/go-humanize"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type colorer struct {
	*encoder.Colorer
}

func newColorer(when encoder.ColorMode) *colorer {
	return &colorer{
		Colorer: encoder.NewColorer(when),
	}
}

func (c colorer) interfaceInfo(host string, stats *tetragon.InterfaceStats) string {
	source := c.Green.Sprint(host)
	interfaceInfo := c.Magenta.Sprint(stats.InterfaceName, "@", stats.InterfaceIfindex)
	return fmt.Sprintf("%s %s", source, interfaceInfo)
}

func (c colorer) http(http *tetragon.HttpInfo) string {
	if http.Response == nil || http.Response.Code == 0 {
		return c.Cyan.Sprint(
			http.Request.Host, " ",
			http.Request.Method, " ",
			http.Request.Uri, " ")
	}
	var latency time.Duration
	if http.Latency != nil {
		latency = http.Latency.AsDuration()
	}
	return c.Cyan.Sprint(
		http.Request.Host, " ",
		http.Request.Method, " ",
		http.Request.Uri, " ",
		http.Response.Code, " ",
		http.Response.Reason, " ",
		latency)
}

func (c colorer) tls(tls *tetragon.Tls) string {
	var dstPort uint32
	if tls.DestinationPort != nil {
		dstPort = tls.DestinationPort.Value
	}
	return c.Cyan.Sprint(
		tls.DestinationIp, ":", dstPort, " ",
		tls.SniName, " ",
		tls.NegotiatedVersion, " ",
		tls.Cipher)
}

func (c colorer) close(close *tetragon.ProcessClose) string {
	if close.SocketType == "listen" {
		return c.hostPort(close.Protocol, close.SourceIp, close.SourcePort) + " (listen)"
	}
	destination := c.fiveTuple(
		close.Protocol,
		close.SourceIp,
		close.SourcePort,
		close.DestinationIp,
		close.DestinationPort,
		close.DestinationNames)
	var txBytes, rxBytes string
	if close.Stats != nil {
		txBytes = humanize.Bytes(close.Stats.BytesSent)
		rxBytes = humanize.Bytes(close.Stats.BytesReceived)
	}
	return c.Cyan.Sprint(
		destination,
		" tx ", txBytes,
		" rx ", rxBytes,
	)
}

func (c colorer) hostPort(protocol tetragon.SocketProtocol, host string, portPtr *wrapperspb.UInt32Value) string {
	var port uint32
	if portPtr != nil {
		port = portPtr.Value
	}
	return c.Cyan.Sprint(protocol, " ", host, ":", port)
}

func (c colorer) fiveTuple(
	protocol tetragon.SocketProtocol,
	srcHost string,
	srcPortPtr *wrapperspb.UInt32Value,
	dstHost string,
	dstPortPtr *wrapperspb.UInt32Value,
	dns []string) string {
	var srcPort, dstPort uint32
	if srcPortPtr != nil {
		srcPort = srcPortPtr.GetValue()
	}
	if dstPortPtr != nil {
		dstPort = dstPortPtr.GetValue()
	}
	if len(dns) == 0 {
		return c.Cyan.Sprint(protocol, " ", srcHost, ":", srcPort, " => ", dstHost, ":", dstPort)
	}
	return c.Cyan.Sprint(protocol, " ", srcHost, ":", srcPort, " => ", dstHost, ":", dstPort, " ", dns)
}
