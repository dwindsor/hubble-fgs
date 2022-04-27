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
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type colorer struct {
	colors  []*color.Color
	red     *color.Color
	green   *color.Color
	blue    *color.Color
	cyan    *color.Color
	magenta *color.Color
	yellow  *color.Color
}

func newColorer(when ColorMode) *colorer {
	red := color.New(color.FgRed)
	green := color.New(color.FgGreen)
	blue := color.New(color.FgBlue)
	cyan := color.New(color.FgCyan)
	magenta := color.New(color.FgMagenta)
	yellow := color.New(color.FgYellow)

	c := &colorer{
		red:     red,
		green:   green,
		blue:    blue,
		cyan:    cyan,
		magenta: magenta,
		yellow:  yellow,
	}

	c.colors = []*color.Color{
		red, green, blue,
		cyan, magenta, yellow,
	}
	switch when {
	case Always:
		c.enable()
	case Never:
		c.disable()
	case Auto:
		c.auto()
	}
	return c
}

func (c *colorer) auto() {
	for _, v := range c.colors {
		if color.NoColor { // NoColor is global and set dynamically
			v.DisableColor()
		} else {
			v.EnableColor()
		}
	}
}

func (c *colorer) enable() {
	for _, v := range c.colors {
		v.EnableColor()
	}
}

func (c *colorer) disable() {
	for _, v := range c.colors {
		v.DisableColor()
	}
}

func printCap(c int) bool {
	switch c {
	case int(fgs.CapabilitiesType_CAP_SYS_ADMIN):
		return true
	}
	return false
}

func processCaps(c *fgs.Capabilities) string {
	var caps []string

	if c == nil {
		return ""
	}

	for e := range c.Effective {
		if printCap(e) {
			caps = append(caps, fgs.CapabilitiesType_name[int32(e)])
		}
	}

	capsString := strings.Join(caps, ",")
	if len(caps) > 0 {
		capsString = "🛑 " + capsString
	}
	return capsString
}

func (c colorer) processInfo(host string, process *fgs.Process) (string, string) {
	source := c.green.Sprint(host)
	if process.Pod != nil {
		source = c.green.Sprint(process.Pod.Namespace, "/", process.Pod.Name)
	}
	proc := c.magenta.Sprint(process.Binary)
	caps := c.magenta.Sprint(processCaps(process.Cap))
	return fmt.Sprintf("%s %s", source, proc), caps
}

func (c colorer) interfaceInfo(host string, stats *fgs.InterfaceStats) string {
	source := c.green.Sprint(host)
	interfaceInfo := c.magenta.Sprint(stats.InterfaceName, "@", stats.InterfaceIfindex)
	return fmt.Sprintf("%s %s", source, interfaceInfo)
}

func (c colorer) http(http *fgs.HttpInfo) string {
	if http.Response == nil || http.Response.Code == 0 {
		return c.cyan.Sprint(
			http.Request.Host, " ",
			http.Request.Method, " ",
			http.Request.Uri, " ")
	}
	var latency time.Duration
	if http.Latency != nil {
		latency = http.Latency.AsDuration()
	}
	return c.cyan.Sprint(
		http.Request.Host, " ",
		http.Request.Method, " ",
		http.Request.Uri, " ",
		http.Response.Code, " ",
		http.Response.Reason, " ",
		latency)
}

func (c colorer) tls(tls *fgs.Tls) string {
	var dstPort uint32
	if tls.DestinationPort != nil {
		dstPort = tls.DestinationPort.Value
	}
	return c.cyan.Sprint(
		tls.DestinationIp, ":", dstPort, " ",
		tls.SniName, " ",
		tls.NegotiatedVersion, " ",
		tls.Cipher)
}

func (c colorer) close(close *fgs.ProcessClose) string {
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
	return c.cyan.Sprint(
		destination,
		" tx ", txBytes,
		" rx ", rxBytes,
	)
}

func (c colorer) hostPort(protocol fgs.SocketProtocol, host string, portPtr *wrapperspb.UInt32Value) string {
	var port uint32
	if portPtr != nil {
		port = portPtr.Value
	}
	return c.cyan.Sprint(protocol, " ", host, ":", port)
}

func (c colorer) fiveTuple(
	protocol fgs.SocketProtocol,
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
		return c.cyan.Sprint(protocol, " ", srcHost, ":", srcPort, " => ", dstHost, ":", dstPort)
	}
	return c.cyan.Sprint(protocol, " ", srcHost, ":", srcPort, " => ", dstHost, ":", dstPort, " ", dns)
}
