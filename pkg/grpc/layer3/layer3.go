//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package layer3

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/cilium"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/node"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/grpc/sockinfo"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
	reader "github.com/isovalent/hubble-fgs/pkg/reader/network"
)

var (
	nodeName = node.GetNodeNameForExport()
)

func SocketFlagsDnsEnabled(t uint32) bool {
	return (t & api.SOCKFLAGS_TYPE_DNSREADY) != 0
}

type MsgIPEventUnix struct {
	Common      processapi.MsgCommon
	Tuple       networkapi.MsgIPTuple
	Kube        processapi.MsgK8sUnix
	Return      int64
	ProcessKey  processapi.MsgExecveKey
	SockCookie  uint64
	SocketStats networkapi.MsgSocketStatsUnix
	SocketFlags uint32
}

func msgToProtocol(event *MsgIPEventUnix) tetragon.SocketProtocol {
	return reader.MsgOpToProtocol(event.Common.Op)
}

// GetProcessConnect converts KprobeEvent from hubble-fgs to protobuf message.
func GetProcessConnect(event *MsgIPEventUnix) *tetragon.ProcessConnect {
	var fgsProcess, fgsParent *tetragon.Process
	var sourcePort, destinationPort *wrapperspb.UInt32Value
	var err error

	if event.Tuple.SPort != 0 {
		sourcePort = &wrapperspb.UInt32Value{
			Value: uint32(reader.GetSport(event.Tuple.SPort)),
		}
	}
	if event.Tuple.DPort != 0 {
		destinationPort = &wrapperspb.UInt32Value{
			Value: uint32(reader.SwapByte(event.Tuple.DPort)),
		}
	}

	process, parent := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
		process.RefInc()
	}
	if parent == nil {
		fgsParent = &tetragon.Process{}
	} else {
		parent.RefInc()
		fgsParent = parent.GetProcessCopy()
	}

	destinationIP := reader.GetIP(event.Tuple.DAddr, event.Common.Op, event.Tuple.IPv6 != 0)
	fgsEvent := &tetragon.ProcessConnect{
		Process:         fgsProcess,
		Parent:          fgsParent,
		SourceIp:        reader.GetIP(event.Tuple.SAddr, event.Common.Op, event.Tuple.IPv6 != 0).String(),
		SourcePort:      sourcePort,
		DestinationIp:   destinationIP.String(),
		DestinationPort: destinationPort,
		SockCookie:      event.SockCookie,
		Protocol:        msgToProtocol(event),
	}

	if event.SockCookie != 0 {
		fgsEvent.SockCookie = event.SockCookie
	}

	ec := eventcache.Get()
	fgsEvent.DestinationNames, err = sockinfo.GetProcessIp(fgsProcess, destinationIP.String(), dns.Get(), cilium.GetCiliumState())
	if err != nil && ec != nil && SocketFlagsDnsEnabled(event.SocketFlags) {
		ec.Add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if option.Config.EnableCilium && fgsProcess != nil {
		destinationIP := reader.GetIP(event.Tuple.DAddr, ops.MSG_OP_HTTP, event.Tuple.IPv6 != 0)
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
	}
	if ec != nil && ec.Needed(fgsProcess) {
		ec.Add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}
	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}
	return fgsEvent
}

func SocketFlagsToType(t uint32) string {
	if t&api.SOCKFLAGS_TYPE_CONNECT != 0 {
		return "connect"
	} else if t&api.SOCKFLAGS_TYPE_ACCEPT != 0 {
		return "accept"
	} else if t&api.SOCKFLAGS_TYPE_LISTEN != 0 {
		return "listen"
	}
	return "unknown"
}

// GetProcessClose converts KprobeEvent from hubble-fgs to protobuf message.
func GetProcessClose(event *MsgIPEventUnix) *tetragon.ProcessClose {
	var sourcePort, destinationPort *wrapperspb.UInt32Value
	var fgsParent, fgsProcess *tetragon.Process
	var err error

	if event.Tuple.SPort != 0 {
		sourcePort = &wrapperspb.UInt32Value{
			Value: uint32(reader.GetSport(event.Tuple.SPort)),
		}
	}
	if event.Tuple.DPort != 0 {
		destinationPort = &wrapperspb.UInt32Value{
			Value: uint32(reader.SwapByte(event.Tuple.DPort)),
		}
	}

	process, parent := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
		process.RefDec()
	}
	if parent == nil {
		fgsParent = &tetragon.Process{}
	} else {
		fgsParent = parent.GetProcessCopy()
		parent.RefDec()
	}

	destinationIP := reader.GetIP(event.Tuple.DAddr, event.Common.Op, event.Tuple.IPv6 != 0)
	socketStats := reader.GetSocketStats(&event.SocketStats)

	fgsEvent := &tetragon.ProcessClose{
		Process:         fgsProcess,
		Parent:          fgsParent,
		SourceIp:        reader.GetIP(event.Tuple.SAddr, event.Common.Op, event.Tuple.IPv6 != 0).String(),
		SourcePort:      sourcePort,
		DestinationIp:   destinationIP.String(),
		DestinationPort: destinationPort,
		Stats:           socketStats,
		Protocol:        msgToProtocol(event),
		SocketType:      SocketFlagsToType(event.SocketFlags),
	}

	if event.SockCookie != 0 {
		fgsEvent.SockCookie = event.SockCookie
	}

	dnsCache := dns.Get()
	ec := eventcache.Get()
	state := cilium.GetCiliumState()
	fgsEvent.DestinationNames, err = sockinfo.GetProcessIp(fgsProcess, destinationIP.String(), dnsCache, state)
	if err != nil && ec != nil && SocketFlagsDnsEnabled(event.SocketFlags) {
		ec.Add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if option.Config.EnableCilium && fgsProcess != nil {
		destinationIP := reader.GetIP(event.Tuple.DAddr, ops.MSG_OP_HTTP, event.Tuple.IPv6 != 0)
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
	}
	if ec != nil && ec.Needed(fgsProcess) {
		ec.Add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}
	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}
	return fgsEvent
}

// GetProcessListen returns Listen protobuf message for a given process, including the ancestor list.
func GetProcessListen(
	event *MsgIPEventUnix,
) *tetragon.ProcessListen {
	var fgsProcess, fgsParent *tetragon.Process
	var port *wrapperspb.UInt32Value

	if event.Tuple.SPort != 0 {
		port = &wrapperspb.UInt32Value{
			Value: uint32(reader.GetSport(event.Tuple.SPort)),
		}
	}
	process, parent := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process != nil {
		process.RefInc()
		fgsProcess = process.UnsafeGetProcess()
	} else {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	}
	if parent != nil {
		parent.RefInc()
		fgsParent = parent.GetProcessCopy()
	}
	fgsEvent := &tetragon.ProcessListen{
		Process:  fgsProcess,
		Parent:   fgsParent,
		Ip:       reader.GetIP(event.Tuple.SAddr, 0, event.Tuple.IPv6 != 0).String(),
		Port:     port,
		Protocol: msgToProtocol(event),
	}

	if event.SockCookie != 0 {
		fgsEvent.SockCookie = event.SockCookie
	}

	ec := eventcache.Get()
	if ec != nil && ec.Needed(fgsProcess) {
		ec.Add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}

	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}
	return fgsEvent
}

// GetProcessAccept converts KprobeEvent from hubble-fgs to protobuf message.
func GetProcessAccept(event *MsgIPEventUnix) *tetragon.ProcessAccept {
	var sourcePort, destinationPort *wrapperspb.UInt32Value
	var fgsParent, fgsProcess *tetragon.Process
	var err error

	if event.Tuple.SPort != 0 {
		sourcePort = &wrapperspb.UInt32Value{
			Value: uint32(reader.GetSport(event.Tuple.SPort)),
		}
	}
	if event.Tuple.DPort != 0 {
		destinationPort = &wrapperspb.UInt32Value{
			Value: uint32(reader.SwapByte(event.Tuple.DPort)),
		}
	}

	process, parent := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
		process.RefInc()
	}
	if parent == nil {
		fgsParent = &tetragon.Process{}
	} else {
		parent.RefInc()
		fgsParent = parent.GetProcessCopy()
	}

	destinationIP := reader.GetIP(event.Tuple.DAddr, event.Common.Op, event.Tuple.IPv6 != 0)
	fgsEvent := &tetragon.ProcessAccept{
		Process:         fgsProcess,
		Parent:          fgsParent,
		SourceIp:        reader.GetIP(event.Tuple.SAddr, event.Common.Op, event.Tuple.IPv6 != 0).String(),
		SourcePort:      sourcePort,
		DestinationIp:   destinationIP.String(),
		DestinationPort: destinationPort,

		Protocol: msgToProtocol(event),
	}

	if event.SockCookie != 0 {
		fgsEvent.SockCookie = event.SockCookie
	}

	dnsCache := dns.Get()
	ec := eventcache.Get()
	state := cilium.GetCiliumState()
	fgsEvent.DestinationNames, err = sockinfo.GetProcessIp(fgsProcess, destinationIP.String(), dnsCache, state)
	if err != nil && ec != nil && SocketFlagsDnsEnabled(event.SocketFlags) {
		ec.Add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if option.Config.EnableCilium && fgsProcess != nil {
		destinationIP := reader.GetIP(event.Tuple.DAddr, ops.MSG_OP_HTTP, event.Tuple.IPv6 != 0)
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
	}

	if ec != nil  && ec.Needed(fgsProcess) {
		ec.Add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}
	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}

	return fgsEvent
}

// GetProcessSockStats converts KprobeEvent from hubble-fgs to protobuf message.
func GetProcessSockStats(event *MsgIPEventUnix) *tetragon.ProcessSockStats {
	var fgsParent, fgsProcess *tetragon.Process

	process, parent := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
	}
	if parent == nil {
		fgsParent = &tetragon.Process{}
	} else {
		fgsParent = parent.GetProcessCopy()
	}

	fgsTuple := sockinfo.GetTuple(&event.Tuple, event.SockCookie, event.Common.Op)
	fgsSocketStats := reader.GetSocketStats(&event.SocketStats)

	fgsEvent := &tetragon.ProcessSockStats{
		Process: fgsProcess,
		Parent:  fgsParent,
		Socket:  fgsTuple,
		Stats:   fgsSocketStats,
	}

	// Stats are pushed on the timer e.g. every 60 seconds by default and at
	// end of flow so it seems unliklye that DNS entry should be missing. For
	// now I'll skip bouncing these through DNS entries when missing DNS
	dnsCache := dns.Get()
	ec := eventcache.Get()
	state := cilium.GetCiliumState()
	fgsEvent.Socket.DestinationNames, _ = sockinfo.GetProcessIp(fgsProcess, fgsTuple.DestinationIp, dnsCache, state)

	if option.Config.EnableCilium && fgsProcess != nil {
		destinationIP := reader.GetIP(event.Tuple.DAddr, event.Common.Op, event.Tuple.IPv6 != 0)
		fgsEvent.Socket.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
	}

	if ec != nil && ec.Needed(fgsProcess) {
		ec.Add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}
	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}
	return fgsEvent
}

func (msg *MsgIPEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	switch msg.Common.Op {
	case ops.MSG_OP_TCPCONNECTRET,
		ops.MSG_OP_UDPCONNECT:
		cnct := GetProcessConnect(msg)
		if cnct != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessConnect{ProcessConnect: cnct},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	case ops.MSG_OP_TCPCLOSE,
		ops.MSG_OP_UDPCLOSE:
		c := GetProcessClose(msg)
		if c != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessClose{ProcessClose: c},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	case ops.MSG_OP_LISTEN:
		l := GetProcessListen(msg)
		if l != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessListen{ProcessListen: l},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	case ops.MSG_OP_ACCEPT:
		a := GetProcessAccept(msg)
		if a != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessAccept{ProcessAccept: a},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}

	case ops.MSG_OP_TCPSTATS, ops.MSG_OP_UDPSTATS:
		s := GetProcessSockStats(msg)
		if s != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessSockStats{ProcessSockStats: s},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}

	case ops.MSG_OP_IP_ERROR:
		s := GetProcessIPError(msg)
		if s != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessIpError{ProcessIpError: s},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}

	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleIpMessage: Unhandled event")
	}
	return res
}

func GetProcessIPError(event *MsgIPEventUnix) *tetragon.ProcessIpError {
	var fgsParent, fgsProcess *tetragon.Process

	process, parent := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
	}
	if parent == nil {
		fgsParent = &tetragon.Process{}
	} else {
		fgsParent = parent.GetProcessCopy()
	}

	sourceIP := reader.GetIP(event.Tuple.SAddr, event.Common.Op, event.Tuple.IPv6 != 0)
	destinationIP := reader.GetIP(event.Tuple.DAddr, event.Common.Op, event.Tuple.IPv6 != 0)

	var version string
	if event.Tuple.IPv6 == 0 {
		version = "IPv4"
	} else {
		version = "IPv6"
	}

	var details string

	// Lower 32 bits is error code, upper 32 bits is data if required.
	switch event.Return & 0xffffffff {
	case 1:
		details = "No heap available"
	case 2:
		details = "Read next failed (probe)"
	case 3:
		details = "Read next failed (skb_load)"
	case 4:
		details = "Read next failed (skb)"
	case 5:
		details = "Unknown IPv6 extension: " + fmt.Sprintf("%d", event.Return>>32)
	case 6:
		details = "Too many IPv6 extensions"
	default:
		details = "Unknown error"
	}

	fgsEvent := &tetragon.ProcessIpError{
		Process:       fgsProcess,
		Parent:        fgsParent,
		SourceIp:      sourceIP.String(),
		DestinationIp: destinationIP.String(),
		Version:       version,
		SockCookie:    event.SockCookie,
		Details:       details,
	}

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if option.Config.EnableCilium && fgsProcess != nil {
		destinationIP := reader.GetIP(event.Tuple.DAddr, event.Common.Op, event.Tuple.IPv6 != 0)
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
	}

	ec := eventcache.Get()
	if ec != nil && ec.Needed(fgsProcess) {
		ec.Add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}
	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}
	return fgsEvent
}
