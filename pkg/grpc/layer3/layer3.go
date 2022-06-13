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
	"github.com/cilium/hubble/pkg/cilium"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/eventcache"
	"github.com/isovalent/hubble-fgs/pkg/grpc/sockinfo"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
	"github.com/isovalent/hubble-fgs/pkg/process"
	reader "github.com/isovalent/hubble-fgs/pkg/reader/network"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	nodeName = node.GetNodeNameForExport()
)

type Grpc struct {
	ciliumState      *cilium.State
	dns              *dns.Cache
	enableCilium     bool
	enableEventCache bool
	eventCache       *eventcache.Cache
}

func SocketFlagsDnsEnabled(t uint32) bool {
	return (t & api.SOCKFLAGS_TYPE_DNSREADY) != 0
}

// GetProcessConnect converts KprobeEvent from hubble-fgs to protobuf message.
func (l3 *Grpc) GetProcessConnect(event *api.MsgIPEventUnix) *fgs.ProcessConnect {
	var fgsProcess, fgsParent *fgs.Process
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
		fgsProcess = &fgs.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
		process.RefInc()
	}
	if parent == nil {
		fgsParent = &fgs.Process{}
	} else {
		parent.RefInc()
		fgsParent = parent.GetProcessCopy()
	}

	destinationIP := reader.GetIP(uint32(event.Tuple.DAddr[0]), event.Common.Op)
	fgsEvent := &fgs.ProcessConnect{
		Process:         fgsProcess,
		Parent:          fgsParent,
		SourceIp:        reader.GetIP(uint32(event.Tuple.SAddr[0]), event.Common.Op).String(),
		SourcePort:      sourcePort,
		DestinationIp:   destinationIP.String(),
		DestinationPort: destinationPort,
		SockCookie:      event.SockCookie,
		Protocol:        reader.MsgToProtocol(event),
	}

	if event.SockCookie != 0 {
		fgsEvent.SockCookie = event.SockCookie
	}

	fgsEvent.DestinationNames, err = sockinfo.GetProcessIp(fgsProcess, destinationIP.String(), l3.dns, l3.ciliumState)
	if err != nil && l3.enableEventCache && SocketFlagsDnsEnabled(event.SocketFlags) {
		l3.eventCache.Add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if l3.enableCilium && fgsProcess != nil {
		destinationIP := reader.GetIP(uint32(event.Tuple.DAddr[0]), ops.MSG_OP_HTTP)
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
	}
	if l3.eventCache.Needed(fgsProcess) {
		l3.eventCache.Add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
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
func (l3 *Grpc) GetProcessClose(event *api.MsgIPEventUnix) *fgs.ProcessClose {
	var sourcePort, destinationPort *wrapperspb.UInt32Value
	var fgsParent, fgsProcess *fgs.Process
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
		fgsProcess = &fgs.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
		process.RefDec()
	}
	if parent == nil {
		fgsParent = &fgs.Process{}
	} else {
		fgsParent = parent.GetProcessCopy()
		parent.RefDec()
	}

	destinationIP := reader.GetIP(uint32(event.Tuple.DAddr[0]), event.Common.Op)
	socketStats := reader.GetSocketStats(&event.SocketStats)

	fgsEvent := &fgs.ProcessClose{
		Process:         fgsProcess,
		Parent:          fgsParent,
		SourceIp:        reader.GetIP(uint32(event.Tuple.SAddr[0]), event.Common.Op).String(),
		SourcePort:      sourcePort,
		DestinationIp:   destinationIP.String(),
		DestinationPort: destinationPort,
		Stats:           socketStats,
		Protocol:        reader.MsgToProtocol(event),
		SocketType:      SocketFlagsToType(event.SocketFlags),
	}

	if event.SockCookie != 0 {
		fgsEvent.SockCookie = event.SockCookie
	}

	fgsEvent.DestinationNames, err = sockinfo.GetProcessIp(fgsProcess, destinationIP.String(), l3.dns, l3.ciliumState)
	if err != nil && l3.enableEventCache && SocketFlagsDnsEnabled(event.SocketFlags) {
		l3.eventCache.Add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if l3.enableCilium && fgsProcess != nil {
		destinationIP := reader.GetIP(uint32(event.Tuple.DAddr[0]), ops.MSG_OP_HTTP)
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
	}
	if l3.eventCache.Needed(fgsProcess) {
		l3.eventCache.Add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}
	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}
	return fgsEvent
}

// GetProcessListen returns Listen protobuf message for a given process, including the ancestor list.
func (l3 *Grpc) GetProcessListen(
	event *api.MsgIPEventUnix,
) *fgs.ProcessListen {
	var fgsProcess, fgsParent *fgs.Process
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
		fgsProcess = &fgs.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	}
	if parent != nil {
		parent.RefInc()
		fgsParent = parent.GetProcessCopy()
	}
	fgsEvent := &fgs.ProcessListen{
		Process:  fgsProcess,
		Parent:   fgsParent,
		Ip:       reader.GetIP(uint32(event.Tuple.SAddr[0]), 0).String(),
		Port:     port,
		Protocol: reader.MsgToProtocol(event),
	}

	if event.SockCookie != 0 {
		fgsEvent.SockCookie = event.SockCookie
	}

	if l3.eventCache.Needed(fgsProcess) {
		l3.eventCache.Add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}

	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}
	return fgsEvent
}

// GetProcessAccept converts KprobeEvent from hubble-fgs to protobuf message.
func (l3 *Grpc) GetProcessAccept(event *api.MsgIPEventUnix) *fgs.ProcessAccept {
	var sourcePort, destinationPort *wrapperspb.UInt32Value
	var fgsParent, fgsProcess *fgs.Process
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
		fgsProcess = &fgs.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
		process.RefInc()
	}
	if parent == nil {
		fgsParent = &fgs.Process{}
	} else {
		parent.RefInc()
		fgsParent = parent.GetProcessCopy()
	}

	destinationIP := reader.GetIP(uint32(event.Tuple.DAddr[0]), event.Common.Op)
	fgsEvent := &fgs.ProcessAccept{
		Process:         fgsProcess,
		Parent:          fgsParent,
		SourceIp:        reader.GetIP(uint32(event.Tuple.SAddr[0]), event.Common.Op).String(),
		SourcePort:      sourcePort,
		DestinationIp:   destinationIP.String(),
		DestinationPort: destinationPort,

		Protocol: reader.MsgToProtocol(event),
	}

	if event.SockCookie != 0 {
		fgsEvent.SockCookie = event.SockCookie
	}

	fgsEvent.DestinationNames, err = sockinfo.GetProcessIp(fgsProcess, destinationIP.String(), l3.dns, l3.ciliumState)
	if err != nil && l3.enableEventCache && SocketFlagsDnsEnabled(event.SocketFlags) {
		l3.eventCache.Add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if l3.enableCilium && fgsProcess != nil {
		destinationIP := reader.GetIP(uint32(event.Tuple.DAddr[0]), ops.MSG_OP_HTTP)
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
	}

	if l3.eventCache.Needed(fgsProcess) {
		l3.eventCache.Add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}
	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}

	return fgsEvent
}

// GetProcessSockStats converts KprobeEvent from hubble-fgs to protobuf message.
func (l3 *Grpc) GetProcessSockStats(event *api.MsgIPEventUnix) *fgs.ProcessSockStats {
	var fgsParent, fgsProcess *fgs.Process

	process, parent := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &fgs.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
	}
	if parent == nil {
		fgsParent = &fgs.Process{}
	} else {
		fgsParent = parent.GetProcessCopy()
	}

	fgsTuple := sockinfo.GetProcessTuple(event)
	fgsSocketStats := reader.GetSocketStats(&event.SocketStats)

	fgsEvent := &fgs.ProcessSockStats{
		Process: fgsProcess,
		Parent:  fgsParent,
		Socket:  fgsTuple,
		Stats:   fgsSocketStats,
	}

	// Stats are pushed on the timer e.g. every 60 seconds by default and at
	// end of flow so it seems unliklye that DNS entry should be missing. For
	// now I'll skip bouncing these through DNS entries when missing DNS.
	fgsEvent.Socket.DestinationNames, _ = sockinfo.GetProcessIp(fgsProcess, fgsTuple.DestinationIp, l3.dns, l3.ciliumState)

	if l3.enableCilium && fgsProcess != nil {
		destinationIP := reader.GetIP(uint32(event.Tuple.DAddr[0]), event.Common.Op)
		fgsEvent.Socket.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
	}

	if l3.eventCache.Needed(fgsProcess) {
		l3.eventCache.Add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}
	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}
	return fgsEvent
}

func (l3 *Grpc) HandleIpMessage(msg *api.MsgIPEventUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case ops.MSG_OP_TCPCONNECTRET,
		ops.MSG_OP_UDPCONNECT:
		cnct := l3.GetProcessConnect(msg)
		if cnct != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessConnect{ProcessConnect: cnct},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	case ops.MSG_OP_TCPCLOSE,
		ops.MSG_OP_UDPCLOSE:
		c := l3.GetProcessClose(msg)
		if c != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessClose{ProcessClose: c},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	case ops.MSG_OP_LISTEN:
		l := l3.GetProcessListen(msg)
		if l != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessListen{ProcessListen: l},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	case ops.MSG_OP_ACCEPT:
		a := l3.GetProcessAccept(msg)
		if a != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessAccept{ProcessAccept: a},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}

	case ops.MSG_OP_TCPSTATS, ops.MSG_OP_UDPSTATS:
		s := l3.GetProcessSockStats(msg)
		if s != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessSockStats{ProcessSockStats: s},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}

	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleIpMessage: Unhandled event")
	}
	return res
}

func New(ciliumState *cilium.State, dnsCache *dns.Cache, eventC *eventcache.Cache, ciliumEnabled bool) *Grpc {
	return &Grpc{
		ciliumState:  ciliumState,
		dns:          dnsCache,
		enableCilium: ciliumEnabled,
		eventCache:   eventC,
	}
}
