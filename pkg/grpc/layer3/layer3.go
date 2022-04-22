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
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	fgsAPI "github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/eventcache"
	"github.com/isovalent/hubble-fgs/pkg/grpc/sockinfo"
	"github.com/isovalent/hubble-fgs/pkg/ktime"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
	"github.com/isovalent/hubble-fgs/pkg/process"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	nodeName = reader.GetNodeNameForExport()
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
func (l3 *Grpc) GetProcessConnect(event *fgsAPI.MsgIPv4EventUnix) *fgs.ProcessConnect {
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
			Value: uint32(fgsAPI.SwapByte(event.Tuple.DPort)),
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

	destinationIP := reader.GetIP(event.Tuple.DAddr, event.Common.Op)
	fgsEvent := &fgs.ProcessConnect{
		Process:         fgsProcess,
		Parent:          fgsParent,
		SourceIp:        reader.GetIP(event.Tuple.SAddr, event.Common.Op).String(),
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
		destinationIP := reader.GetIP(event.Tuple.DAddr, api.MSG_OP_HTTP)
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
func (l3 *Grpc) GetProcessClose(event *fgsAPI.MsgIPv4EventUnix) *fgs.ProcessClose {
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
			Value: uint32(fgsAPI.SwapByte(event.Tuple.DPort)),
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

	destinationIP := reader.GetIP(event.Tuple.DAddr, event.Common.Op)
	socketStats := reader.GetSocketStats(&event.SocketStats)

	fgsEvent := &fgs.ProcessClose{
		Process:         fgsProcess,
		Parent:          fgsParent,
		SourceIp:        reader.GetIP(event.Tuple.SAddr, event.Common.Op).String(),
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
		destinationIP := reader.GetIP(event.Tuple.DAddr, api.MSG_OP_HTTP)
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
	event *fgsAPI.MsgIPv4EventUnix,
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
		Ip:       reader.GetIP(event.Tuple.SAddr, 0).String(),
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
func (l3 *Grpc) GetProcessAccept(event *fgsAPI.MsgIPv4EventUnix) *fgs.ProcessAccept {
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
			Value: uint32(fgsAPI.SwapByte(event.Tuple.DPort)),
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

	destinationIP := reader.GetIP(event.Tuple.DAddr, event.Common.Op)
	fgsEvent := &fgs.ProcessAccept{
		Process:         fgsProcess,
		Parent:          fgsParent,
		SourceIp:        reader.GetIP(event.Tuple.SAddr, event.Common.Op).String(),
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
		destinationIP := reader.GetIP(event.Tuple.DAddr, api.MSG_OP_HTTP)
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
func (l3 *Grpc) GetProcessSockStats(event *fgsAPI.MsgIPv4EventUnix) *fgs.ProcessSockStats {
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
		destinationIP := reader.GetIP(event.Tuple.DAddr, event.Common.Op)
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

func (l3 *Grpc) HandleIpMessage(msg *api.MsgIPv4EventUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_IPV4_TCPCONNECTRET,
		api.MSG_OP_IPV4_UDPCONNECT:
		cnct := l3.GetProcessConnect(msg)
		if cnct != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessConnect{ProcessConnect: cnct},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	case api.MSG_OP_IPV4_TCPCLOSE,
		api.MSG_OP_IPV4_UDPCLOSE:
		c := l3.GetProcessClose(msg)
		if c != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessClose{ProcessClose: c},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	case api.MSG_OP_IPV4_LISTEN:
		l := l3.GetProcessListen(msg)
		if l != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessListen{ProcessListen: l},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	case api.MSG_OP_IPV4_ACCEPT:
		a := l3.GetProcessAccept(msg)
		if a != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessAccept{ProcessAccept: a},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}

	case api.MSG_OP_IPV4_TCPSTATS, api.MSG_OP_IPV4_UDPSTATS:
		s := l3.GetProcessSockStats(msg)
		if s != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessSockStats{ProcessSockStats: s},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}

	default:
		logger.GetLogger().WithField("message", msg).Warn("Unhandled event")
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
