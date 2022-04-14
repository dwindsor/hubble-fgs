//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package grpc

import (
	"fmt"
	"net"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	fgsAPI "github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/ktime"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
	"github.com/isovalent/hubble-fgs/pkg/process"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func (pm *ProcessManager) __getProcessTuple(tuple *fgsAPI.MsgIPv4Tuple, cookie uint64, op uint8) *fgs.SockInfo {
	var sourcePort, destinationPort *wrapperspb.UInt32Value

	if tuple.SPort != 0 {
		sourcePort = &wrapperspb.UInt32Value{
			Value: uint32(reader.GetSport(tuple.SPort)),
		}
	}
	if tuple.DPort != 0 {
		destinationPort = &wrapperspb.UInt32Value{
			Value: uint32(fgsAPI.SwapByte(tuple.DPort)),
		}
	}

	destinationIP := reader.GetIP(tuple.DAddr, op)

	return &fgs.SockInfo{
		SourcePort:      sourcePort,
		SourceIp:        reader.GetIP(tuple.SAddr, op).String(),
		DestinationIp:   destinationIP.String(),
		DestinationPort: destinationPort,
		SockCookie:      cookie,

		Protocol: reader.MsgOpToProtocol(op),
	}
}

func (pm *ProcessManager) getProcessTuple(event *fgsAPI.MsgIPv4EventUnix) *fgs.SockInfo {
	return pm.__getProcessTuple(&event.Tuple, event.SockCookie, event.Common.Op)
}

func (pm *ProcessManager) getProcessIp(proc *fgs.Process, ip string) ([]string, error) {
	var entry []string

	if dns.CiliumDnsEnabled() {
		endpoint := process.GetProcessEndpoint(proc)
		if endpoint == nil {
			return nil, fmt.Errorf("no endpoint found for GetIp")
		}
		entry = pm.ciliumState.GetFQDNCache().GetNamesOf(endpoint.ID, net.ParseIP(ip))
		if len(entry) == 0 {
			return nil, fmt.Errorf("no dns entry found through FQDN Cache")
		}
		return entry, nil
	}
	return pm.dns.GetIp(ip)
}

func SocketFlagsDnsEnabled(t uint32) bool {
	return (t & api.SOCKFLAGS_TYPE_DNSREADY) != 0
}

// GetProcessConnect converts KprobeEvent from hubble-fgs to protobuf message.
func (pm *ProcessManager) GetProcessConnect(event *fgsAPI.MsgIPv4EventUnix) *fgs.ProcessConnect {
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

	fgsEvent.DestinationNames, err = pm.getProcessIp(fgsProcess, destinationIP.String())
	if err != nil && pm.enableEventCache && SocketFlagsDnsEnabled(event.SocketFlags) {
		pm.eventCache.add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if pm.enableCilium && fgsProcess != nil {
		destinationIP := reader.GetIP(event.Tuple.DAddr, api.MSG_OP_HTTP)
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
	}
	if pm.processCacheNeeded(fgsProcess) {
		pm.eventCache.add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
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
func (pm *ProcessManager) GetProcessClose(event *fgsAPI.MsgIPv4EventUnix) *fgs.ProcessClose {
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

	fgsEvent.DestinationNames, err = pm.getProcessIp(fgsProcess, destinationIP.String())
	if err != nil && pm.enableEventCache && SocketFlagsDnsEnabled(event.SocketFlags) {
		pm.eventCache.add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if pm.enableCilium && fgsProcess != nil {
		destinationIP := reader.GetIP(event.Tuple.DAddr, api.MSG_OP_HTTP)
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
	}
	if pm.processCacheNeeded(fgsProcess) {
		pm.eventCache.add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}
	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}
	return fgsEvent
}

// GetProcessListen returns Listen protobuf message for a given process, including the ancestor list.
func (pm *ProcessManager) GetProcessListen(
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

	if pm.processCacheNeeded(fgsProcess) {
		pm.eventCache.add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}

	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}
	return fgsEvent
}

// GetProcessAccept converts KprobeEvent from hubble-fgs to protobuf message.
func (pm *ProcessManager) GetProcessAccept(event *fgsAPI.MsgIPv4EventUnix) *fgs.ProcessAccept {
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

	fgsEvent.DestinationNames, err = pm.getProcessIp(fgsProcess, destinationIP.String())
	if err != nil && pm.enableEventCache && SocketFlagsDnsEnabled(event.SocketFlags) {
		pm.eventCache.add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if pm.enableCilium && fgsProcess != nil {
		destinationIP := reader.GetIP(event.Tuple.DAddr, api.MSG_OP_HTTP)
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
	}

	if pm.processCacheNeeded(fgsProcess) {
		pm.eventCache.add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}
	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}

	return fgsEvent
}

// GetProcessSockStats converts KprobeEvent from hubble-fgs to protobuf message.
func (pm *ProcessManager) GetProcessSockStats(event *fgsAPI.MsgIPv4EventUnix) *fgs.ProcessSockStats {
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

	fgsTuple := pm.getProcessTuple(event)
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
	fgsEvent.Socket.DestinationNames, _ = pm.getProcessIp(fgsProcess, fgsTuple.DestinationIp)

	if pm.enableCilium && fgsProcess != nil {
		destinationIP := reader.GetIP(event.Tuple.DAddr, event.Common.Op)
		fgsEvent.Socket.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
	}

	if pm.processCacheNeeded(fgsProcess) {
		pm.eventCache.add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}
	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}
	return fgsEvent
}

func (pm *ProcessManager) HandleIpMessage(msg *api.MsgIPv4EventUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_IPV4_TCPCONNECTRET,
		api.MSG_OP_IPV4_UDPCONNECT:
		cnct := pm.GetProcessConnect(msg)
		if cnct != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessConnect{ProcessConnect: cnct},
				NodeName: pm.nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	case api.MSG_OP_IPV4_TCPCLOSE,
		api.MSG_OP_IPV4_UDPCLOSE:
		c := pm.GetProcessClose(msg)
		if c != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessClose{ProcessClose: c},
				NodeName: pm.nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	case api.MSG_OP_IPV4_LISTEN:
		l := pm.GetProcessListen(msg)
		if l != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessListen{ProcessListen: l},
				NodeName: pm.nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	case api.MSG_OP_IPV4_ACCEPT:
		a := pm.GetProcessAccept(msg)
		if a != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessAccept{ProcessAccept: a},
				NodeName: pm.nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}

	case api.MSG_OP_IPV4_TCPSTATS, api.MSG_OP_IPV4_UDPSTATS:
		s := pm.GetProcessSockStats(msg)
		if s != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessSockstats{ProcessSockstats: s},
				NodeName: pm.nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}

	default:
		pm.log.WithField("message", msg).Warn("Unhandled event")
	}
	return res
}
