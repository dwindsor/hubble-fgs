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
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/eventcachemetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/cilium"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/grpc/exec"
	"github.com/isovalent/hubble-fgs/pkg/grpc/sockinfo"
	"github.com/isovalent/hubble-fgs/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/iperrormetrics"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
	reader "github.com/isovalent/hubble-fgs/pkg/reader/network"
	"github.com/isovalent/hubble-fgs/pkg/svcinfo"
)

var (
	nodeName = node.GetNodeNameForExport()
)

const (
	refNothing = iota
	refInc
	refDec
)

func SocketFlagsDnsEnabled(t uint32) bool {
	return (t & networkapi.SOCKFLAGS_TYPE_DNSREADY) != 0
}

type IpEventUnixMeta struct {
	Kube       processapi.MsgK8sUnix
	RefCntDone [2]bool
	Duration   time.Duration
}

type MsgIPEventUnix struct {
	IpEventUnixMeta
	Msg *networkapi.MsgIPEvent
}

type MsgIPWithStatsEventUnix struct {
	IpEventUnixMeta
	Msg *networkapi.MsgIPWithStatsEvent
}

type MsgUdpSeqCheckErrorEventUnix struct {
	Common         processapi.MsgCommon
	ProcessKey     processapi.MsgExecveKey
	Tuple          networkapi.MsgIPTuple
	Kube           processapi.MsgK8sUnix
	SockCookie     uint64
	ApplicationId  uint64
	AppSpecificId  uint64
	SeqNumExpected uint64
	SeqNumReceived uint64
}

func opToProtocol(op uint8) tetragon.SocketProtocol {
	return reader.MsgOpToProtocol(op)
}

// GetProcessConnect converts KprobeEvent from hubble-fgs to protobuf message.
func GetProcessConnect(event *MsgIPEventUnix) *tetragon.ProcessConnect {
	var fgsProcess, fgsParent *tetragon.Process
	var sourcePort, destinationPort *wrapperspb.UInt32Value

	if event.Msg.Tuple.SPort != 0 {
		sourcePort = &wrapperspb.UInt32Value{
			Value: uint32(networkapi.GetSport(event.Msg.Tuple.SPort)),
		}
	}
	if event.Msg.Tuple.DPort != 0 {
		destinationPort = &wrapperspb.UInt32Value{
			Value: uint32(networkapi.GetDport(event.Msg.Tuple.DPort, event.Msg.Common.Op)),
		}
	}

	process, parent := process.GetParentProcessInternal(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
	}
	if parent != nil {
		fgsParent = parent.UnsafeGetProcess()
	}

	destinationIP := networkapi.GetIP(event.Msg.Tuple.DAddr, event.Msg.Common.Op, event.Msg.Tuple.IPv6 != 0)
	fgsEvent := &tetragon.ProcessConnect{
		Process:         fgsProcess,
		Parent:          fgsParent,
		SourceIp:        networkapi.GetIP(event.Msg.Tuple.SAddr, event.Msg.Common.Op, event.Msg.Tuple.IPv6 != 0).String(),
		SourcePort:      sourcePort,
		DestinationIp:   destinationIP.String(),
		DestinationPort: destinationPort,
		SockCookie:      event.Msg.SockCookie,
		Protocol:        opToProtocol(event.Msg.Common.Op),
	}

	if event.Msg.SockCookie != 0 {
		fgsEvent.SockCookie = event.Msg.SockCookie
	}

	ec := eventcache.Get()
	fgsEvent.DestinationNames, _ = sockinfo.GetProcessIp(fgsProcess, destinationIP.String(), dns.Get(), cilium.GetCiliumState())

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if fgsProcess != nil {
		destinationIP := networkapi.GetIP(event.Msg.Tuple.DAddr, ops.MSG_OP_HTTP, event.Msg.Tuple.IPv6 != 0)
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
		fgsEvent.DestinationService = svcinfo.GetSvcInfoOfIp(destinationIP)
	}
	if ec != nil && (ec.Needed(fgsProcess) || (fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(nil, fgsEvent, event.Msg.Common.Ktime, event.Msg.ProcessKey.Ktime, event)
		return nil
	}
	if process != nil {
		process.RefInc()
	}
	if parent != nil {
		parent.RefInc()
	}
	return fgsEvent
}

func SocketFlagsToType(t uint32) string {
	if t&networkapi.SOCKFLAGS_TYPE_CONNECT != 0 {
		return "connect"
	} else if t&networkapi.SOCKFLAGS_TYPE_ACCEPT != 0 {
		return "accept"
	} else if t&networkapi.SOCKFLAGS_TYPE_LISTEN != 0 {
		return "listen"
	}
	return "unknown"
}

// GetProcessClose converts KprobeEvent from hubble-fgs to protobuf message.
func GetProcessClose(event *MsgIPWithStatsEventUnix) *tetragon.ProcessClose {
	var sourcePort, destinationPort *wrapperspb.UInt32Value
	var fgsParent, fgsProcess *tetragon.Process

	if event.Msg.Tuple.SPort != 0 {
		sourcePort = &wrapperspb.UInt32Value{
			Value: uint32(networkapi.GetSport(event.Msg.Tuple.SPort)),
		}
	}
	if event.Msg.Tuple.DPort != 0 {
		destinationPort = &wrapperspb.UInt32Value{
			Value: uint32(networkapi.GetDport(event.Msg.Tuple.DPort, event.Msg.Common.Op)),
		}
	}

	process, parent := process.GetParentProcessInternal(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
	}
	if parent != nil {
		fgsParent = parent.UnsafeGetProcess()
	}

	destinationIP := networkapi.GetIP(event.Msg.Tuple.DAddr, event.Msg.Common.Op, event.Msg.Tuple.IPv6 != 0)
	socketStats := reader.GetSocketStats(&event.Msg.SocketStats)

	fgsEvent := &tetragon.ProcessClose{
		Process:         fgsProcess,
		Parent:          fgsParent,
		SourceIp:        networkapi.GetIP(event.Msg.Tuple.SAddr, event.Msg.Common.Op, event.Msg.Tuple.IPv6 != 0).String(),
		SourcePort:      sourcePort,
		DestinationIp:   destinationIP.String(),
		DestinationPort: destinationPort,
		Stats:           socketStats,
		Protocol:        opToProtocol(event.Msg.Common.Op),
		SocketType:      SocketFlagsToType(event.Msg.SocketFlags),
		Duration:        durationpb.New(event.Duration),
	}

	if event.Msg.SockCookie != 0 {
		fgsEvent.SockCookie = event.Msg.SockCookie
	}

	dnsCache := dns.Get()
	ec := eventcache.Get()
	state := cilium.GetCiliumState()
	fgsEvent.DestinationNames, _ = sockinfo.GetProcessIp(fgsProcess, destinationIP.String(), dnsCache, state)

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if fgsProcess != nil {
		destinationIP := networkapi.GetIP(event.Msg.Tuple.DAddr, ops.MSG_OP_HTTP, event.Msg.Tuple.IPv6 != 0)
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
		fgsEvent.DestinationService = svcinfo.GetSvcInfoOfIp(destinationIP)
	}
	if ec != nil && (ec.Needed(fgsProcess) || (fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(nil, fgsEvent, event.Msg.Common.Ktime, event.Msg.ProcessKey.Ktime, event)
		return nil
	}
	if process != nil {
		process.RefDec()
	}
	if parent != nil {
		parent.RefDec()
	}
	return fgsEvent
}

// GetProcessListen returns Listen protobuf message for a given process, including the ancestor list.
func GetProcessListen(
	event *MsgIPEventUnix,
) *tetragon.ProcessListen {
	var fgsProcess, fgsParent *tetragon.Process
	var port *wrapperspb.UInt32Value

	if event.Msg.Tuple.SPort != 0 {
		port = &wrapperspb.UInt32Value{
			Value: uint32(networkapi.GetSport(event.Msg.Tuple.SPort)),
		}
	}
	process, parent := process.GetParentProcessInternal(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if process != nil {
		fgsProcess = process.UnsafeGetProcess()
	} else {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
		}
	}
	if parent != nil {
		fgsParent = parent.UnsafeGetProcess()
	}
	fgsEvent := &tetragon.ProcessListen{
		Process:  fgsProcess,
		Parent:   fgsParent,
		Ip:       networkapi.GetIP(event.Msg.Tuple.SAddr, 0, event.Msg.Tuple.IPv6 != 0).String(),
		Port:     port,
		Protocol: opToProtocol(event.Msg.Common.Op),
	}

	if event.Msg.SockCookie != 0 {
		fgsEvent.SockCookie = event.Msg.SockCookie
	}

	ec := eventcache.Get()
	if ec != nil && (ec.Needed(fgsProcess) || (fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(nil, fgsEvent, event.Msg.Common.Ktime, event.Msg.ProcessKey.Ktime, event)
		return nil
	}

	if process != nil {
		process.RefInc()
	}
	if parent != nil {
		parent.RefInc()
	}

	return fgsEvent
}

// GetProcessAccept converts KprobeEvent from hubble-fgs to protobuf message.
func GetProcessAccept(event *MsgIPEventUnix) *tetragon.ProcessAccept {
	var sourcePort, destinationPort *wrapperspb.UInt32Value
	var fgsParent, fgsProcess *tetragon.Process

	if event.Msg.Tuple.SPort != 0 {
		sourcePort = &wrapperspb.UInt32Value{
			Value: uint32(networkapi.GetSport(event.Msg.Tuple.SPort)),
		}
	}
	if event.Msg.Tuple.DPort != 0 {
		destinationPort = &wrapperspb.UInt32Value{
			Value: uint32(networkapi.GetDport(event.Msg.Tuple.DPort, event.Msg.Common.Op)),
		}
	}

	process, parent := process.GetParentProcessInternal(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
	}
	if parent != nil {
		fgsParent = parent.UnsafeGetProcess()
	}

	destinationIP := networkapi.GetIP(event.Msg.Tuple.DAddr, event.Msg.Common.Op, event.Msg.Tuple.IPv6 != 0)
	fgsEvent := &tetragon.ProcessAccept{
		Process:         fgsProcess,
		Parent:          fgsParent,
		SourceIp:        networkapi.GetIP(event.Msg.Tuple.SAddr, event.Msg.Common.Op, event.Msg.Tuple.IPv6 != 0).String(),
		SourcePort:      sourcePort,
		DestinationIp:   destinationIP.String(),
		DestinationPort: destinationPort,

		Protocol: opToProtocol(event.Msg.Common.Op),
	}

	if event.Msg.SockCookie != 0 {
		fgsEvent.SockCookie = event.Msg.SockCookie
	}

	dnsCache := dns.Get()
	ec := eventcache.Get()
	state := cilium.GetCiliumState()
	fgsEvent.DestinationNames, _ = sockinfo.GetProcessIp(fgsProcess, destinationIP.String(), dnsCache, state)

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if fgsProcess != nil {
		destinationIP := networkapi.GetIP(event.Msg.Tuple.DAddr, ops.MSG_OP_HTTP, event.Msg.Tuple.IPv6 != 0)
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
		fgsEvent.DestinationService = svcinfo.GetSvcInfoOfIp(destinationIP)
	}

	if ec != nil && (ec.Needed(fgsProcess) || (fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(nil, fgsEvent, event.Msg.Common.Ktime, event.Msg.ProcessKey.Ktime, event)
		return nil
	}
	if process != nil {
		process.RefInc()
	}
	if parent != nil {
		parent.RefInc()
	}

	return fgsEvent
}

// GetProcessRawsockCreate converts KprobeEvent from hubble-fgs to protobuf message.
func GetProcessRawsockCreate(event *MsgIPEventUnix) *tetragon.ProcessRawsockCreate {
	var fgsParent, fgsProcess *tetragon.Process

	process, parent := process.GetParentProcessInternal(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
	}
	if parent != nil {
		fgsParent = parent.UnsafeGetProcess()
	}

	fgsEvent := &tetragon.ProcessRawsockCreate{
		Process: fgsProcess,
		Parent:  fgsParent,
	}

	if event.Msg.SockCookie != 0 {
		fgsEvent.SockCookie = event.Msg.SockCookie
	}

	ec := eventcache.Get()
	if ec != nil && (ec.Needed(fgsProcess) || (fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(nil, fgsEvent, event.Msg.Common.Ktime, event.Msg.ProcessKey.Ktime, event)
		return nil
	}
	if process != nil {
		process.RefInc()
	}
	if parent != nil {
		parent.RefInc()
	}

	eventmetrics.HandleRawsockCreateEvent(fgsEvent)

	return fgsEvent
}

// GetProcessRawsockCreate converts KprobeEvent from hubble-fgs to protobuf message.
func GetProcessRawsockClose(event *MsgIPEventUnix) *tetragon.ProcessRawsockClose {
	var fgsParent, fgsProcess *tetragon.Process

	process, parent := process.GetParentProcessInternal(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
	}
	if parent != nil {
		fgsParent = parent.UnsafeGetProcess()
	}

	fgsEvent := &tetragon.ProcessRawsockClose{
		Process:  fgsProcess,
		Parent:   fgsParent,
		Duration: durationpb.New(event.Duration),
	}

	if event.Msg.SockCookie != 0 {
		fgsEvent.SockCookie = event.Msg.SockCookie
	}

	ec := eventcache.Get()
	if ec != nil && (ec.Needed(fgsProcess) || (fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(nil, fgsEvent, event.Msg.Common.Ktime, event.Msg.ProcessKey.Ktime, event)
		return nil
	}
	if process != nil {
		process.RefDec()
	}
	if parent != nil {
		parent.RefDec()
	}

	eventmetrics.HandleRawsockCloseEvent(fgsEvent)

	return fgsEvent
}

// Allow lower layers to call up the stack to push stats into metrics.
func CreateProcessSockStats(event *MsgIPWithStatsEventUnix, cache bool) *tetragon.ProcessSockStats {
	var fgsParent, fgsProcess *tetragon.Process

	process, parent := process.GetParentProcessInternal(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
	}
	if parent != nil {
		fgsParent = parent.UnsafeGetProcess()
	}

	fgsTuple := sockinfo.GetTuple(&event.Msg.Tuple, event.Msg.SockCookie, event.Msg.Common.Op)
	fgsSocketStats := reader.GetSocketStats(&event.Msg.SocketStats)

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

	if cache && ec != nil && (ec.Needed(fgsProcess) || (fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(nil, fgsEvent, event.Msg.Common.Ktime, event.Msg.ProcessKey.Ktime, event)
		return nil
	}
	eventmetrics.HandleSocketEvent(fgsEvent)
	return fgsEvent

}

// GetProcessSockStats converts KprobeEvent from hubble-fgs to protobuf message.
func GetProcessSockStats(event *MsgIPWithStatsEventUnix) *tetragon.ProcessSockStats {
	return CreateProcessSockStats(event, true)
}

func ipEventRetryInternal(op uint8, refCntDone *[2]bool, ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	p := ev.GetProcess()
	process, parent := process.GetParentProcessInternal(p.Pid.Value, timestamp)
	var err error

	refAction := refNothing
	switch op {
	case ops.MSG_OP_TCPCONNECTRET,
		ops.MSG_OP_UDPCONNECT,
		ops.MSG_OP_LISTEN,
		ops.MSG_OP_UDPLISTEN,
		ops.MSG_OP_ACCEPT,
		ops.MSG_OP_RAWSOCK_CREATE:
		refAction = refInc
	case ops.MSG_OP_TCPCLOSE,
		ops.MSG_OP_UDPCLOSE,
		ops.MSG_OP_RAWSOCK_CLOSE:
		refAction = refDec
	}

	if parent != nil {
		ev.SetParent(parent.UnsafeGetProcess())
		if !refCntDone[exec.ParentRefCnt] {
			if refAction == refInc {
				parent.RefInc()
			} else if refAction == refDec {
				parent.RefDec()
			}
			refCntDone[exec.ParentRefCnt] = true
		}
	} else {
		eventcachemetrics.EventCacheRetries(eventcachemetrics.ParentInfo).Inc()
		err = eventcache.ErrFailedToGetParentInfo
	}

	if process != nil {
		if !refCntDone[exec.ProcessRefCnt] {
			if refAction == refInc {
				process.RefInc()
			} else if refAction == refDec {
				process.RefDec()
			}
			refCntDone[exec.ProcessRefCnt] = true
		}
	} else {
		eventcachemetrics.EventCacheRetries(eventcachemetrics.ProcessInfo).Inc()
		err = eventcache.ErrFailedToGetProcessInfo
	}

	if err == nil {
		return process, err
	}
	return nil, err
}

func (msg *MsgIPEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	return ipEventRetryInternal(msg.Msg.Common.Op, &msg.RefCntDone, ev, timestamp)
}

func (msg *MsgIPWithStatsEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	return ipEventRetryInternal(msg.Msg.Common.Op, &msg.RefCntDone, ev, timestamp)
}

func (msg *MsgIPEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	p := internal.UnsafeGetProcess()
	if option.Config.EnableK8s && p.Pod == nil {
		eventcachemetrics.EventCacheRetries(eventcachemetrics.PodInfo).Inc()
		return eventcache.ErrFailedToGetPodInfo
	}

	ev.SetProcess(internal.UnsafeGetProcess())

	return nil
}

func (msg *MsgIPWithStatsEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	p := internal.UnsafeGetProcess()
	if option.Config.EnableK8s && p.Pod == nil {
		eventcachemetrics.EventCacheRetries(eventcachemetrics.PodInfo).Inc()
		return eventcache.ErrFailedToGetPodInfo
	}

	ev.SetProcess(internal.UnsafeGetProcess())

	// For SockStats events we need to account for metrics skipped
	// by original handling of event.
	switch msg.Msg.Common.Op {
	case ops.MSG_OP_TCPSTATS, ops.MSG_OP_UDPSTATS:
		CreateProcessSockStats(msg, false)
	}

	return nil
}

func (msg *MsgIPEventUnix) Notify() bool {
	return true
}

func (msg *MsgIPWithStatsEventUnix) Notify() bool {
	return true
}

func (msg *MsgIPEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	msg.RefCntDone = [2]bool{false, false}
	switch msg.Msg.Common.Op {
	case ops.MSG_OP_TCPCONNECTRET,
		ops.MSG_OP_UDPCONNECT:
		cnct := GetProcessConnect(msg)
		if cnct != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessConnect{ProcessConnect: cnct},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Msg.Common.Ktime),
			}
		}
	case ops.MSG_OP_LISTEN,
		ops.MSG_OP_UDPLISTEN:
		l := GetProcessListen(msg)
		if l != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessListen{ProcessListen: l},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Msg.Common.Ktime),
			}
		}
	case ops.MSG_OP_ACCEPT:
		a := GetProcessAccept(msg)
		if a != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessAccept{ProcessAccept: a},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Msg.Common.Ktime),
			}
		}
	case ops.MSG_OP_RAWSOCK_CREATE:
		r := GetProcessRawsockCreate(msg)
		if r != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessRawsockCreate{ProcessRawsockCreate: r},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Msg.Common.Ktime),
			}
		}
	case ops.MSG_OP_RAWSOCK_CLOSE:
		r := GetProcessRawsockClose(msg)
		if r != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessRawsockClose{ProcessRawsockClose: r},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Msg.Common.Ktime),
			}
		}
	case ops.MSG_OP_IP_ERROR:
		s := GetProcessIPError(msg)
		if s != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessIpError{ProcessIpError: s},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Msg.Common.Ktime),
			}
		}

	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleIpMessage: Unhandled event")
	}
	return res
}

func (msg *MsgIPWithStatsEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	msg.RefCntDone = [2]bool{false, false}
	switch msg.Msg.Common.Op {
	case ops.MSG_OP_TCPCLOSE,
		ops.MSG_OP_UDPCLOSE:
		c := GetProcessClose(msg)
		if c != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessClose{ProcessClose: c},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Msg.Common.Ktime),
			}
		}
	case ops.MSG_OP_TCPSTATS, ops.MSG_OP_UDPSTATS:
		s := GetProcessSockStats(msg)
		if s != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessSockStats{ProcessSockStats: s},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Msg.Common.Ktime),
			}
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleIpMessage: Unhandled event")
	}
	return res
}

func (msg *MsgIPEventUnix) Cast(_ interface{}) notify.Message {
	return &MsgIPEventUnix{}
}

func (msg *MsgIPWithStatsEventUnix) Cast(_ interface{}) notify.Message {
	return &MsgIPWithStatsEventUnix{}
}

func GetProcessIPError(event *MsgIPEventUnix) *tetragon.ProcessIpError {
	var fgsParent, fgsProcess *tetragon.Process

	process, parent := process.GetParentProcessInternal(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
	}
	if parent != nil {
		fgsParent = parent.UnsafeGetProcess()
	}

	sourceIP := networkapi.GetIP(event.Msg.Tuple.SAddr, event.Msg.Common.Op, event.Msg.Tuple.IPv6 != 0)
	destinationIP := networkapi.GetIP(event.Msg.Tuple.DAddr, event.Msg.Common.Op, event.Msg.Tuple.IPv6 != 0)

	var version string
	if event.Msg.Tuple.IPv6 == 0 {
		version = networkapi.IPv4Family
	} else {
		version = networkapi.IPv6Family
	}

	var details iperrormetrics.Config
	var ok bool

	// Lower 32 bits is error code, upper 32 bits is data if required.
	errorCode := event.Msg.Return & 0xffffffff
	if details, ok = iperrormetrics.IpErrorToString[iperrormetrics.IpError(errorCode)]; ok {
		// Populate the metrics here before we parameterize with any data, otherwise we
		// risk cardinality exploding
		iperrormetrics.ProcessIpErrors(details.Msg, version).Inc()
		if errorCode == 5 {
			details.Msg = details.Msg + fmt.Sprintf(": %d", event.Msg.Return>>32)
		}
	} else {
		details = iperrormetrics.Config{Msg: "Unknown error", Protocol: iperrormetrics.Unknown}
	}

	var send string
	switch event.Msg.Tuple.Send {
	case 1:
		send = "Send"
	case 2:
		send = "Receive"
	}

	fgsEvent := &tetragon.ProcessIpError{
		Process:       fgsProcess,
		Parent:        fgsParent,
		SourceIp:      sourceIP.String(),
		DestinationIp: destinationIP.String(),
		Version:       version,
		SockCookie:    event.Msg.SockCookie,
		Details:       details.Msg,
		Send:          send,
		VersionByte:   uint64(event.Msg.Tuple.VersionByte),
		Data:          event.Msg.CreateTime, // We use the CreateTime field to pass error data
	}

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if fgsProcess != nil {
		destinationIP := networkapi.GetIP(event.Msg.Tuple.DAddr, event.Msg.Common.Op, event.Msg.Tuple.IPv6 != 0)
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
		fgsEvent.DestinationService = svcinfo.GetSvcInfoOfIp(destinationIP)
	}

	ec := eventcache.Get()
	if ec != nil && (ec.Needed(fgsProcess) || (fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(nil, fgsEvent, event.Msg.Common.Ktime, event.Msg.ProcessKey.Ktime, event)
		return nil
	}

	if iperrormetrics.ProtoConsoleEnabled(details.Protocol) {
		// Report error to console.
		// This sounds dubious but is actually quite sensible. In a perfect system
		// where the code is robust and handles all situations, no error events will
		// be generated so no errors will be reported to the console. If, however,
		// issues cause errors to be generated, then we really need to know about
		// them and console messages are a great way to get attention while preserving
		// some context relative to other logger console messages. We will not ship a
		// release that has produced lots of error messages in dogfooding, so this
		// approach should focus efforts on removing the bugs that cause these errors.
		//
		// Still, if necessary, a switch statement can be used to choose which error
		// types should be reported to the console or not.
		logger.GetLogger().WithFields(logrus.Fields{
			"Process":     fgsProcess,
			"Tuple":       event.Msg.Tuple.String(),
			"Cookie":      event.Msg.SockCookie,
			"IpVersion":   version,
			"Details":     details.Msg,
			"Send":        send,
			"VersionByte": uint64(event.Msg.Tuple.VersionByte),
			"Data":        event.Msg.CreateTime,
		}).Warn("IP error. This is a bug, please report it to Tetragon developers.")
	}

	return fgsEvent
}
