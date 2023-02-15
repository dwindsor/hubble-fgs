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
	"github.com/cilium/tetragon/pkg/cilium"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/grpc/exec"
	"github.com/isovalent/hubble-fgs/pkg/grpc/sockinfo"
	"github.com/isovalent/hubble-fgs/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/iperrormetrics"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
	reader "github.com/isovalent/hubble-fgs/pkg/reader/network"
)

var (
	nodeName = node.GetNodeNameForExport()
)

const (
	refNothing = iota
	refInc
	refDec
)

var ipErrorToString = []string{
	0:  "Header error",
	1:  "No heap available",
	2:  "Read IPv6 next failed (probe)",
	3:  "Read IPv6 next failed (skb_load)",
	4:  "Read IPv6 next failed (skb)",
	5:  "Unknown IPv6 extension",
	6:  "Too many IPv6 extensions",
	7:  "UDP stack no cookie",
	8:  "UDP stack read version failed",
	9:  "UDP stack read IP header failed",
	10: "UDP stack read UDP header failed",
	11: "UDP stack no payload offset",
	12: "UDP stack invalid IP version",
	13: "UDP stack burst no process",
	14: "UDP stack burst no PID",
	15: "UDP stack read payload failed",
	16: "UDP send no socket info",
	17: "UDP send no cookie",
	18: "UDP recv no cookie",
	19: "UDP recv read IP header failed",
	20: "UDP recv read UDP header failed",
	21: "UDP recv invalid IP version",
	22: "UDP sock create no cookie",
	23: "UDP sock release no cookie",
	24: "UDP failed to read IP option",
	25: "UDP retprobe add failed",
	26: "UDP retprobe delete failed",
	27: "UDP retprobe key already exists",
}

const ipErrorMax = 27

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
	RefCntDone  [2]bool
	Rtt         networkapi.Histogram
	Duration    time.Duration
}

func msgToProtocol(event *MsgIPEventUnix) tetragon.SocketProtocol {
	return reader.MsgOpToProtocol(event.Common.Op)
}

// GetProcessConnect converts KprobeEvent from hubble-fgs to protobuf message.
func GetProcessConnect(event *MsgIPEventUnix) *tetragon.ProcessConnect {
	var fgsProcess, fgsParent *tetragon.Process
	var sourcePort, destinationPort *wrapperspb.UInt32Value

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
	}
	if parent != nil {
		fgsParent = parent.UnsafeGetProcess()
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
	fgsEvent.DestinationNames, _ = sockinfo.GetProcessIp(fgsProcess, destinationIP.String(), dns.Get(), cilium.GetCiliumState())

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if option.Config.EnableCilium && fgsProcess != nil {
		destinationIP := reader.GetIP(event.Tuple.DAddr, ops.MSG_OP_HTTP, event.Tuple.IPv6 != 0)
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
	}
	if ec != nil && (ec.Needed(fgsProcess) || (fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(nil, fgsEvent, event.Common.Ktime, event.ProcessKey.Ktime, event)
		return nil
	}
	if process != nil {
		process.RefInc()
		fgsEvent.Process = process.GetProcessCopy()
	}
	if parent != nil {
		parent.RefInc()
		fgsEvent.Parent = parent.GetProcessCopy()
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
	}
	if parent != nil {
		fgsParent = parent.UnsafeGetProcess()
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
		Duration:        durationpb.New(event.Duration),
	}

	if event.SockCookie != 0 {
		fgsEvent.SockCookie = event.SockCookie
	}

	dnsCache := dns.Get()
	ec := eventcache.Get()
	state := cilium.GetCiliumState()
	fgsEvent.DestinationNames, _ = sockinfo.GetProcessIp(fgsProcess, destinationIP.String(), dnsCache, state)

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if option.Config.EnableCilium && fgsProcess != nil {
		destinationIP := reader.GetIP(event.Tuple.DAddr, ops.MSG_OP_HTTP, event.Tuple.IPv6 != 0)
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
	}
	if ec != nil && (ec.Needed(fgsProcess) || (fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(nil, fgsEvent, event.Common.Ktime, event.ProcessKey.Ktime, event)
		return nil
	}
	if process != nil {
		process.RefDec()
		fgsEvent.Process = process.GetProcessCopy()
	}
	if parent != nil {
		parent.RefDec()
		fgsEvent.Parent = parent.GetProcessCopy()
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
		fgsProcess = process.UnsafeGetProcess()
	} else {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	}
	if parent != nil {
		fgsParent = parent.UnsafeGetProcess()
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
	if ec != nil && (ec.Needed(fgsProcess) || (fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(nil, fgsEvent, event.Common.Ktime, event.ProcessKey.Ktime, event)
		return nil
	}

	if process != nil {
		process.RefInc()
		fgsEvent.Process = process.GetProcessCopy()
	}
	if parent != nil {
		parent.RefInc()
		fgsEvent.Parent = parent.GetProcessCopy()
	}

	return fgsEvent
}

// GetProcessAccept converts KprobeEvent from hubble-fgs to protobuf message.
func GetProcessAccept(event *MsgIPEventUnix) *tetragon.ProcessAccept {
	var sourcePort, destinationPort *wrapperspb.UInt32Value
	var fgsParent, fgsProcess *tetragon.Process

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
	}
	if parent != nil {
		fgsParent = parent.UnsafeGetProcess()
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
	fgsEvent.DestinationNames, _ = sockinfo.GetProcessIp(fgsProcess, destinationIP.String(), dnsCache, state)

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if option.Config.EnableCilium && fgsProcess != nil {
		destinationIP := reader.GetIP(event.Tuple.DAddr, ops.MSG_OP_HTTP, event.Tuple.IPv6 != 0)
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
	}

	if ec != nil && (ec.Needed(fgsProcess) || (fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(nil, fgsEvent, event.Common.Ktime, event.ProcessKey.Ktime, event)
		return nil
	}
	if process != nil {
		process.RefInc()
		fgsEvent.Process = process.GetProcessCopy()
	}
	if parent != nil {
		parent.RefInc()
		fgsEvent.Parent = parent.GetProcessCopy()
	}

	return fgsEvent
}

func createProcessSockStats(event *MsgIPEventUnix, cache bool) *tetragon.ProcessSockStats {
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
	if parent != nil {
		fgsParent = parent.UnsafeGetProcess()
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

	if cache && ec != nil && (ec.Needed(fgsProcess) || (fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(nil, fgsEvent, event.Common.Ktime, event.ProcessKey.Ktime, event)
		return nil
	}
	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}
	if parent != nil {
		fgsEvent.Parent = parent.GetProcessCopy()
	}
	eventmetrics.HandleSocketEvent(fgsEvent)
	return fgsEvent

}

// GetProcessSockStats converts KprobeEvent from hubble-fgs to protobuf message.
func GetProcessSockStats(event *MsgIPEventUnix) *tetragon.ProcessSockStats {
	return createProcessSockStats(event, true)
}

func (msg *MsgIPEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	p := ev.GetProcess()
	process, parent := process.GetParentProcessInternal(p.Pid.Value, timestamp)
	var err error

	refAction := refNothing
	switch msg.Common.Op {
	case ops.MSG_OP_TCPCONNECTRET,
		ops.MSG_OP_UDPCONNECT,
		ops.MSG_OP_LISTEN,
		ops.MSG_OP_ACCEPT:
		refAction = refInc
	case ops.MSG_OP_TCPCLOSE,
		ops.MSG_OP_UDPCLOSE:
		refAction = refDec
	}

	if parent != nil {
		ev.SetParent(parent.GetProcessCopy())
		if !msg.RefCntDone[exec.ParentRefCnt] {
			if refAction == refInc {
				parent.RefInc()
			} else if refAction == refDec {
				parent.RefDec()
			}
			msg.RefCntDone[exec.ParentRefCnt] = true
		}
	} else {
		errormetrics.ErrorTotalInc(errormetrics.EventCacheParentInfoFailed)
		err = eventcache.ErrFailedToGetParentInfo
	}

	if process != nil {
		if !msg.RefCntDone[exec.ProcessRefCnt] {
			if refAction == refInc {
				process.RefInc()
			} else if refAction == refDec {
				process.RefDec()
			}
			msg.RefCntDone[exec.ProcessRefCnt] = true
		}
	} else {
		errormetrics.ErrorTotalInc(errormetrics.EventCacheProcessInfoFailed)
		err = eventcache.ErrFailedToGetProcessInfo
	}

	if err == nil {
		return process, err
	}
	return nil, err
}

func (msg *MsgIPEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	p := internal.UnsafeGetProcess()
	if option.Config.EnableK8s && p.Pod == nil {
		errormetrics.ErrorTotalInc(errormetrics.EventCachePodInfoRetryFailed)
		return eventcache.ErrFailedToGetPodInfo
	}

	ev.SetProcess(internal.GetProcessCopy())

	// For SockStats events we need to account for metrics skipped
	// by original handling of event.
	switch msg.Common.Op {
	case ops.MSG_OP_TCPSTATS, ops.MSG_OP_UDPSTATS:
		createProcessSockStats(msg, false)
	}

	return nil
}

func (msg *MsgIPEventUnix) Notify() bool {
	return true
}

func (msg *MsgIPEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	msg.RefCntDone = [2]bool{false, false}
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

func (msg *MsgIPEventUnix) Cast(o interface{}) notify.Message {
	return &MsgIPEventUnix{}
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
	if parent != nil {
		fgsParent = parent.UnsafeGetProcess()
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
	errorCode := event.Return & 0xffffffff
	if errorCode <= ipErrorMax {
		details = ipErrorToString[errorCode]
		// Populate the metrics here before we parameterize with any data, otherwise we
		// risk cardinality exploding
		iperrormetrics.ProcessIpErrors(details).Inc()
		if errorCode == 5 {
			details = details + fmt.Sprintf(": %d", event.Return>>32)
		}
	} else {
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
	if ec != nil && (ec.Needed(fgsProcess) || (fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(nil, fgsEvent, event.Common.Ktime, event.ProcessKey.Ktime, event)
		return nil
	}
	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}
	if parent != nil {
		fgsEvent.Parent = parent.GetProcessCopy()
	}
	eventmetrics.HandleIpErrorEvent(fgsEvent)
	return fgsEvent
}
