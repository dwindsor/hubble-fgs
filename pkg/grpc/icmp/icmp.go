//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package icmp

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/cilium"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/grpc/sockinfo"
	"github.com/isovalent/hubble-fgs/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
	reader "github.com/isovalent/hubble-fgs/pkg/reader/network"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	nodeName = node.GetNodeNameForExport()
)

type MsgICMPEventUnix struct {
	Common     processapi.MsgCommon
	Tuple      networkapi.MsgIPTuple
	Kube       processapi.MsgK8sUnix
	ProcessKey processapi.MsgExecveKey
	SockCookie uint64
	IcmpData   networkapi.MsgICMPData
}

func msgToProtocol(event *MsgICMPEventUnix) tetragon.SocketProtocol {
	return reader.MsgOpToProtocol(event.Common.Op)
}

func (msg *MsgICMPEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	p := ev.GetProcess()
	return eventcache.HandleGenericInternal(ev, p.Pid.Value, nil, timestamp)
}

func (msg *MsgICMPEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	p := internal.UnsafeGetProcess()
	if option.Config.EnableK8s && p.Pod == nil {
		errormetrics.ErrorTotalInc(errormetrics.EventCachePodInfoRetryFailed)
		return eventcache.ErrFailedToGetPodInfo
	}

	ev.SetProcess(internal.UnsafeGetProcess())
	GetProcessIcmp(msg)

	return nil
}

func (msg *MsgICMPEventUnix) Notify() bool {
	return true
}

func (msg *MsgICMPEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	b := GetProcessIcmp(msg)
	if b != nil {
		res = &tetragon.GetEventsResponse{
			Event:    &tetragon.GetEventsResponse_ProcessIcmp{ProcessIcmp: b},
			NodeName: nodeName,
			Time:     ktime.ToProto(msg.Common.Ktime),
		}
	}
	return res
}

func (msg *MsgICMPEventUnix) Cast(_ interface{}) notify.Message {
	return &MsgICMPEventUnix{}
}

func icmpTypeAndCodeToStrings(icmpType uint8, icmpCode uint8) (string, string) {
	typeStr := fmt.Sprintf("Unknown (%d)", icmpType)
	switch icmpType {
	case 0:
		typeStr = "Echo Reply"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 3:
		typeStr = "Destination Unreachable"
		switch icmpCode {
		case 0:
			return typeStr, "net unreachable"
		case 1:
			return typeStr, "host unreachable"
		case 2:
			return typeStr, "protocol unreachable"
		case 3:
			return typeStr, "port unreachable"
		case 4:
			return typeStr, "fragmentation needed and DF set"
		case 5:
			return typeStr, "source route failed"
		}
	case 4:
		typeStr = "Source Quench"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 5:
		typeStr = "Redirect"
		switch icmpCode {
		case 0:
			return typeStr, "Redirect datagrams for the Network"
		case 1:
			return typeStr, "Redirect datagrams for the Host"
		case 2:
			return typeStr, "Redirect datagrams for the Type of Service and Network"
		case 3:
			return typeStr, "Redirect datagrams for the Type of Service and Host"
		}
	case 8:
		typeStr = "Echo"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 11:
		typeStr = "Time Exceeded"
		switch icmpCode {
		case 0:
			return typeStr, "time to live exceeded in transit"
		case 1:
			return typeStr, "fragment reassembly time exceeded"
		}
	case 12:
		typeStr = "Parameter Problem"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 13:
		typeStr = "Timestamp"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 14:
		typeStr = "Timestamp Reply"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 15:
		typeStr = "Information Request"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 16:
		typeStr = "Information Reply"
		if icmpCode == 0 {
			return typeStr, ""
		}
	}
	return typeStr, fmt.Sprintf("unknown (%d)", icmpCode)
}

func icmpV6TypeAndCodeToStrings(icmpType uint8, icmpCode uint8) (string, string) {
	typeStr := fmt.Sprintf("Unknown (%d)", icmpType)
	switch icmpType {
	case 1:
		typeStr = "Destination unreachable"
		switch icmpCode {
		case 0:
			return typeStr, "no route to destination"
		case 1:
			return typeStr, "communication with destination administratively prohibited"
		case 2:
			return typeStr, "beyond scope of source address"
		case 3:
			return typeStr, "address unreachable"
		case 4:
			return typeStr, "port unreachable"
		case 5:
			return typeStr, "source address failed ingress/egress policy"
		case 6:
			return typeStr, "reject route to destination"
		case 7:
			return typeStr, "Error in Source Routing Header"
		}
	case 2:
		typeStr = "Packet too big"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 3:
		typeStr = "Time exceeded"
		switch icmpCode {
		case 0:
			return typeStr, "hop limit exceeded in transit"
		case 1:
			return typeStr, "fragment reassembly time exceeded"
		}
	case 4:
		typeStr = "Parameter problem"
		switch icmpCode {
		case 0:
			return typeStr, "erroneous header field encountered"
		case 1:
			return typeStr, "unrecognized Next Header type encountered"
		case 2:
			return typeStr, "unrecognized IPv6 option encountered"
		}
	case 128:
		typeStr = "Echo Request"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 129:
		typeStr = "Echo Reply"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 130:
		typeStr = "Multicast Listener Query (MLD)"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 131:
		typeStr = "Multicast Listener Report (MLD)"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 132:
		typeStr = "Multicast Listener Done (MLD)"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 133:
		typeStr = "Router Solicitation (NDP)"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 134:
		typeStr = "Router Advertisement (NDP)"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 135:
		typeStr = "Neighbor Solicitation (NDP)"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 136:
		typeStr = "Neighbor Advertisement (NDP)"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 137:
		typeStr = "Redirect Message (NDP)"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 138:
		typeStr = "Router Renumbering"
		switch icmpCode {
		case 0:
			return typeStr, "Router Renumbering Command"
		case 1:
			return typeStr, "Router Renumbering Result"
		case 255:
			return typeStr, "Sequence Number Reset"
		}
	case 139:
		typeStr = "ICMP Node Information Query"
		switch icmpCode {
		case 0:
			return typeStr, "The Data field contains an IPv6 address which is the Subject of this Query."
		case 1:
			return typeStr, "The Data field contains a name which is the Subject of this Query, or is empty, as in the case of a NOOP."
		case 2:
			return typeStr, "The Data field contains an IPv4 address which is the Subject of this Query."
		}
	case 140:
		typeStr = "ICMP Node Information Response"
		switch icmpCode {
		case 0:
			return typeStr, "A successful reply. The Reply Data field may or may not be empty."
		case 1:
			return typeStr, "The Responder refuses to supply the answer. The Reply Data field will be empty."
		case 2:
			return typeStr, "The Qtype of the Query is unknown to the Responder. The Reply Data field will be empty."
		}
	case 141:
		typeStr = "Inverse Neighbor Discovery Solicitation Message"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 142:
		typeStr = "Inverse Neighbor Discovery Advertisement Message"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 143:
		typeStr = "Multicast Listener Discovery (MLDv2) reports"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 144:
		typeStr = "Home Agent Address Discovery Request Message"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 145:
		typeStr = "Home Agent Address Discovery Reply Message"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 146:
		typeStr = "Mobile Prefix Solicitation"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 147:
		typeStr = "Mobile Prefix Advertisement"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 148:
		typeStr = "Certification Path Solicitation (SEND)"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 149:
		typeStr = "Certification Path Advertisement (SEND)"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 151:
		typeStr = "Multicast Router Advertisement (MRD)"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 152:
		typeStr = "Multicast Router Solicitation (MRD)"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 153:
		typeStr = "Multicast Router Termination (MRD)"
		if icmpCode == 0 {
			return typeStr, ""
		}
	case 155:
		typeStr = "RPL Control Message"
		if icmpCode == 0 {
			return typeStr, ""
		}

	}
	return typeStr, fmt.Sprintf("unknown (%d)", icmpCode)
}

func icmpDecodeIdAndSeq(icmpType uint8, icmpData [4]uint8) (uint32, uint32) {
	switch icmpType {
	case 0, 8, 13, 14, 15, 16:
		id := binary.BigEndian.Uint16(icmpData[0:2])
		seqNum := binary.BigEndian.Uint16(icmpData[2:4])
		return uint32(id), uint32(seqNum)
	}
	return 0, 0
}

func icmpV6DecodeIdAndSeq(icmpType uint8, icmpData [4]uint8) (uint32, uint32) {
	switch icmpType {
	case 128, 129:
		id := binary.BigEndian.Uint16(icmpData[0:2])
		seqNum := binary.BigEndian.Uint16(icmpData[2:4])
		return uint32(id), uint32(seqNum)
	}
	return 0, 0
}

// GetProcessIcmp returns Icmp protobuf message for a given process, including the ancestor list.
func GetProcessIcmp(
	event *MsgICMPEventUnix,
) *tetragon.ProcessIcmp {
	var fgsProcess, fgsParent *tetragon.Process

	var icmpType, icmpCode string
	var icmpId, icmpSeqNum uint32

	if event.Tuple.IPv6 == 0 {
		icmpType, icmpCode = icmpTypeAndCodeToStrings(event.IcmpData.IcmpType, event.IcmpData.IcmpCode)
		icmpId, icmpSeqNum = icmpDecodeIdAndSeq(event.IcmpData.IcmpType, event.IcmpData.IcmpData)
	} else {
		icmpType, icmpCode = icmpV6TypeAndCodeToStrings(event.IcmpData.IcmpType, event.IcmpData.IcmpCode)
		icmpId, icmpSeqNum = icmpV6DecodeIdAndSeq(event.IcmpData.IcmpType, event.IcmpData.IcmpData)
	}
	destinationIp := networkapi.GetIP(event.Tuple.DAddr, 0, event.Tuple.IPv6 != 0)

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
	direction := "ingress"
	if event.Tuple.Send == 1 {
		direction = "egress"
	}
	fgsEvent := &tetragon.ProcessIcmp{
		Process:        fgsProcess,
		Parent:         fgsParent,
		SourceIp:       networkapi.GetIP(event.Tuple.SAddr, 0, event.Tuple.IPv6 != 0).String(),
		DestinationIp:  destinationIp.String(),
		IcmpType:       icmpType,
		IcmpCode:       icmpCode,
		IcmpTypeValue:  uint32(event.IcmpData.IcmpType),
		IcmpCodeValue:  uint32(event.IcmpData.IcmpCode),
		Identifier:     icmpId,
		SequenceNumber: icmpSeqNum,
		IcmpDataLen:    uint32(event.IcmpData.IcmpLen),
		Direction:      direction,
		Protocol:       msgToProtocol(event),
	}

	if event.SockCookie != 0 {
		fgsEvent.SockCookie = event.SockCookie
	}

	dnsCache := dns.Get()
	state := cilium.GetCiliumState()
	fgsEvent.DestinationNames, _ = sockinfo.GetProcessIp(fgsProcess, fgsEvent.DestinationIp, dnsCache, state)
	fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIp)

	switch event.IcmpData.IcmpIpProto {
	case unix.IPPROTO_TCP:
		fgsEvent.IcmpIpProtocol = tetragon.SocketProtocol_TCP
	case unix.IPPROTO_UDP:
		fgsEvent.IcmpIpProtocol = tetragon.SocketProtocol_UDP
	}

	if event.IcmpData.IcmpIpPort != 0 {
		fgsEvent.IcmpIpPort = uint32(event.IcmpData.IcmpIpPort)
	}

	if event.IcmpData.IcmpIpTtl != 0 {
		fgsEvent.IcmpIpTtl = uint32(event.IcmpData.IcmpIpTtl)
	}

	if event.IcmpData.IcmpIpPointer != 0 {
		fgsEvent.IcmpIpPointer = uint32(event.IcmpData.IcmpIpPointer)
	}

	if event.IcmpData.IcmpGateway[0] != 0 || event.IcmpData.IcmpGateway[1] != 0 {
		fgsEvent.IcmpIpGateway = networkapi.GetIP(event.IcmpData.IcmpGateway, 0, event.Tuple.IPv6 != 0).String()
	}

	ec := eventcache.Get()
	if ec != nil && (ec.Needed(fgsProcess) || (fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(nil, fgsEvent, event.Common.Ktime, event.ProcessKey.Ktime, event)
		return nil
	}

	if process != nil {
		process.RefInc()
	}
	if parent != nil {
		parent.RefInc()
	}

	eventmetrics.HandleIcmpEvent(fgsEvent)

	return fgsEvent
}
