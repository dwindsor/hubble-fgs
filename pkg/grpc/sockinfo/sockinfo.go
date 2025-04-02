package sockinfo

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
	"github.com/isovalent/hubble-fgs/pkg/reader/network"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func GetTupleV4(tuple *networkapi.MsgIPTuple, cookie uint64, op uint8) *tetragon.SockInfo {
	var sourcePort, destinationPort *wrapperspb.UInt32Value

	if tuple == nil {
		return &tetragon.SockInfo{}
	}

	if tuple.SPort != 0 {
		sourcePort = &wrapperspb.UInt32Value{
			Value: uint32(networkapi.GetSport(tuple.SPort)),
		}
	}
	if tuple.DPort != 0 {
		destinationPort = &wrapperspb.UInt32Value{
			Value: uint32(networkapi.GetDport(tuple.DPort, op)),
		}
	}

	destinationIP := networkapi.GetIP(tuple.DAddr, op, false)

	return &tetragon.SockInfo{
		SourcePort:      sourcePort,
		SourceIp:        networkapi.GetIP(tuple.SAddr, op, false).String(),
		DestinationIp:   destinationIP.String(),
		DestinationPort: destinationPort,
		SockCookie:      cookie,

		Protocol: network.MsgOpToProtocol(op),
	}
}

func GetTuple(tuple *networkapi.MsgIPTuple, cookie uint64, op uint8) *tetragon.SockInfo {
	var sourcePort, destinationPort *wrapperspb.UInt32Value

	if tuple == nil {
		return &tetragon.SockInfo{}
	}

	if tuple.SPort != 0 {
		sourcePort = &wrapperspb.UInt32Value{
			Value: uint32(networkapi.GetSport(tuple.SPort)),
		}
	}
	if tuple.DPort != 0 {
		destinationPort = &wrapperspb.UInt32Value{
			Value: uint32(networkapi.GetDport(tuple.DPort, op)),
		}
	}

	destinationIP := networkapi.GetIP(tuple.DAddr, op, tuple.IPv6 != 0)

	sockInfo := &tetragon.SockInfo{
		SourcePort:      sourcePort,
		SourceIp:        networkapi.GetIP(tuple.SAddr, op, tuple.IPv6 != 0).String(),
		DestinationIp:   destinationIP.String(),
		DestinationPort: destinationPort,
		SockCookie:      cookie,

		Protocol: network.MsgOpToProtocol(op),
	}

	sockInfo.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)

	return sockInfo
}
