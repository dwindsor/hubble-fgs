package sockinfo

import (
	"fmt"
	"net"

	"github.com/cilium/hubble/pkg/cilium"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/process"
	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/reader/network"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func GetTupleV4(tuple *api.MsgIPTuple, cookie uint64, op uint8) *tetragon.SockInfo {
	var sourcePort, destinationPort *wrapperspb.UInt32Value

	if tuple.SPort != 0 {
		sourcePort = &wrapperspb.UInt32Value{
			Value: uint32(network.GetSport(tuple.SPort)),
		}
	}
	if tuple.DPort != 0 {
		destinationPort = &wrapperspb.UInt32Value{
			Value: uint32(network.SwapByte(tuple.DPort)),
		}
	}

	destinationIP := network.GetIP(tuple.DAddr, op, false)

	return &tetragon.SockInfo{
		SourcePort:      sourcePort,
		SourceIp:        network.GetIP(tuple.SAddr, op, false).String(),
		DestinationIp:   destinationIP.String(),
		DestinationPort: destinationPort,
		SockCookie:      cookie,

		Protocol: network.MsgOpToProtocol(op),
	}
}

func GetTuple(tuple *api.MsgIPTuple, cookie uint64, op uint8) *tetragon.SockInfo {
	var sourcePort, destinationPort *wrapperspb.UInt32Value

	if tuple.SPort != 0 {
		sourcePort = &wrapperspb.UInt32Value{
			Value: uint32(network.GetSport(tuple.SPort)),
		}
	}
	if tuple.DPort != 0 {
		destinationPort = &wrapperspb.UInt32Value{
			Value: uint32(network.SwapByte(tuple.DPort)),
		}
	}

	destinationIP := network.GetIP(tuple.DAddr, op, tuple.IPv6 != 0)

	return &tetragon.SockInfo{
		SourcePort:      sourcePort,
		SourceIp:        network.GetIP(tuple.SAddr, op, tuple.IPv6 != 0).String(),
		DestinationIp:   destinationIP.String(),
		DestinationPort: destinationPort,
		SockCookie:      cookie,

		Protocol: network.MsgOpToProtocol(op),
	}
}

func GetProcessIp(proc *tetragon.Process, ip string, cache *dns.Cache, cs *cilium.State) ([]string, error) {
	var entry []string

	if dns.CiliumDnsEnabled() {
		endpoint := process.GetProcessEndpoint(proc)
		if endpoint == nil {
			return nil, fmt.Errorf("no endpoint found for GetIp")
		}
		entry = cs.GetFQDNCache().GetNamesOf(endpoint.ID, net.ParseIP(ip))
		if len(entry) == 0 {
			return nil, fmt.Errorf("no dns entry found through FQDN Cache")
		}
		return entry, nil
	}
	return cache.GetIp(ip)
}
