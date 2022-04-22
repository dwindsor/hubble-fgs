package sockinfo

import (
	"fmt"
	"net"

	"github.com/cilium/hubble/pkg/cilium"
	fgsAPI "github.com/isovalent/hubble-fgs/pkg/api"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/process"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func GetTuple(tuple *fgsAPI.MsgIPv4Tuple, cookie uint64, op uint8) *fgs.SockInfo {
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

func GetProcessTuple(event *fgsAPI.MsgIPv4EventUnix) *fgs.SockInfo {
	return GetTuple(&event.Tuple, event.SockCookie, event.Common.Op)
}

func GetProcessIp(proc *fgs.Process, ip string, cache *dns.Cache, cs *cilium.State) ([]string, error) {
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
