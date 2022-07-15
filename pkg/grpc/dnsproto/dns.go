package dnsproto

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/cilium"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/isovalent/hubble-fgs/pkg/api/dnsapi"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/grpc/sockinfo"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
	"github.com/isovalent/hubble-fgs/pkg/reader/network"
)

var (
	nodeName = node.GetNodeNameForExport()
)

type MsgDnsUnix struct {
	Common     processapi.MsgCommon
	Tuple      networkapi.MsgIPTuple
	Return     int64
	ProcessKey processapi.MsgExecveKey
	SockCookie uint64
	Dns        dnsapi.MsgDns
}

func get(msg *MsgDnsUnix) *tetragon.ProcessDns {
	var proc *tetragon.Process
	var err error

	processID := process.GetProcessID(msg.ProcessKey.Pid, msg.ProcessKey.Ktime)
	processInt, err := process.Get(processID)
	if err != nil {
		logger.GetLogger().WithField("id in DNS event", processID).Debug("process not found in cache")
	} else {
		proc = processInt.UnsafeGetProcess()

	}
	fgsTuple := sockinfo.GetTuple(&msg.Tuple, 0, msg.Common.Op)

	fgsDns := &tetragon.DnsInfo{
		Response:      msg.Dns.Response,
		Rcode:         int32(msg.Dns.RCode),
		Ips:           msg.Dns.IPs,
		Names:         msg.Dns.Names,
		QuestionTypes: msg.Dns.QuestionTypes,
		AnswerTypes:   msg.Dns.AnswerTypes,
	}

	c := dns.Get()
	if c != nil {
		c.AddIp(fgsDns)
	}

	fgsEvent := &tetragon.ProcessDns{
		Process: proc,
		Socket:  fgsTuple,
		Dns:     fgsDns,
	}

	fgsEvent.Socket.DestinationNames, _ = sockinfo.GetProcessIp(proc, fgsEvent.Socket.DestinationIp, c, cilium.GetCiliumState())

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if option.Config.EnableCilium && proc != nil {
		destinationIP := network.GetIP(msg.Tuple.DAddr, ops.MSG_OP_DNS, msg.Tuple.IPv6 != 0)
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
	}
	ec := eventcache.Get()
	if ec != nil && ec.Needed(proc) {
		ec.Add(processInt, fgsEvent, ktime.ToProto(msg.Common.Ktime), msg)
		return nil
	}
	if processInt != nil {
		fgsEvent.Process = processInt.GetProcessCopy()
	}
	return fgsEvent
}

func (msg *MsgDnsUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	switch msg.Common.Op {
	case ops.MSG_OP_DNS:
		t := get(msg)
		if t != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessDns{ProcessDns: t},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleDnsMessage: Unhandled event")
	}
	return res
}
