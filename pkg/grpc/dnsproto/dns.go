package dnsproto

import (
	"github.com/cilium/hubble/pkg/cilium"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api/dnsapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/eventcache"
	"github.com/isovalent/hubble-fgs/pkg/grpc/sockinfo"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
	"github.com/isovalent/hubble-fgs/pkg/process"
	"github.com/isovalent/hubble-fgs/pkg/reader/network"
)

var (
	nodeName = node.GetNodeNameForExport()
)

type Grpc struct {
	dnsCache     *dns.Cache
	ciliumState  *cilium.State
	eventCache   *eventcache.Cache
	enableCilium bool
}

func (dns *Grpc) get(event *dnsapi.MsgDnsUnix) *fgs.ProcessDns {
	var proc *fgs.Process
	var err error

	processID := process.GetProcessID(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	processInt, err := process.Get(processID)
	if err != nil {
		logger.GetLogger().WithField("id in DNS event", processID).Debug("process not found in cache")
	} else {
		proc = processInt.UnsafeGetProcess()

	}
	fgsTuple := sockinfo.GetTuple(&event.Tuple, 0, event.Common.Op)

	fgsDns := &fgs.DnsInfo{
		Response:      event.Dns.Response,
		Rcode:         int32(event.Dns.RCode),
		Ips:           event.Dns.IPs,
		Names:         event.Dns.Names,
		QuestionTypes: event.Dns.QuestionTypes,
		AnswerTypes:   event.Dns.AnswerTypes,
	}

	dns.dnsCache.AddIp(fgsDns)

	fgsEvent := &fgs.ProcessDns{
		Process: proc,
		Socket:  fgsTuple,
		Dns:     fgsDns,
	}

	fgsEvent.Socket.DestinationNames, _ = sockinfo.GetProcessIp(proc, fgsEvent.Socket.DestinationIp, dns.dnsCache, dns.ciliumState)

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if dns.enableCilium && proc != nil {
		destinationIP := network.GetIP(event.Tuple.DAddr, ops.MSG_OP_DNS)
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
	}
	if dns.eventCache.Needed(proc) {
		dns.eventCache.Add(processInt, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}
	if processInt != nil {
		fgsEvent.Process = processInt.GetProcessCopy()
	}
	return fgsEvent
}

func (dns *Grpc) HandleDnsMessage(msg *dnsapi.MsgDnsUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case ops.MSG_OP_DNS:
		t := dns.get(msg)
		if t != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessDns{ProcessDns: t},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleDnsMessage: Unhandled event")
	}
	return res
}

func New(cilium *cilium.State, dnsCache *dns.Cache, cache *eventcache.Cache, ciliumEnable bool) *Grpc {
	return &Grpc{
		ciliumState:  cilium,
		dnsCache:     dnsCache,
		eventCache:   cache,
		enableCilium: ciliumEnable,
	}
}
