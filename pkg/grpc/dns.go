package grpc

import (
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	fgsAPI "github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/reader"
)

func (pm *ProcessManager) GetDns(event *fgsAPI.MsgIPv4DnsUnix) *fgs.ProcessDns {
	var proc *fgs.Process
	var err error

	processID := pm.GetProcessID(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	processInt, err := pm.cache.get(processID)
	if err != nil {
		pm.log.WithField("id in DNS event", processID).Debug("process not found in cache")
	} else {
		proc = processInt.process

	}
	fgsTuple := pm.__getProcessTuple(&event.Tuple, 0, event.Common.Op)

	fgsDns := &fgs.DnsInfo{
		Response:      event.Dns.Response,
		Rcode:         int32(event.Dns.RCode),
		Ips:           event.Dns.IPs,
		Names:         event.Dns.Names,
		QuestionTypes: event.Dns.QuestionTypes,
		AnswerTypes:   event.Dns.AnswerTypes,
	}

	pm.dns.AddIp(fgsDns)

	fgsEvent := &fgs.ProcessDns{
		Process: proc,
		Socket:  fgsTuple,
		Dns:     fgsDns,
	}

	fgsEvent.Socket.DestinationNames, _ = pm.getProcessIp(proc, fgsEvent.Socket.DestinationIp)

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if pm.enableCilium && proc != nil {
		destinationIP := reader.GetIP(event.Tuple.DAddr, api.MSG_OP_IPV4_DNS)
		fgsEvent.DestinationPod = pm.getPodInfoOfIp(destinationIP)
	}
	if pm.processCacheNeeded(proc) {
		pm.eventCache.add(processInt, fgsEvent, ktimeToProto(event.Common.Ktime), event)
		return nil
	}
	if processInt != nil {
		fgsEvent.Process = processInt.GetProcessCopy()
	}
	return fgsEvent
}

func (pm *ProcessManager) handleDnsMessage(msg *api.MsgIPv4DnsUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_IPV4_DNS:
		t := pm.GetDns(msg)
		if t != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessDns{ProcessDns: t},
				NodeName: pm.nodeName,
				Time:     ktimeToProto(msg.Common.Ktime),
			}
		}
	default:
		pm.log.WithField("message", msg).Warn("Unhandled event")
	}
	return res
}
