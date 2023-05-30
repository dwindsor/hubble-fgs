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
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/isovalent/hubble-fgs/pkg/api/dnsapi"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/grpc/sockinfo"
	"github.com/isovalent/hubble-fgs/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
	"github.com/isovalent/hubble-fgs/pkg/reader/network"
	"google.golang.org/protobuf/types/known/wrapperspb"
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
	var proc, parent *tetragon.Process

	processInt, parentInt := process.GetParentProcessInternal(msg.ProcessKey.Pid, msg.ProcessKey.Ktime)
	if processInt == nil {
		proc = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(msg.ProcessKey.Ktime),
		}
		logger.GetLogger().WithField("id in DNS event", process.GetProcessID(msg.ProcessKey.Pid, msg.ProcessKey.Ktime)).Debug("process not found in cache")
	} else {
		proc = processInt.UnsafeGetProcess()

	}
	if parentInt != nil {
		parent = parentInt.GetProcessCopy()
	}

	fgsTuple := sockinfo.GetTuple(&msg.Tuple, 0, msg.Common.Op)

	var qTypesEnum []tetragon.DnsType
	var aTypesEnum []tetragon.DnsType

	for _, a := range msg.Dns.AnswerTypes {
		aTypesEnum = append(aTypesEnum, tetragon.DnsType(a))
	}
	for _, q := range msg.Dns.QuestionTypes {
		qTypesEnum = append(qTypesEnum, tetragon.DnsType(q))
	}

	fgsDns := &tetragon.DnsInfo{
		Response: msg.Dns.Response,
		Rcode:    int32(msg.Dns.RCode),
		ReturnCode: &wrapperspb.Int32Value{
			Value: int32(msg.Dns.RCode),
		},
		Ips:           msg.Dns.IPs,
		Names:         msg.Dns.Names,
		QuestionTypes: msg.Dns.QuestionTypes,
		AnswerTypes:   msg.Dns.AnswerTypes,
		QueryTypes:    qTypesEnum,
		ResponseTypes: aTypesEnum,
	}

	c := dns.Get()
	if c != nil {
		c.AddIp(fgsDns)
	}

	fgsEvent := &tetragon.ProcessDns{
		Process: proc,
		Parent:  parent,
		Socket:  fgsTuple,
		Dns:     fgsDns,
	}

	fgsEvent.Socket.DestinationNames, _ = sockinfo.GetProcessIp(proc, fgsEvent.Socket.DestinationIp, c, cilium.GetCiliumState())

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	// TODO: this field is deprecated in favor of the Socket field, so we can probably
	// remove this at some point in the future.
	if option.Config.EnableCilium && proc != nil {
		destinationIP := network.GetIP(msg.Tuple.DAddr, ops.MSG_OP_DNS, msg.Tuple.IPv6 != 0)
		// We want to continue populating this deprecated field for now
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP) //nolint:staticcheck
	}
	ec := eventcache.Get()
	if ec != nil && ec.Needed(proc) || (proc.Pid.Value > 1 && ec.Needed(parent)) {
		ec.Add(nil, fgsEvent, msg.Common.Ktime, msg.ProcessKey.Ktime, msg)
		return nil
	}
	if processInt != nil {
		fgsEvent.Process = processInt.GetProcessCopy()
	}
	eventmetrics.HandleDnsEvent(fgsEvent)
	return fgsEvent
}

func (msg *MsgDnsUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	p := ev.GetProcess()
	return eventcache.HandleGenericInternal(ev, p.Pid.Value, nil, timestamp)
}

func (msg *MsgDnsUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev, nil)
}

func (msg *MsgDnsUnix) Notify() bool {
	return true
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

func (msg *MsgDnsUnix) Cast(_ interface{}) notify.Message {
	return &MsgDnsUnix{}
}
