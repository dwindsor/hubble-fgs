// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dnsproto

import (
	"strings"

	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	ossEventmetrics "github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/api/dnsapi"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/grpc/sockinfo"
	"github.com/isovalent/hubble-fgs/pkg/logutils"
	"github.com/isovalent/hubble-fgs/pkg/metrics/dnsmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
)

type MsgDnsUnix struct {
	Msg *networkapi.MsgIPEvent
	Dns dnsapi.MsgDns
}

// Returns whether an integer t corresponds to an expected value
// for DNS Question/Response type.
func isValidDnsType(t uint32) bool {
	// Unknown is not considered a valid type,
	// even though it technically exists in the enum
	if t == 0 {
		return false
	}
	_, ok := tetragon.DnsType_name[int32(t)]
	return ok
}

func addDnsType(t uint32, types []tetragon.DnsType, msg *MsgDnsUnix, answer bool) []tetragon.DnsType {
	if !isValidDnsType(t) {
		if option.Config.EnableUserDNSDebug {
			logger.GetLogger().Warn("Invalid DNS type",
				"type", t,
				"pid", msg.Msg.ProcessKey.Pid,
				"src", logutils.FormatTupleSrc(&msg.Msg.Common, &msg.Msg.Tuple),
				"dst", logutils.FormatTupleDst(&msg.Msg.Common, &msg.Msg.Tuple),
				"answer", answer,
				"proto", msg.Msg.Tuple.Proto)
		}
		types = append(types, tetragon.DnsType_DNS_TYPE_UNDEF)
		return types
	}
	types = append(types, tetragon.DnsType(t))
	return types
}

func get(msg *MsgDnsUnix) *tetragon.ProcessDns {
	var proc, parent *tetragon.Process

	processInt, parentInt := process.GetParentProcessInternal(msg.Msg.ProcessKey.Pid, msg.Msg.ProcessKey.Ktime)
	if processInt == nil {
		proc = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: msg.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(msg.Msg.ProcessKey.Ktime),
		}
		logger.GetLogger().Debug("process not found in cache",
			"id in DNS event", process.GetProcessID(msg.Msg.ProcessKey.Pid, msg.Msg.ProcessKey.Ktime))
	} else {
		proc = processInt.UnsafeGetProcess()

	}
	if parentInt != nil {
		parent = parentInt.UnsafeGetProcess()
	}

	fgsTuple := sockinfo.GetTuple(&msg.Msg.Tuple, 0, msg.Msg.Common.Op)

	var qTypesEnum []tetragon.DnsType
	var aTypesEnum []tetragon.DnsType

	binary, pod, workload, ns := ossEventmetrics.GetProcessInfo(proc)

	for _, a := range msg.Dns.AnswerTypes {
		dnsmetrics.AddDnsRType(ns, workload, pod, binary, strings.Join(msg.Dns.Names, ","), dnsmessage.Type(a))
		aTypesEnum = addDnsType(a, aTypesEnum, msg, true)
	}

	for _, q := range msg.Dns.QuestionTypes {
		dnsmetrics.AddDnsQType(ns, workload, pod, binary, strings.Join(msg.Dns.Names, ","), dnsmessage.Type(q))
		qTypesEnum = addDnsType(q, aTypesEnum, msg, false)
	}

	fgsDns := &tetragon.DnsInfo{
		Response: msg.Dns.Response,
		Rcode:    int32(msg.Dns.RCode), //nolint:staticcheck // deprecated, populated for backwards compatibility with ReturnCode
		ReturnCode: &wrapperspb.Int32Value{
			Value: int32(msg.Dns.RCode),
		},
		Ips:           msg.Dns.IPs,
		Names:         msg.Dns.Names,
		QuestionTypes: msg.Dns.QuestionTypes, //nolint:staticcheck // deprecated, populated for backwards compatibility with QueryTypes
		AnswerTypes:   msg.Dns.AnswerTypes,   //nolint:staticcheck // deprecated, populated for backwards compatibility with ResponseTypes
		QueryTypes:    qTypesEnum,
		ResponseTypes: aTypesEnum,
	}

	c := dns.Get()
	if c != nil {
		c.AddIp(fgsDns)
	}
	e := endpoint.MustGet()
	e.AddIpDnsMap(fgsDns)

	fgsEvent := &tetragon.ProcessDns{
		Process: proc,
		Parent:  parent,
		Socket:  fgsTuple,
		Dns:     fgsDns,
	}

	var err error
	fgsEvent.Socket.DestinationNames, err = c.LookupDomains(fgsEvent.Socket.DestinationIp)
	if err != nil {
		logger.GetLogger().Warn("DNS cache lookup failure", logfields.Error, err)
	}

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	// TODO: this field is deprecated in favor of the Socket field, so we can probably
	// remove this at some point in the future.
	if proc != nil {
		destinationIP := networkapi.GetIP(msg.Msg.Tuple.DAddr, ops.MSG_OP_DNS, msg.Msg.Tuple.IPv6 != 0)
		// We want to continue populating this deprecated field for now
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP) //nolint:staticcheck
	}
	ec := eventcache.Get()
	if ec != nil && (ec.Needed(proc) || (proc.Pid.Value > 1 && ec.Needed(parent))) {
		ec.Add(nil, fgsEvent, msg.Msg.Common.Ktime, msg.Msg.ProcessKey.Ktime, msg)
		return nil
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
	switch msg.Msg.Common.Op {
	case ops.MSG_OP_DNS:
		t := get(msg)
		if t != nil {
			res = &tetragon.GetEventsResponse{
				Event: &tetragon.GetEventsResponse_ProcessDns{ProcessDns: t},
				Time:  ktime.ToProto(msg.Msg.Common.Ktime),
			}
		}
	default:
		logger.GetLogger().Warn("HandleDnsMessage: Unhandled event", "message", msg)
	}
	return res
}

func (msg *MsgDnsUnix) Cast(_ any) notify.Message {
	return &MsgDnsUnix{}
}
