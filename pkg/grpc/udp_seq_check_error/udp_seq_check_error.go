// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package udp_seq_check_error

import (
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
)

type MsgUdpSeqCheckErrorEventUnix struct {
	Msg *networkapi.MsgUdpSeqCheckErrorEvent
}

func (msg *MsgUdpSeqCheckErrorEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	p := ev.GetProcess()
	return eventcache.HandleGenericInternal(ev, p.Pid.Value, nil, timestamp)
}

func (msg *MsgUdpSeqCheckErrorEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	p := internal.UnsafeGetProcess()
	if option.Config.EnableK8s && p.Pod == nil {
		eventcache.CacheRetries(eventcache.PodInfo).Inc()
		return eventcache.ErrFailedToGetPodInfo
	}

	ev.SetProcess(internal.UnsafeGetProcess())
	createProcessUdpSeqCheckError(msg, false)

	return nil
}

func (msg *MsgUdpSeqCheckErrorEventUnix) Notify() bool {
	return true
}

func (msg *MsgUdpSeqCheckErrorEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	b := getProcessUdpSeqCheckError(msg)
	if b != nil {
		res = &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessUdpSeqCheckError{ProcessUdpSeqCheckError: b},
			Time:  ktime.ToProto(msg.Msg.Common.Ktime),
		}
	}
	return res
}

func (msg *MsgUdpSeqCheckErrorEventUnix) Cast(_ any) notify.Message {
	return &MsgUdpSeqCheckErrorEventUnix{}
}

func createProcessUdpSeqCheckError(
	event *MsgUdpSeqCheckErrorEventUnix, _ bool,
) *tetragon.ProcessUdpSeqCheckError {
	var fgsProcess, fgsParent *tetragon.Process
	var sourcePort, destinationPort *wrapperspb.UInt32Value

	if event.Msg.Tuple.SPort != 0 {
		sourcePort = &wrapperspb.UInt32Value{
			Value: uint32(networkapi.GetSport(event.Msg.Tuple.SPort)),
		}
	}
	if event.Msg.Tuple.DPort != 0 {
		destinationPort = &wrapperspb.UInt32Value{
			Value: uint32(networkapi.GetDport(event.Msg.Tuple.DPort, event.Msg.Common.Op)),
		}
	}

	process, parent := process.GetParentProcessInternal(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
	}
	if parent != nil {
		fgsParent = parent.UnsafeGetProcess()
	}

	destinationIP := networkapi.GetIP(event.Msg.Tuple.DAddr, event.Msg.Common.Op, event.Msg.Tuple.IPv6 != 0)

	socket := &tetragon.SockInfo{
		SourceIp:        networkapi.GetIP(event.Msg.Tuple.SAddr, event.Msg.Common.Op, event.Msg.Tuple.IPv6 != 0).String(),
		SourcePort:      sourcePort,
		DestinationIp:   destinationIP.String(),
		DestinationPort: destinationPort,
		SockCookie:      event.Msg.SockCookie,
	}

	ec := eventcache.Get()
	var err error
	socket.DestinationNames, err = dns.Get().LookupDomains(destinationIP.String())
	if err != nil {
		logger.GetLogger().Warn("DNS cache lookup failure", logfields.Error, err)
	}

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if fgsProcess != nil {
		destinationIP := networkapi.GetIP(event.Msg.Tuple.DAddr, ops.MSG_OP_HTTP, event.Msg.Tuple.IPv6 != 0)
		socket.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
	}

	fgsEvent := &tetragon.ProcessUdpSeqCheckError{
		Process:        fgsProcess,
		Parent:         fgsParent,
		Socket:         socket,
		ApplicationId:  event.Msg.ApplicationId,
		AppSpecificId:  event.Msg.AppSpecificId,
		SeqNumExpected: event.Msg.SeqNumExpected,
		SeqNumReceived: event.Msg.SeqNumReceived,
	}

	if ec != nil && (ec.Needed(fgsProcess) || (fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(nil, fgsEvent, event.Msg.Common.Ktime, event.Msg.ProcessKey.Ktime, event)
		return nil
	}

	eventmetrics.HandleProcessUdpSeqCheckError(fgsEvent)
	return fgsEvent
}

func getProcessUdpSeqCheckError(
	event *MsgUdpSeqCheckErrorEventUnix,
) *tetragon.ProcessUdpSeqCheckError {
	return createProcessUdpSeqCheckError(event, true)
}
