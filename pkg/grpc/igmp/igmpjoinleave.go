// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package igmp

import (
	"net"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/metrics/eventmetrics"
)

type MsgIGMPJoinEventUnix struct {
	Kube processapi.MsgK8sUnix
	Msg  *networkapi.MsgIGMPJoinEvent
}

func (msg *MsgIGMPJoinEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	p := ev.GetProcess()
	return eventcache.HandleGenericInternal(ev, p.Pid.Value, nil, timestamp)
}

func (msg *MsgIGMPJoinEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	p := internal.UnsafeGetProcess()
	if option.Config.EnableK8s && p.Pod == nil {
		eventcache.CacheRetries(eventcache.PodInfo).Inc()
		return eventcache.ErrFailedToGetPodInfo
	}

	ev.SetProcess(internal.UnsafeGetProcess())
	GetProcessIGMPJoin(msg)

	return nil
}

func (msg *MsgIGMPJoinEventUnix) Notify() bool {
	return true
}

func (msg *MsgIGMPJoinEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	b := GetProcessIGMPJoin(msg)
	if b != nil {
		res = &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessIgmpJoin{ProcessIgmpJoin: b},
			Time:  ktime.ToProto(msg.Msg.Common.Ktime),
		}
	}
	return res
}

func (msg *MsgIGMPJoinEventUnix) Cast(_ interface{}) notify.Message {
	return &MsgIGMPJoinEventUnix{}
}

// GetProcessIGMPJoin returns IGMP Join protobuf message for a given process, including the ancestor list.
func GetProcessIGMPJoin(
	event *MsgIGMPJoinEventUnix,
) *tetragon.ProcessIgmpJoin {
	var fgsProcess, fgsParent *tetragon.Process

	groupIp := networkapi.GetIPv4(event.Msg.GAddr, 0)

	process, parent := process.GetParentProcessInternal(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if process != nil {
		fgsProcess = process.UnsafeGetProcess()
	} else {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
		}
	}
	if parent != nil {
		fgsParent = parent.UnsafeGetProcess()
	}

	ifaceName := ""
	ifIndex := event.Msg.IFIndex
	if ifIndex != 0 {
		iface, err := net.InterfaceByIndex(int(event.Msg.IFIndex))
		if err == nil {
			ifaceName = iface.Name
		}
	}
	if ifaceName == "" {
		iface, err := interfaceBySAddr(event.Msg.SAddr)
		if err == nil {
			ifaceName = iface.Name
			ifIndex = uint32(iface.Index)
		}
	}

	fgsEvent := &tetragon.ProcessIgmpJoin{
		Process:          fgsProcess,
		Parent:           fgsParent,
		SourceIp:         networkapi.GetIPv4(event.Msg.SAddr, 0).String(),
		GroupIp:          groupIp.String(),
		InterfaceIfindex: ifIndex,
		InterfaceName:    ifaceName,
		SockCookie:       event.Msg.SockCookie,
	}

	ec := eventcache.Get()
	if ec != nil && (ec.Needed(fgsProcess) || (fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(nil, fgsEvent, event.Msg.Common.Ktime, event.Msg.ProcessKey.Ktime, event)
		return nil
	}

	eventmetrics.HandleIgmpJoinEvent(fgsEvent)

	return fgsEvent
}

type MsgIGMPLeaveEventUnix struct {
	Kube processapi.MsgK8sUnix
	Msg  *networkapi.MsgIGMPLeaveEvent
}

func (msg *MsgIGMPLeaveEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	p := ev.GetProcess()
	return eventcache.HandleGenericInternal(ev, p.Pid.Value, nil, timestamp)
}

func (msg *MsgIGMPLeaveEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	p := internal.UnsafeGetProcess()
	if option.Config.EnableK8s && p.Pod == nil {
		eventcache.CacheRetries(eventcache.PodInfo).Inc()
		return eventcache.ErrFailedToGetPodInfo
	}

	ev.SetProcess(internal.UnsafeGetProcess())
	GetProcessIGMPLeave(msg)

	return nil
}

func (msg *MsgIGMPLeaveEventUnix) Notify() bool {
	return true
}

func (msg *MsgIGMPLeaveEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	b := GetProcessIGMPLeave(msg)
	if b != nil {
		res = &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessIgmpLeave{ProcessIgmpLeave: b},
			Time:  ktime.ToProto(msg.Msg.Common.Ktime),
		}
	}
	return res
}

func (msg *MsgIGMPLeaveEventUnix) Cast(_ interface{}) notify.Message {
	return &MsgIGMPLeaveEventUnix{}
}

// GetProcessIGMPLeave returns IGMP Leave protobuf message for a given process, including the ancestor list.
func GetProcessIGMPLeave(
	event *MsgIGMPLeaveEventUnix,
) *tetragon.ProcessIgmpLeave {
	var fgsProcess, fgsParent *tetragon.Process

	groupIp := networkapi.GetIPv4(event.Msg.GAddr, 0)

	process, parent := process.GetParentProcessInternal(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if process != nil {
		fgsProcess = process.UnsafeGetProcess()
	} else {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
		}
	}
	if parent != nil {
		fgsParent = parent.UnsafeGetProcess()
	}

	ifaceName := ""
	ifIndex := event.Msg.IFIndex
	if ifIndex != 0 {
		iface, err := net.InterfaceByIndex(int(event.Msg.IFIndex))
		if err == nil {
			ifaceName = iface.Name
		}
	}
	if ifaceName == "" {
		iface, err := interfaceBySAddr(event.Msg.SAddr)
		if err == nil {
			ifaceName = iface.Name
			ifIndex = uint32(iface.Index)
		}
	}

	fgsEvent := &tetragon.ProcessIgmpLeave{
		Process:          fgsProcess,
		Parent:           fgsParent,
		SourceIp:         networkapi.GetIPv4(event.Msg.SAddr, 0).String(),
		GroupIp:          groupIp.String(),
		InterfaceIfindex: ifIndex,
		InterfaceName:    ifaceName,
		SockCookie:       event.Msg.SockCookie,
	}

	ec := eventcache.Get()
	if ec != nil && (ec.Needed(fgsProcess) || (fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(nil, fgsEvent, event.Msg.Common.Ktime, event.Msg.ProcessKey.Ktime, event)
		return nil
	}

	eventmetrics.HandleIgmpLeaveEvent(fgsEvent)

	return fgsEvent
}
