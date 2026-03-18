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
	"strings"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/metrics/eventmetrics"
)

type MsgIGMPGroupRecordUnix struct {
	Msg   networkapi.MsgIGMPGroupRecord
	SAddr []uint32
}

type MsgIGMPMembershipReportUnix struct {
	Kube  processapi.MsgK8sUnix
	Msg   *networkapi.MsgIGMPMembershipReport
	Group []MsgIGMPGroupRecordUnix
}

func (msg *MsgIGMPMembershipReportUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	p := ev.GetProcess()
	return eventcache.HandleGenericInternal(ev, p.Pid.Value, nil, timestamp)
}

func (msg *MsgIGMPMembershipReportUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	p := internal.UnsafeGetProcess()
	if option.Config.EnableK8s && p.Pod == nil {
		eventcache.CacheRetries(eventcache.PodInfo).Inc()
		return eventcache.ErrFailedToGetPodInfo
	}

	ev.SetProcess(internal.UnsafeGetProcess())
	GetProcessIGMPMembershipReport(msg)

	return nil
}

func (msg *MsgIGMPMembershipReportUnix) Notify() bool {
	return true
}

func (msg *MsgIGMPMembershipReportUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	b := GetProcessIGMPMembershipReport(msg)
	if b != nil {
		res = &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_IgmpMembershipReport{IgmpMembershipReport: b},
			Time:  ktime.ToProto(msg.Msg.Common.Ktime),
		}
	}
	return res
}

func (msg *MsgIGMPMembershipReportUnix) Cast(_ interface{}) notify.Message {
	return &MsgIGMPMembershipReportUnix{}
}

// GetProcessIGMPMembershipReport returns IGMP Membership Report protobuf message.
func GetProcessIGMPMembershipReport(
	event *MsgIGMPMembershipReportUnix,
) *tetragon.IgmpMembershipReport {
	groupIp := networkapi.GetIPv4(event.Msg.GAddr, 0)
	sAddrIp := networkapi.GetIPv4(event.Msg.SAddr, 0)

	groups := make([]*tetragon.IgmpGroupRecord, len(event.Group))
	for gidx, g := range event.Group {
		saddrs := make([]string, len(g.SAddr))
		for sidx, s := range g.SAddr {
			saddrs[sidx] = string(networkapi.GetIPv4(s, 0))
		}
		groups[gidx] = &tetragon.IgmpGroupRecord{
			Type:      tetragon.IgmpGroupRecordType(g.Msg.Type),
			GroupIp:   networkapi.GetIPv4(g.Msg.GAddr, 0).String(),
			SourceIps: saddrs,
		}
	}

	ifname := string(event.Msg.IFName[:])
	if strings.IndexByte(ifname, 0) >= 0 {
		ifname = ifname[:strings.IndexByte(ifname, 0)]
	}

	fgsEvent := &tetragon.IgmpMembershipReport{
		Type:             tetragon.IgmpMembershipReportType(event.Msg.Type),
		GroupIp:          groupIp.String(),
		SourceIp:         sAddrIp.String(),
		InterfaceIfindex: event.Msg.IFIndex,
		InterfaceName:    ifname,
		Groups:           groups,
	}

	// As this event does not have process, parent, pod, or ancestors, we have all the information we require
	// and do not require the event cache.

	eventmetrics.HandleIgmpMembershipReportEvent(fgsEvent)

	return fgsEvent
}
