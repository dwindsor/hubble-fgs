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
	"bytes"
	"encoding/binary"

	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/yalue/native_endian"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/grpc/igmp"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

const kernelVersionGroupRecords = "6.6"

var (
	// Ensure every program has a type defined by the layer3 sensor to force loading
	// through our own LoadProbe function. This is essential for socket discovery.
	//
	// Kprobes are for systems without fentry support (<v5.5).
	// Fentry are preferred from v5.5.
	// Here, we define all programs as kprobes and we fix-up these definitions later.
	IGMPJoinGroup = program.Builder(
		"bpf_igmp_kprobe.o",
		"__ip_mc_join_group",
		"kprobe/__ip_mc_join_group",
		"tg_ip_mc_join_group",
		"layer3_sensor",
	)

	IGMPLeaveGroup = program.Builder(
		"bpf_igmp_kprobe.o",
		"ip_mc_leave_group",
		"kprobe/ip_mc_leave_group",
		"tg_ip_mc_leave_group",
		"layer3_sensor",
	)

	IGMPTimerExpire = program.Builder(
		"bpf_igmp_kprobe.o",
		"igmp_timer_expire",
		"kprobe/igmp_timer_expire",
		"tg_igmp_timer_expire",
		"layer3_sensor",
	)

	IGMPGQTimerExpire = program.Builder(
		"bpf_igmp_kprobe.o",
		"igmp_gq_timer_expire",
		"kprobe/igmp_gq_timer_expire",
		"tg_igmp_gq_timer_expire",
		"layer3_sensor",
	)

	IGMPGroupDropped = program.Builder(
		"bpf_igmp_kprobe.o",
		"__igmp_group_dropped",
		"kprobe/__igmp_group_dropped",
		"tg_igmp_group_dropped",
		"layer3_sensor",
	)

	IGMPNetdevEvent = program.Builder(
		"bpf_igmp_kprobe.o",
		"igmp_netdev_event",
		"kprobe/igmp_netdev_event",
		"tg_igmp_netdev_event",
		"layer3_sensor",
	)
)

func EnableIgmp() ([]*program.Program, []*program.Program, []*program.Map) {
	var progsCollectStats []*program.Program
	maps := []*program.Map{
		program.MapUserFrom(base.SocketMap),
	}

	// We initially gate the IGMP observability at v5.15. It will be possible to support earlier versions
	// but some rework will be required.
	if !kernels.MinKernelVersion("5.15.0") {
		logger.GetLogger().Warn("IGMP support requires a later kernel (v5.15+ or RHEL equivalent)")
		return nil, nil, nil
	}

	progsCollectStats = []*program.Program{
		IGMPJoinGroup,
		IGMPLeaveGroup,
		IGMPTimerExpire,
		IGMPGroupDropped,
		IGMPNetdevEvent,
		IGMPGQTimerExpire,
	}

	supportFentry := utils.SupportFentry()
	supportGroupRecords := kernels.MinKernelVersion(kernelVersionGroupRecords)

	for _, p := range progsCollectStats {
		if supportFentry {
			if supportGroupRecords {
				p.Name = "bpf_igmp_gr_fentry.o"
			} else {
				p.Name = "bpf_igmp_fentry.o"
			}
			p.Attach = "fentry"
			p.Label = "fentry" + p.Label[6:]
			p.Type = "igmp_fentry"
		} else {
			if supportGroupRecords {
				p.Name = "bpf_igmp_gr_kprobe.o"
			}
		}
	}

	// Due to changes in the verifier at or before v6.6 (but after v6.1), our programs can loop over
	// group records; prior to the change these loops exceed complexity constraints. We therefore do
	// not support collecting group records (introduced in IGMPv3) on kernels <v6.6.
	// In addition, further changes after v6.6 but before v6.12 allow more loop iterations - see
	// fgsRodataCurrent() in pkg/sensors/base/rodata_linux.go for TG_IGMPV3_MAX_PMCS's own version gate.
	// If group records are required for kernels <v6.6 or more group records are required than
	// complexity allows for, then the IGMP programs could be reworked to observe IGMP packets instead
	// of the functions that create the packets. There will be a perf hit as a result of hooking a
	// busy packet hook, such as ip_local_out(), however.

	logger.GetLogger().Info("Enable IGMP", "supportGroupRecords", supportGroupRecords)
	return nil, progsCollectStats, maps
}

func ConfigureSensor() error {
	return nil
}

func UnloadSensor() error {
	return nil
}

func PolicyHandler(_ *v1alpha1.TracingPolicySpec) error {
	return nil
}

func MsgToIGMPJoinEventUnix(m *networkapi.MsgIGMPJoinEvent) *igmp.MsgIGMPJoinEventUnix {
	unix := &igmp.MsgIGMPJoinEventUnix{}
	unix.Msg = m
	return unix
}

func handleIGMPJoin(r *bytes.Reader) ([]observer.Event, error) {
	m := networkapi.MsgIGMPJoinEvent{}
	err := binary.Read(r, native_endian.NativeEndian(), &m)
	if err != nil {
		return nil, err
	}
	msgUnix := MsgToIGMPJoinEventUnix(&m)

	return []observer.Event{msgUnix}, nil
}

func MsgToIGMPLeaveEventUnix(m *networkapi.MsgIGMPLeaveEvent) *igmp.MsgIGMPLeaveEventUnix {
	unix := &igmp.MsgIGMPLeaveEventUnix{}
	unix.Msg = m
	return unix
}

func handleIGMPLeave(r *bytes.Reader) ([]observer.Event, error) {
	m := networkapi.MsgIGMPLeaveEvent{}
	err := binary.Read(r, native_endian.NativeEndian(), &m)
	if err != nil {
		return nil, err
	}
	msgUnix := MsgToIGMPLeaveEventUnix(&m)

	return []observer.Event{msgUnix}, nil
}

func getGroups(r *bytes.Reader, n uint16) ([]igmp.MsgIGMPGroupRecordUnix, error) {
	if n == 0 {
		return []igmp.MsgIGMPGroupRecordUnix{}, nil
	}
	groups := make([]igmp.MsgIGMPGroupRecordUnix, n)
	for idx := range n {
		err := binary.Read(r, native_endian.NativeEndian(), &groups[idx].Msg)
		if err != nil {
			return nil, err
		}
		numSources := groups[idx].Msg.NumSources
		if numSources != 0 {
			groups[idx].SAddr = make([]uint32, numSources)
			for sidx := range numSources {
				err := binary.Read(r, native_endian.NativeEndian(), &groups[idx].SAddr[sidx])
				if err != nil {
					return nil, err
				}
			}
		}
	}
	return groups, nil
}

func MsgToIGMPMembershipReportEventUnix(m *networkapi.MsgIGMPMembershipReport, g []igmp.MsgIGMPGroupRecordUnix) *igmp.MsgIGMPMembershipReportUnix {
	unix := &igmp.MsgIGMPMembershipReportUnix{}
	unix.Msg = m
	unix.Group = g
	return unix
}

func handleIGMPReport(r *bytes.Reader) ([]observer.Event, error) {
	m := networkapi.MsgIGMPMembershipReport{}
	err := binary.Read(r, native_endian.NativeEndian(), &m)
	if err != nil {
		return nil, err
	}
	groups, err := getGroups(r, m.NumGroupRecords)
	if err != nil {
		return nil, err
	}
	msgUnix := MsgToIGMPMembershipReportEventUnix(&m, groups)

	return []observer.Event{msgUnix}, nil
}

func Init() error {
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_IGMP_JOIN, handleIGMPJoin)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_IGMP_LEAVE, handleIGMPLeave)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_IGMP_REPORT, handleIGMPReport)
	return nil
}
