//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package icmp

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/sirupsen/logrus"
	"github.com/yalue/native_endian"
	"golang.org/x/sys/unix"

	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/grpc/icmp"
	"github.com/isovalent/hubble-fgs/pkg/sensors/ip"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/cgroup"
)

const (
	SocketMapName = "tg_socket_map"
)

var (
	configured = false
)

var (
	SkRawAlloc = program.Builder(
		"bpf_pingsock_create.o",
		"raw_sk_init",
		"kprobe/raw_sk_init",
		"tg_raw_sk_init",
		"kprobe",
	)

	SkPingAlloc = program.Builder(
		"bpf_pingsock_create.o",
		"ping_init_sock",
		"kprobe/ping_init_sock",
		"tg_ping_init_sock",
		"kprobe",
	)

	// Some environments init ping sockets, send ping over ping sockets,
	// and then close ping sockets. Other environments, however, init ping
	// sockets, init a raw socket, sends ping over the raw socket, and then
	// closes the raw socket, but doesn't close the ping sockets.
	// As such, we choose to solely use __sk_free to catch the sockets being
	// discarded. The original raw_close and ping_close programs are retained
	// (in comments) in case we decide to revert.

	/*
		SkRawRelease = program.Builder(
			"bpf_pingsock_release.o",
			"raw_close",
			"kprobe/raw_close",
			"tg_raw_close",
			"kprobe",
		)

		SkPingRelease = program.Builder(
			"bpf_pingsock_release.o",
			"ping_close",
			"kprobe/ping_close",
			"tg_ping_close",
			"kprobe",
		)
	*/

	SkSockRelease = program.Builder(
		"bpf_pingsock_release.o",
		"__sk_free",
		"kprobe/__sk_free",
		"tg_sk_free",
		"kprobe",
	)

	IcmpSend = program.Builder(
		"bpf_icmp.o",
		"icmp_send",
		"cgroup_skb/egress",
		"tg_icmp_egress",
		"cgrp_icmp_egress",
	)

	IcmpRecv = program.Builder(
		"bpf_icmp.o",
		"icmp_recv",
		"cgroup_skb/ingress",
		"tg_icmp_ingress",
		"cgrp_icmp_ingress",
	)

	IcmpSendLazy = program.Builder(
		"bpf_icmp_lazy.o",
		"icmp_lazy_send",
		"cgroup_skb/egress",
		"tg_icmp_egress",
		"cgrp_icmp_egress",
	)

	IcmpRecvLazy = program.Builder(
		"bpf_icmp_lazy.o",
		"icmp_lazy_recv",
		"cgroup_skb/ingress",
		"tg_icmp_ingress",
		"cgrp_icmp_ingress",
	)

	IcmpRcv = program.Builder(
		"bpf_icmp_rcv.o",
		"icmp_rcv",
		"kprobe/icmp_rcv",
		"tg_icmp_rcv",
		"kprobe",
	)

	// Shared socket cookie infrastructure
	SocketCookieMap       = program.MapBuilder(SocketMapName, IcmpSend)
	SocketCookieStats     = program.MapBuilder("tg_socket_map_stats", IcmpSend)
	SocketCookieMapLazy   = program.MapBuilder(SocketMapName, IcmpSendLazy)
	SocketCookieStatsLazy = program.MapBuilder("tg_socket_map_stats", IcmpSendLazy)
)

type icmpSensor struct {
	name string
}

func FdCallback(socket *ip.FdLookupValue, pid uint32) {
	logger.GetLogger().WithFields(logrus.Fields{"Pid": pid, "Cookie": socket.Sockaddr}).Debug("Discovered ICMP Socket")
}

func (icmp *icmpSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	if !configured {
		ip.LoadSockets(FdCallback, unix.IPPROTO_ICMP)
	}

	if args.Load.Type == "cgrp_icmp_ingress" || args.Load.Type == "cgrp_icmp_egress" {
		err := cgroup.LoadCgroupProgram(args.BPFDir, args.MapDir, args.Load, args.Verbose)
		if err != nil {
			return err
		}
	}
	if !configured {
		configured = true
	}
	return nil
}

func EnableIcmpParser() *sensors.Sensor {
	var progs []*program.Program
	var maps []*program.Map
	var versionStr string

	// We want to make sure we stand configuration up when loading/unloading the sensor.
	configured = false

	if !kernels.MinKernelVersion("5.4.0") {
		logger.GetLogger().Warn("ICMP requires kernel v5.4 or later")
		return nil
	} else if !kernels.MinKernelVersion("5.10.0") {
		progs = []*program.Program{
			SkRawAlloc,
			SkPingAlloc,
			// SkRawRelease, // see comment above
			// SkPingRelease, // see comment above
			SkSockRelease,
			IcmpSendLazy,
			IcmpRecvLazy,
			IcmpRcv,
		}
		maps = []*program.Map{
			SocketCookieMap,
			SocketCookieStats,
		}
		versionStr = "__icmp_sensor_probe__"
	} else {
		progs = []*program.Program{
			SkRawAlloc,
			SkPingAlloc,
			// SkRawRelease, // see comment above
			// SkPingRelease, // see comment above
			SkSockRelease,
			IcmpSend,
			IcmpRecv,
			IcmpRcv,
		}
		maps = []*program.Map{
			SocketCookieMap,
			SocketCookieStats,
		}
		versionStr = "__icmp_sensor_probe__"
	}

	logger.GetLogger().Infof("Enable ICMP")
	icmpSensor := sensors.SensorBuilder(versionStr, progs, maps)
	return icmpSensor
}

func (icmp *icmpSensor) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	fid policyfilter.PolicyID,
) (*sensors.Sensor, error) {
	spec := policy.TpSpec()

	if !spec.Parser.Icmp.Enable {
		return nil, nil
	}

	if fid != policyfilter.NoFilterID {
		return nil, fmt.Errorf("icmp sensor does not implement policy filtering")
	}

	return EnableIcmpParser(), nil
}

func MsgToICMPUnix(m *api.MsgICMPEvent) *icmp.MsgICMPEventUnix {
	unix := &icmp.MsgICMPEventUnix{}

	unix.Common = m.Common
	unix.Tuple = m.Tuple
	unix.ProcessKey = m.ProcessKey
	unix.SockCookie = m.SockCookie
	unix.IcmpData = m.IcmpData

	return unix
}

func handleIcmp(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgICMPEvent{}
	err := binary.Read(r, native_endian.NativeEndian(), &m)
	if err != nil {
		return nil, err
	}
	msgUnix := MsgToICMPUnix(&m)

	return []observer.Event{msgUnix}, nil
}

func init() {
	AddICMP()
}

func AddICMP() {
	icmp := &icmpSensor{
		name: "ICMP sensor",
	}
	sensors.RegisterProbeType("icmp_sensor", icmp)
	sensors.RegisterPolicyHandlerAtInit(icmp.name, icmp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_ICMP, handleIcmp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_ICMPV6, handleIcmp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_IP_ERROR, ip.HandleIpError)

	sensors.RegisterProbeType("cgrp_icmp_ingress", icmp)
	sensors.RegisterProbeType("cgrp_icmp_egress", icmp)
}
