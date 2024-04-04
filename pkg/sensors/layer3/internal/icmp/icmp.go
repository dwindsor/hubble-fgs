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
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/sirupsen/logrus"
	"github.com/yalue/native_endian"

	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/grpc/icmp"
	"github.com/isovalent/hubble-fgs/pkg/sensors/ip"
)

var (
	Config        ConfigValue
	ConfigMapName = "tg_icmp_cfg_map"
	SocketMapName = "tg_socket_map"
)

var (
	SkRawAllocV4 = program.Builder(
		"bpf_pingsock_create.o",
		"raw_sk_init",
		"kprobe/raw_sk_init",
		"tg_icmp_raw_sk_init",
		"kprobe",
	)

	SkRawAllocV6 = program.Builder(
		"bpf_pingsock_create.o",
		"rawv6_init_sk",
		"kprobe/rawv6_init_sk",
		"tg_icmp_rawv6_init_sk",
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
		"tg_icmp_sk_free",
		"kprobe",
	)

	IcmpSend = program.Builder(
		"bpf_icmp.o",
		"icmp_send",
		"cgroup_skb/egress",
		"tg_icmp_egress",
		"cgrp_egress",
	)

	IcmpRecv = program.Builder(
		"bpf_icmp.o",
		"icmp_recv",
		"cgroup_skb/ingress",
		"tg_icmp_ingress",
		"cgrp_ingress",
	)

	IcmpSendLazy = program.Builder(
		"bpf_icmp_lazy.o",
		"icmp_lazy_send",
		"cgroup_skb/egress",
		"tg_icmp_egress",
		"cgrp_egress",
	)

	IcmpRecvLazy = program.Builder(
		"bpf_icmp_lazy.o",
		"icmp_lazy_recv",
		"cgroup_skb/ingress",
		"tg_icmp_ingress",
		"cgrp_ingress",
	)

	IcmpRcv = program.Builder(
		"bpf_icmp_rcv.o",
		"icmp_rcv",
		"kprobe/icmp_rcv",
		"tg_icmp_rcv",
		"kprobe",
	)

	IcmpRcv6 = program.Builder(
		"bpf_icmp_rcv.o",
		"icmpv6_rcv",
		"kprobe/icmpv6_rcv",
		"tg_icmpv6_rcv",
		"kprobe",
	)

	// Shared socket cookie infrastructure
	SocketCookieMap        = program.MapBuilder(SocketMapName, IcmpSend)
	SocketCookieStats      = program.MapBuilder("tg_socket_map_stats", IcmpSend)
	SocketCookieMapLazy    = program.MapBuilder(SocketMapName, IcmpSendLazy)
	SocketCookieStatsLazy  = program.MapBuilder("tg_socket_map_stats", IcmpSendLazy)
	SocketTupleMap         = program.MapBuilder("tg_socket_tuple_map", IcmpSend)
	SocketTupleStats       = program.MapBuilder("tg_socket_tuple_map_stats", IcmpSend)
	SocketTupleHintMap     = program.MapBuilder("tg_socket_tuple_hint_map", IcmpSend)
	CfgMap                 = program.MapBuilder("tg_cfg_map", IcmpSend)
	IcmpCfgMap             = program.MapBuilder("tg_icmp_cfg_map", IcmpSend)
	SocketTupleMapLazy     = program.MapBuilder("tg_socket_tuple_map", IcmpSendLazy)
	SocketTupleStatsLazy   = program.MapBuilder("tg_socket_tuple_map_stats", IcmpSendLazy)
	SocketTupleHintMapLazy = program.MapBuilder("tg_socket_tuple_hint_map", IcmpSendLazy)
	CfgMapLazy             = program.MapBuilder("tg_cfg_map", IcmpSendLazy)
	IcmpCfgMapLazy         = program.MapBuilder("tg_icmp_cfg_map", IcmpSendLazy)
)

type sensorConfigKey struct {
	Zero uint32
}

type ConfigValue struct {
	v6info uint8
	Pad    [7]uint8
}

func (v *ConfigValue) String() string {
	return fmt.Sprintf("v6info: %d, ", v.v6info)
}

func EnableIcmp() ([]*program.Program, []*program.Map) {
	var progs []*program.Program
	var maps []*program.Map

	if !kernels.MinKernelVersion("5.4.0") {
		logger.GetLogger().Warn("ICMP requires kernel v5.4 or later")
		return nil, nil
	} else if !kernels.MinKernelVersion("5.10.0") {
		progs = []*program.Program{
			SkRawAllocV4,
			SkRawAllocV6,
			SkPingAlloc,
			// SkRawRelease, // see comment above
			// SkPingRelease, // see comment above
			SkSockRelease,
			IcmpSendLazy,
			IcmpRecvLazy,
			IcmpRcv,
			IcmpRcv6,
		}
		maps = []*program.Map{
			SocketCookieMapLazy,
			SocketCookieStatsLazy,
			SocketTupleMapLazy,
			SocketTupleStatsLazy,
			SocketTupleHintMapLazy,
			CfgMapLazy,
			IcmpCfgMapLazy,
		}
	} else {
		progs = []*program.Program{
			SkRawAllocV4,
			SkRawAllocV6,
			SkPingAlloc,
			// SkRawRelease, // see comment above
			// SkPingRelease, // see comment above
			SkSockRelease,
			IcmpSend,
			IcmpRecv,
			IcmpRcv,
			IcmpRcv6,
		}
		maps = []*program.Map{
			SocketCookieMap,
			SocketCookieStats,
			SocketTupleMap,
			SocketTupleStats,
			SocketTupleHintMap,
			CfgMap,
			IcmpCfgMap,
		}
	}

	logger.GetLogger().Infof("Enable ICMP")
	return progs, maps
}

func ConfigureIcmpSensor(mapDir string, mapName string, config ConfigValue) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(mapDir, mapName), nil)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("LoadPinnedMap")
		return err
	}
	defer m.Close()

	key := &sensorConfigKey{
		Zero: uint32(0),
	}
	m.Put(key, &config)
	return nil
}

func UnloadSensor() error {
	return nil
}

func PolicyHandler(spec *v1alpha1.TracingPolicySpec) error {
	if !kernels.MinKernelVersion("5.4.0") {
		logger.GetLogger().Warn("ICMP requires kernel v5.4 or later")
		return fmt.Errorf("icmp requires kernel v5.4 or later")
	}

	if spec.Parser.Icmp.V6Info {
		Config.v6info = 1
	} else {
		Config.v6info = 0
	}

	return nil
}

func FdCallback(socket *ip.FdLookupValue, pid uint32) {
	logger.GetLogger().WithFields(logrus.Fields{"Pid": pid, "Cookie": socket.Sockaddr}).Debug("Discovered ICMP Socket")
}

func MsgToICMPUnix(m *api.MsgICMPEvent) *icmp.MsgICMPEventUnix {
	unix := &icmp.MsgICMPEventUnix{}
	unix.Msg = m
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

func Init() error {
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_ICMP, handleIcmp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_ICMPV6, handleIcmp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_IP_ERROR, ip.HandleIpError)
	return nil
}
