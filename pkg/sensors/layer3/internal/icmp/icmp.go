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
	"golang.org/x/sys/unix"

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
	SkPingAlloc = program.Builder(
		"bpf_pingsock_create.o",
		"ping_init_sock",
		"kprobe/ping_init_sock",
		"tg_ping_init_sock",
		"kprobe",
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
	SocketCookieMap    = program.MapBuilder(SocketMapName, IcmpRcv)
	SocketCookieStats  = program.MapBuilder("tg_socket_map_stats", IcmpRcv)
	SocketTupleMap     = program.MapBuilder("tg_socket_tuple_map", IcmpRcv)
	SocketTupleStats   = program.MapBuilder("tg_socket_tuple_map_stats", IcmpRcv)
	SocketTupleRevMap  = program.MapBuilder("tg_rev_tuple_map", IcmpRcv)
	SocketTupleHintMap = program.MapBuilder("tg_socket_tuple_hint_map", IcmpRcv)
	// ICMP runtime maps
	CfgMap     = program.MapBuilder("tg_cfg_map", IcmpRcv)
	IcmpCfgMap = program.MapBuilder("tg_icmp_cfg_map", IcmpRcv)
	VerMap     = program.MapBuilder("tg_ver_map", SkPingAlloc)
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
	}

	progs = []*program.Program{
		SkPingAlloc,
		IcmpRcv,
		IcmpRcv6,
	}
	maps = []*program.Map{
		SocketCookieMap,
		SocketCookieStats,
		SocketTupleMap,
		SocketTupleStats,
		SocketTupleRevMap,
		SocketTupleHintMap,
		CfgMap,
		IcmpCfgMap,
		VerMap,
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

func ConfigureSensor() error {
	ip.LoadSockets(fdCallback, unix.IPPROTO_ICMP, 0)
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

func fdCallback(socket *ip.FdLookupValue, pid uint32) {
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
	return nil
}
