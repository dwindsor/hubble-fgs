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
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/yalue/native_endian"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/constants"
	"github.com/isovalent/hubble-fgs/pkg/grpc/icmp"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/ip"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

var (
	Config        ConfigValue
	ConfigMapName = "tg_icmp_cfg_map"
	SocketMapName = "tg_socket_map"
)

var (
	// Ensure every program has a type defined by the layer3 sensor to force loading
	// through our own LoadProbe function. This is essential for socket discovery.
	//
	// Kprobes are for systems without fentry support (<v5.5).
	// Fentry are preferred from v5.5.
	SkPingAllocKprobe = program.Builder(
		"bpf_pingsock_create.o",
		"ping_init_sock",
		"kprobe/ping_init_sock",
		"tg_ping_init_sock",
		"layer3_sensor",
	)

	SkPingAllocFentry = program.Builder(
		"bpf_pingsock_create_fentry.o",
		"fentry",
		"fentry/ping_init_sock",
		"tg_ping_init_sock",
		"icmp_fentry",
	)

	IcmpRcvKprobe = program.Builder(
		"bpf_icmp_rcv.o",
		"icmp_rcv",
		"kprobe/icmp_rcv",
		"tg_icmp_rcv",
		"layer3_sensor",
	)

	IcmpRcvFentry = program.Builder(
		"bpf_icmp_rcv_fentry.o",
		"fentry",
		"fentry/icmp_rcv",
		"tg_icmp_rcv",
		"icmp_fentry",
	)

	IcmpRcv6Kprobe = program.Builder(
		"bpf_icmp_rcv.o",
		"icmpv6_rcv",
		"kprobe/icmpv6_rcv",
		"tg_icmpv6_rcv",
		"layer3_sensor",
	)

	IcmpRcv6Fentry = program.Builder(
		"bpf_icmp_rcv_fentry.o",
		"fentry",
		"fentry/icmpv6_rcv",
		"tg_icmpv6_rcv",
		"icmp_fentry",
	)

	// Shared socket cookie infrastructure
	SocketCookieMapKprobe    = program.MapBuilder(SocketMapName, IcmpRcvKprobe)
	SocketCookieStatsKprobe  = program.MapBuilder("tg_socket_map_stats", IcmpRcvKprobe)
	SocketTupleMapKprobe     = program.MapBuilder("tg_socket_tuple_map", IcmpRcvKprobe)
	SocketTupleStatsKprobe   = program.MapBuilder("tg_socket_tuple_map_stats", IcmpRcvKprobe)
	SocketTupleRevMapKprobe  = program.MapBuilder("tg_rev_tuple_map", IcmpRcvKprobe)
	SocketTupleHintMapKprobe = program.MapBuilder("tg_socket_tuple_hint_map", IcmpRcvKprobe)
	SocketCookieMapFentry    = program.MapBuilder(SocketMapName, IcmpRcvFentry)
	SocketCookieStatsFentry  = program.MapBuilder("tg_socket_map_stats", IcmpRcvFentry)
	SocketTupleMapFentry     = program.MapBuilder("tg_socket_tuple_map", IcmpRcvFentry)
	SocketTupleStatsFentry   = program.MapBuilder("tg_socket_tuple_map_stats", IcmpRcvFentry)
	SocketTupleRevMapFentry  = program.MapBuilder("tg_rev_tuple_map", IcmpRcvFentry)
	SocketTupleHintMapFentry = program.MapBuilder("tg_socket_tuple_hint_map", IcmpRcvFentry)
	// ICMP runtime maps
	CfgMapKprobe     = program.MapBuilder("tg_cfg_map", IcmpRcvKprobe)
	IcmpCfgMapKprobe = program.MapBuilder("tg_icmp_cfg_map", IcmpRcvKprobe)
	VerMapKprobe     = program.MapBuilder("tg_ver_map", SkPingAllocKprobe)
	CfgMapFentry     = program.MapBuilder("tg_cfg_map", IcmpRcvFentry)
	IcmpCfgMapFentry = program.MapBuilder("tg_icmp_cfg_map", IcmpRcvFentry)
	VerMapFentry     = program.MapBuilder("tg_ver_map", SkPingAllocFentry)
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

func EnableIcmp() ([]*program.Program, []*program.Program, []*program.Map) {
	var progsInitSock []*program.Program
	var progsCollectStats []*program.Program
	var maps []*program.Map

	if !utils.CGroupSKBAvailable() {
		logger.GetLogger().Warn("ICMP support requires a later kernel (v5.4+ or RHEL equivalent)")
		return nil, nil, nil
	}

	if utils.SupportFentry() {
		progsInitSock = []*program.Program{
			SkPingAllocFentry,
		}
		progsCollectStats = []*program.Program{
			IcmpRcvFentry,
			IcmpRcv6Fentry,
		}
		maps = []*program.Map{
			SocketCookieMapFentry,
			SocketCookieStatsFentry,
			SocketTupleMapFentry,
			SocketTupleStatsFentry,
			SocketTupleRevMapFentry,
			SocketTupleHintMapFentry,
			CfgMapFentry,
			IcmpCfgMapFentry,
			VerMapFentry,
		}

	} else {
		progsInitSock = []*program.Program{
			SkPingAllocKprobe,
		}
		progsCollectStats = []*program.Program{
			IcmpRcvKprobe,
			IcmpRcv6Kprobe,
		}
		maps = []*program.Map{
			SocketCookieMapKprobe,
			SocketCookieStatsKprobe,
			SocketTupleMapKprobe,
			SocketTupleStatsKprobe,
			SocketTupleRevMapKprobe,
			SocketTupleHintMapKprobe,
			CfgMapKprobe,
			IcmpCfgMapKprobe,
			VerMapKprobe,
		}
	}

	logger.GetLogger().Info("Enable ICMP")
	return progsInitSock, progsCollectStats, maps
}

func ConfigureMaps(mapDir string, mapName string, config ConfigValue) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(mapDir, mapName), nil)
	if err != nil {
		logger.GetLogger().Warn("LoadPinnedMap", logfields.Error, err)
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
	ip.LoadSockets(fdCallback, constants.IPPROTO_ICMP, 0)
	return nil
}

func UnloadSensor() error {
	Config.v6info = 0
	if enterpriseOption.Config.Layer3CLIEnable {
		ConfigureMaps(bpf.MapPrefixPath(), ConfigMapName, Config)
	}
	return nil
}

func PolicyHandler(spec *v1alpha1.TracingPolicySpec) error {
	if !utils.CGroupSKBAvailable() {
		logger.GetLogger().Warn("ICMP support requires a later kernel (v5.4+ or RHEL equivalent)")
		return fmt.Errorf("icmp support requires a later kernel (v5.4+ or RHEL equivalent)")
	}

	if spec.Parser.Icmp != nil && spec.Parser.Icmp.V6Info {
		Config.v6info = 1
	} else {
		Config.v6info = 0
	}

	return nil
}

func fdCallback(socket *networkapi.FdLookupValue, pid uint32) {
	logger.GetLogger().Debug("Discovered ICMP Socket", "Pid", pid, "Cookie", socket.Sockaddr)
}

func MsgToICMPUnix(m *networkapi.MsgICMPEvent) *icmp.MsgICMPEventUnix {
	unix := &icmp.MsgICMPEventUnix{}
	unix.Msg = m
	return unix
}

func handleIcmp(r *bytes.Reader) ([]observer.Event, error) {
	m := networkapi.MsgICMPEvent{}
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
