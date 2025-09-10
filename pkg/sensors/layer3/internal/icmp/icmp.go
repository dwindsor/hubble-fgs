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

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/yalue/native_endian"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/constants"
	"github.com/isovalent/hubble-fgs/pkg/grpc/icmp"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/ip"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

var (
	v6info = false
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
	SocketMap           = program.MapUserFrom(base.SocketMap)
	SocketMapStats      = program.MapUserFrom(base.SocketStats)
	SocketVersionMap    = program.MapUserFrom(base.SocketVersionMap)
	SocketTupleMap      = program.MapUserFrom(base.SocketTupleMap)
	SocketTupleMapStats = program.MapUserFrom(base.SocketTupleStats)
	SocketTupleRevMap   = program.MapUserFrom(base.SocketTupleRevMap)
	SocketTupleHintMap  = program.MapUserFrom(base.SocketTupleHintMap)
	ConfigMap           = program.MapUserFrom(base.CfgMap)
)

func EnableIcmp() ([]*program.Program, []*program.Program, []*program.Map) {
	var progsInitSock []*program.Program
	var progsCollectStats []*program.Program
	maps := []*program.Map{
		SocketMap,
		SocketMapStats,
		SocketVersionMap,
		SocketTupleMap,
		SocketTupleMapStats,
		SocketTupleRevMap,
		SocketTupleHintMap,
		ConfigMap,
	}

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

	} else {
		progsInitSock = []*program.Program{
			SkPingAllocKprobe,
		}
		progsCollectStats = []*program.Program{
			IcmpRcvKprobe,
			IcmpRcv6Kprobe,
		}
	}

	logger.GetLogger().Info("Enable ICMP")
	return progsInitSock, progsCollectStats, maps
}

func ConfigureMaps(cfg *networkapi.ConfigValue) {
	cfg.ICMPV6Info = 0
	if v6info {
		cfg.ICMPV6Info = 1
	}
}

func ConfigureSensor() error {
	ip.LoadSockets(fdCallback, constants.IPPROTO_ICMP, 0)
	return nil
}

func UnloadSensor() error {
	return nil
}

func PolicyHandler(spec *v1alpha1.TracingPolicySpec) error {
	if !utils.CGroupSKBAvailable() {
		logger.GetLogger().Warn("ICMP support requires a later kernel (v5.4+ or RHEL equivalent)")
		return fmt.Errorf("icmp support requires a later kernel (v5.4+ or RHEL equivalent)")
	}

	v6info = false
	if spec.Parser.Icmp != nil && spec.Parser.Icmp.V6Info {
		v6info = true
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
