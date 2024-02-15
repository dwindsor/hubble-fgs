//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package rawsock

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"

	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/ksyms"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/sirupsen/logrus"
	"github.com/yalue/native_endian"
	"golang.org/x/sys/unix"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
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
	SkRawAllocV4 = program.Builder(
		"bpf_rawsock_create.o",
		"raw_sk_init",
		"kprobe/raw_sk_init",
		"tg_rawsock_sk_init",
		"kprobe",
	)

	SkRawAllocV6 = program.Builder(
		"bpf_rawsock_create.o",
		"rawv6_init_sk",
		"kprobe/rawv6_init_sk",
		"tg_rawsockv6_init_sk",
		"kprobe",
	)

	PacketCreateV1 = program.Builder(
		"bpf_rawsock_create.o",
		"__register_prot_hook.part.0",
		"kprobe/__register_prot_hook",
		"tg_raw_packet_reg_prot_hook",
		"kprobe",
	)

	PacketCreateV2 = program.Builder(
		"bpf_rawsock_create.o",
		"__register_prot_hook",
		"kprobe/__register_prot_hook",
		"tg_raw_packet_reg_prot_hook",
		"kprobe",
	)

	// Set this to the novel 'kprobe_raw' to force our LoadProbe function to get called
	// so that we can trigger discovery of existing sockets.
	PacketRelease = program.Builder(
		"bpf_rawsock_release.o",
		"__sk_free",
		"kprobe/__sk_free",
		"tg_rawsock_sk_free",
		"kprobe_raw",
	)

	// Shared socket cookie infrastructure
	SocketCookieMap   = program.MapBuilder(SocketMapName, SkRawAllocV4)
	SocketCookieStats = program.MapBuilder("tg_socket_map_stats", SkRawAllocV4)
)

type rawsockSensor struct {
	name string
}

func FdCallback(socket *ip.FdLookupValue, pid uint32) {
	logger.GetLogger().WithFields(logrus.Fields{"Pid": pid, "Cookie": socket.Sockaddr}).Debug("Discovered Raw Socket")
	pathName := filepath.Join(option.Config.ProcFS, fmt.Sprintf("%d", pid))
	stats, err := proc.GetProcStatStrings(pathName)
	if err != nil {
		return
	}
	ktime, err := proc.GetStatsKtime(stats)
	if err != nil {
		return
	}

	raw := layer3.MsgIPEventUnix{}
	raw.Msg = &networkapi.MsgIPEvent{}

	raw.Msg.ProcessKey.Pid = pid
	raw.Msg.ProcessKey.Ktime = ktime
	raw.Msg.Common.Ktime = ktime

	raw.Msg.SockCookie = socket.Sockaddr
	raw.Msg.Common.Op = ops.MsgOpRawsockCreate

	observer.AllListeners(&raw)

}

func (rawsock *rawsockSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	if !configured {
		ip.LoadSockets(FdCallback, unix.IPPROTO_RAW)
	}

	if args.Load.Type == "cgrp_rawsock_ingress" || args.Load.Type == "cgrp_rawsock_egress" {
		err := cgroup.LoadCgroupProgram(args.BPFDir, args.MapDir, args.Load, args.Verbose)
		if err != nil {
			return err
		}
	}
	if args.Load.Type == "kprobe_raw" {
		err := program.LoadKprobeProgram(args.BPFDir, args.MapDir, args.Load, args.Verbose)
		if err != nil {
			return err
		}
	}
	if !configured {
		configured = true
	}
	return nil
}

func EnableRawsockParser(reportClose bool) *sensors.Sensor {
	var progs []*program.Program
	var maps []*program.Map
	var versionStr string

	// We want to make sure we stand configuration up when loading/unloading the sensor.
	configured = false

	if !kernels.MinKernelVersion("5.4.0") {
		logger.GetLogger().Warn("Raw sockets requires kernel v5.4 or later")
		return nil
	}

	progs = []*program.Program{
		SkRawAllocV4,
		SkRawAllocV6,
	}
	ks, err := ksyms.KernelSymbols()
	if err != nil {
		logger.GetLogger().Warn("Raw socket sensor cannot access kallsyms")
		return nil
	}
	if ks.IsAvailable("__register_prot_hook.part.0") {
		progs = append(progs, PacketCreateV1)
	} else if ks.IsAvailable("__register_prot_hook") {
		progs = append(progs, PacketCreateV2)
	} else {
		logger.GetLogger().Warn("Raw socket sensor cannot locate __register_prot_hook")
		return nil
	}

	if reportClose {
		progs = append(progs, PacketRelease)
	}
	maps = []*program.Map{
		SocketCookieMap,
		SocketCookieStats,
	}
	versionStr = "__rawsock_sensor_probe__"

	logger.GetLogger().Infof("Enable Raw socket")
	rawsockSensor := sensors.SensorBuilder(versionStr, progs, maps)
	return rawsockSensor
}

func (rawsock *rawsockSensor) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	fid policyfilter.PolicyID,
) (*sensors.Sensor, error) {
	spec := policy.TpSpec()

	if !spec.Parser.Rawsock.Enable {
		return nil, nil
	}

	if fid != policyfilter.NoFilterID {
		return nil, fmt.Errorf("raw socket sensor does not implement policy filtering")
	}

	return EnableRawsockParser(spec.Parser.Rawsock.ReportClose), nil
}

func handleRawsock(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgIPEvent{}
	err := binary.Read(r, native_endian.NativeEndian(), &m)
	if err != nil {
		return nil, err
	}
	msgUnix := ip.MsgToIPUnix(&m)

	return []observer.Event{msgUnix}, nil
}

func init() {
	AddRawsock()
}

func AddRawsock() {
	rawsock := &rawsockSensor{
		name: "Raw socket sensor",
	}
	sensors.RegisterProbeType("rawsock_sensor", rawsock)
	sensors.RegisterPolicyHandlerAtInit(rawsock.name, rawsock)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_RAWSOCK_CREATE, handleRawsock)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_RAWSOCK_CLOSE, handleRawsock)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_IP_ERROR, ip.HandleIpError)

	sensors.RegisterProbeType("cgrp_rawsock_ingress", rawsock)
	sensors.RegisterProbeType("cgrp_rawsock_egress", rawsock)
	sensors.RegisterProbeType("kprobe_raw", rawsock)
}
