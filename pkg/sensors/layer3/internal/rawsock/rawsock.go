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

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/sirupsen/logrus"
	"github.com/yalue/native_endian"
	"golang.org/x/sys/unix"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/ip"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/rawsockconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

var (
	// Ensure every program has a type defined by the layer3 sensor to force loading
	// through our own LoadProbe function. This is essential for socket discovery.
	//
	// Kprobes are for systems without fentry support (<v5.5).
	// Fentry are preferred from v5.5.
	SkRawAllocV4Kprobe = program.Builder(
		"bpf_rawsock_create.o",
		"raw_sk_init",
		"kprobe/raw_sk_init",
		"tg_rawsock_sk_init",
		"layer3_sensor",
	)

	SkRawAllocV4Fentry = program.Builder(
		"bpf_rawsock_create_fentry.o",
		"fentry",
		"fentry/raw_sk_init",
		"tg_rawsock_sk_init",
		"rawsock_fentry",
	)

	SkRawAllocV6Kprobe = program.Builder(
		"bpf_rawsock_create.o",
		"rawv6_init_sk",
		"kprobe/rawv6_init_sk",
		"tg_rawsockv6_init_sk",
		"layer3_sensor",
	)

	SkRawAllocV6Fentry = program.Builder(
		"bpf_rawsock_create_fentry.o",
		"fentry",
		"fentry/rawv6_init_sk",
		"tg_rawsockv6_init_sk",
		"rawsock_fentry",
	)

	// Shared socket cookie infrastructure
	SocketCookieMapKprobe   = program.MapBuilder(SocketMapName, SkRawAllocV4Kprobe)
	SocketCookieStatsKprobe = program.MapBuilder("tg_socket_map_stats", SkRawAllocV4Kprobe)
	VerMapKprobe            = program.MapBuilder("tg_ver_map", SkRawAllocV4Kprobe)
	SocketCookieMapFentry   = program.MapBuilder(SocketMapName, SkRawAllocV4Fentry)
	SocketCookieStatsFentry = program.MapBuilder("tg_socket_map_stats", SkRawAllocV4Fentry)
	VerMapFentry            = program.MapBuilder("tg_ver_map", SkRawAllocV4Fentry)
)

const (
	SocketMapName = "tg_socket_map"
)

func PolicyHandler(spec *v1alpha1.TracingPolicySpec) (bool, error) {
	if spec.Parser.Rawsock.Metrics != nil {
		rawsockconfig.MetricsEnabled = spec.Parser.Rawsock.Metrics.Enable
		rawsockconfig.CurrentLabels = rawsockconfig.DefaultLabelFilter().WithEnabledLabels(spec.Parser.Rawsock.Metrics.LabelFilter)
	} else {
		rawsockconfig.MetricsEnabled = true
		rawsockconfig.CurrentLabels = rawsockconfig.DefaultLabelFilter()
	}

	return spec.Parser.Rawsock.ReportClose, nil
}

func EnableRawsock() ([]*program.Program, []*program.Program, []*program.Map) {
	if !kernels.MinKernelVersion("5.4.0") {
		logger.GetLogger().Warn("Raw sockets requires kernel v5.4 or later")
		return nil, nil, nil
	}

	var progsInitSock []*program.Program
	var maps []*program.Map

	if utils.SupportFentry() {
		progsInitSock = []*program.Program{
			SkRawAllocV4Fentry,
			SkRawAllocV6Fentry,
		}
		maps = []*program.Map{
			SocketCookieMapFentry,
			SocketCookieStatsFentry,
			VerMapFentry,
		}
	} else {
		progsInitSock = []*program.Program{
			SkRawAllocV4Kprobe,
			SkRawAllocV6Kprobe,
		}
		maps = []*program.Map{
			SocketCookieMapKprobe,
			SocketCookieStatsKprobe,
			VerMapKprobe,
		}
	}

	logger.GetLogger().Infof("Enable Raw socket")
	return progsInitSock, nil, maps
}

func ConfigureSensor() error {
	ip.LoadSockets(fdCallback, unix.IPPROTO_RAW, 0)
	return nil
}

func UnloadSensor() error {
	return nil
}

func fdCallback(socket *networkapi.FdLookupValue, pid uint32) {
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
	raw.Msg.Common.Op = ops.MSG_OP_RAWSOCK_CREATE

	observer.AllListeners(&raw)
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

func Init() error {
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_RAWSOCK_CREATE, handleRawsock)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_RAWSOCK_CLOSE, handleRawsock)
	return nil
}
