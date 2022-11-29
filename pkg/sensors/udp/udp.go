//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package udp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/timer"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/sirupsen/logrus"
	"github.com/yalue/native_endian"

	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	"github.com/isovalent/hubble-fgs/pkg/metrics/lrumetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
	"github.com/isovalent/hubble-fgs/pkg/reader/network"
	reader "github.com/isovalent/hubble-fgs/pkg/reader/network"
	"github.com/isovalent/hubble-fgs/pkg/sensors/burstEvents"
	"github.com/isovalent/hubble-fgs/pkg/sensors/ip"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/cgroup"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/tc"
)

const (
	UdpGCIntervalDefault = time.Duration(60 * time.Second)
	UdpMapName           = "udp_map"
	UdpRetprobeMapName   = "udp_retprobe_map"
	UdpConfigMapName     = "udp_config_map"
	UdpPayloadMapName    = "udp_payload_map"
	SocketMapName        = "socket_map"

	stataCacheSize = 32000
	IPPROTO_UDP    = 17
)

type udpPseudoSocket struct {
	DAddr [2]uint64
	DPort uint16
	IPv6  uint8
}

var (
	UdpDeleteInterval = time.Duration(600 * time.Second)

	stats *lru.Cache[udpInfoKey, udpInfoValue]

	Config           *ConfigValue
	configured       = false
	gcTimer          = timer.NewPeriodicTimer("UDP GC Timer", runUdpGC, true)
	watermarkEnabled = false
	statsUpdate      sync.Mutex

	pseudoSockets = make(map[uint64](map[udpPseudoSocket]bool))
)

var (
	SockCreate = program.Builder(
		"bpf_sock.o",
		"sock_create",
		"cgroup/sock_create",
		"cgroup_sock_create",
		"cgrp_socket")

	SockRelease = program.Builder(
		"bpf_sock_release.o",
		"inet_release",
		"kprobe/inet_release",
		"kprobe_sock_release",
		"kprobe")

	SockReleaseLazy = program.Builder(
		"bpf_sock_release_lazy.o",
		"inet_release",
		"kprobe/inet_release",
		"kprobe_sock_release",
		"kprobe")

	InetSend = program.Builder(
		"bpf_inet_send.o",
		"inet_send",
		"cgroup_skb/egress",
		"cgroup_skb_egress",
		"cgrp_egress",
	)

	InetRecv = program.Builder(
		"bpf_inet_send.o",
		"inet_recv",
		"cgroup_skb/ingress",
		"cgroup_skb_ingress",
		"cgrp_ingress",
	)

	SkAllocRetLazy = program.Builder(
		"bpf_sock_create.o",
		"sk_alloc",
		"kretprobe/sk_alloc",
		"kretprobe_sk_alloc",
		"kprobe",
	).SetRetProbe(true)

	InetSendLazy = program.Builder(
		"bpf_inet_send_lazy.o",
		"inet_lazy_send",
		"cgroup_skb/egress",
		"cgroup_skb_egress",
		"cgrp_egress",
	)

	InetRecvLazy = program.Builder(
		"bpf_inet_send_lazy.o",
		"inet_lazy_recv",
		"cgroup_skb/ingress",
		"cgroup_skb_ingress",
		"cgrp_ingress",
	)

	InetSendRecvLazy = program.Builder(
		"bpf_inet_send_lazy_kp.o",
		"__cgroup_bpf_run_filter_skb",
		"kprobe/__cgroup_bpf_run_filter_skb",
		"kprobe___cgroup_bpf_run_filter_skb",
		"kprobe_udp",
	)

	Udp4Send = program.Builder(
		"bpf_udp_send_recv.o",
		"udp_sendmsg",
		"kprobe/udp_sendmsg",
		"kprobe_udp_sendmsg",
		"kprobe",
	)

	Udp4RetSend = program.Builder(
		"bpf_udp_send_recv.o",
		"udp_sendmsg",
		"kretprobe/udp_sendmsg",
		"kretprobe_udp_sendmsg",
		"kprobe",
	).SetRetProbe(true)

	Udp6Send = program.Builder(
		"bpf_udp_send_recv.o",
		"udpv6_sendmsg",
		"kprobe/udpv6_sendmsg",
		"kprobe_udpv6_sendmsg",
		"kprobe",
	)

	Udp6RetSend = program.Builder(
		"bpf_udp_send_recv.o",
		"udpv6_sendmsg",
		"kretprobe/udpv6_sendmsg",
		"kretprobe_udpv6_sendmsg",
		"kprobe",
	).SetRetProbe(true)

	UdpRecv = program.Builder(
		"bpf_udp_send_recv.o",
		"skb_consume_udp",
		"kprobe/skb_consume_udp",
		"kprobe_skb_consume_udp",
		"kprobe",
	)

	Udp4SendLazy = program.Builder(
		"bpf_udp_send_recv_lazy.o",
		"udp_sendmsg",
		"kprobe/udp_sendmsg",
		"kprobe_udp_sendmsg",
		"kprobe",
	)

	Udp4RetSendLazy = program.Builder(
		"bpf_udp_send_recv_lazy.o",
		"udp_sendmsg",
		"kretprobe/udp_sendmsg",
		"kretprobe_udp_sendmsg",
		"kprobe",
	).SetRetProbe(true)

	Udp6SendLazy = program.Builder(
		"bpf_udp_send_recv_lazy.o",
		"udpv6_sendmsg",
		"kprobe/udpv6_sendmsg",
		"kprobe_udpv6_sendmsg",
		"kprobe",
	)

	Udp6RetSendLazy = program.Builder(
		"bpf_udp_send_recv_lazy.o",
		"udpv6_sendmsg",
		"kretprobe/udpv6_sendmsg",
		"kretprobe_udpv6_sendmsg",
		"kprobe",
	).SetRetProbe(true)

	UdpRecvLazy = program.Builder(
		"bpf_udp_send_recv_lazy.o",
		"skb_consume_udp",
		"kprobe/skb_consume_udp",
		"kprobe_skb_consume_udp",
		"kprobe",
	)

	TCEgressTimestamp = program.Builder(
		"bpf_udp_timestamp.o",
		"udp_egress_timestamp",
		"classifier/udp_egress_timestamp",
		"classifier_udp_egress_timestamp",
		"tc_egress",
	)

	// Shared socket cookie infrastructure
	SocketCookieMap       = program.MapBuilder(SocketMapName, Udp4Send)
	SocketCookieStats     = program.MapBuilder("socket_map_stats", Udp4Send)
	SocketCookieMapLazy   = program.MapBuilder(SocketMapName, Udp4SendLazy)
	SocketCookieStatsLazy = program.MapBuilder("socket_map_stats", Udp4SendLazy)

	// UDP maps
	UdpMap                  = program.MapBuilder(UdpMapName, InetSend)
	UdpMapLazy              = program.MapBuilder(UdpMapName, InetSendLazy)
	UdpMapLazyKprobe        = program.MapBuilder(UdpMapName, InetSendRecvLazy)
	UdpRetprobeMap          = program.MapBuilder(UdpRetprobeMapName, Udp4Send)
	UdpRetprobeMapLazy      = program.MapBuilder(UdpRetprobeMapName, Udp4SendLazy)
	UdpConfigMap            = program.MapBuilder(UdpConfigMapName, InetSend)
	UdpConfigLazyMap        = program.MapBuilder(UdpConfigMapName, InetSendLazy)
	UdpConfigLazyMapKprobe  = program.MapBuilder(UdpConfigMapName, InetSendRecvLazy)
	UdpPayloadMap           = program.MapBuilder(UdpPayloadMapName, InetSend)
	UdpPayloadLazyMap       = program.MapBuilder(UdpPayloadMapName, InetSendLazy)
	UdpPayloadLazyMapKprobe = program.MapBuilder(UdpPayloadMapName, InetSendRecvLazy)
	FdLookupConfigMap       = program.MapBuilder(ip.FdLookupConfigMapName, SockRelease)
	FdLookupConfigMapLazy   = program.MapBuilder(ip.FdLookupConfigMapName, SockReleaseLazy)
)

type udpInfoKey struct {
	Cookie  uint64
	DAddr   [2]uint64
	DPort   uint16
	IPv6    uint8
	Padding [5]uint8
}

type udpInfoValue struct {
	SubmittedBytes   uint64
	TXBytes          uint64
	ConsumedBytes    uint64
	RXBytes          uint64
	ConsumedSegs     uint64
	SegsIn           uint64
	SubmittedSegs    uint64
	SegsOut          uint64
	Ktime            uint64
	PidKtime         uint64
	Pid              uint32
	SkDrops          uint32
	SAddr            [2]uint64
	DAddr            [2]uint64
	SPort            uint16
	DPort            uint16
	SkbConsumeMisses uint32
	IPv6             uint8
	Padding          [7]uint8
	CreateTime       uint64
}

func (k *udpInfoKey) String() string {
	ipDst := network.GetIP(k.DAddr, ops.MSG_OP_UDPCONNECT, k.IPv6 != 0)
	return fmt.Sprintf("Cookie=%d\n"+
		"DAddr=%s:%d\n", k.Cookie, ipDst, k.DPort)
}
func (k *udpInfoKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *udpInfoKey) NewValue() bpf.MapValue {
	return &udpInfoValue{}
}
func (k *udpInfoKey) DeepCopyMapKey() bpf.MapKey {
	return &udpInfoKey{
		Cookie: k.Cookie,
		DAddr:  k.DAddr,
		DPort:  k.DPort,
		IPv6:   k.IPv6,
	}
}

func (v *udpInfoValue) String() string {
	ipDst := network.GetIP(v.DAddr, ops.MSG_OP_UDPCONNECT, v.IPv6 != 0)
	ipSrc := network.GetIP(v.SAddr, ops.MSG_OP_UDPCONNECT, v.IPv6 != 0)
	return fmt.Sprintf(
		"SAddr=%s:%d DAddr=%s:%d\n"+
			"Pid: %d Ktime %d\n"+
			"SubmittedBytes: %d ConsumedBytes %d\n"+
			"TXBytes: %d RXBytes%d\n"+
			"SubmittedSegs: %d ConsumedSegs: %d\n"+
			"SegsOut: %d SegsIn: %d\n"+
			"SkDrops: %d\n"+
			"SkbConsumeMisses: %d\n",
		ipSrc, v.SPort, ipDst, network.SwapByte(v.DPort),
		v.Pid, v.Ktime,
		v.SubmittedBytes, v.ConsumedBytes,
		v.TXBytes, v.RXBytes,
		v.SubmittedSegs, v.ConsumedSegs,
		v.SegsOut, v.SegsIn,
		v.SkDrops, v.SkbConsumeMisses)
}
func (v *udpInfoValue) GetValuePtr() unsafe.Pointer {
	return unsafe.Pointer(&v)
}
func (v *udpInfoValue) DeepCopyMapValue() bpf.MapValue {
	var newV udpInfoValue
	newV = *v
	return &newV
}

type udpSensorConfigKey struct {
	Zero uint32
}

func (k *udpSensorConfigKey) String() string             { return fmt.Sprintf("Zero: %d", k.Zero) }
func (k *udpSensorConfigKey) NewValue() bpf.MapValue     { return &ConfigValue{} }
func (k *udpSensorConfigKey) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(k) }
func (k *udpSensorConfigKey) DeepCopyMapKey() bpf.MapKey { return &udpSensorConfigKey{} }

type SubnetSelector struct {
	addr      [2]uint64
	ipv6      uint8
	prefixLen uint8
	Padding   [6]uint8
}

type ConfigValue struct {
	dnsPorts                 [maxDnsPorts]uint16
	watermarkEnable          uint64
	watermarkAvgWindowSizeMs uint64
	watermarkWindowSize      uint64
	watermarkTriggerPercent  uint64
	bootNs                   uint64
	latencyEnable            uint64
	latencySubnets           [maxLatencySubnets]SubnetSelector
	latencyPorts             [maxLatencyPorts]uint16
}

func (v *ConfigValue) String() string {
	return fmt.Sprintf("dnsPorts: %d, "+
		"watermarkEnable: %d, "+
		"watermarkAvgWindowSizeMs: %d, "+
		"watermarkWindowSize: %d, "+
		"watermarkTriggerPercent: %d", v.dnsPorts, v.watermarkEnable, v.watermarkAvgWindowSizeMs, v.watermarkWindowSize, v.watermarkTriggerPercent)
}
func (v *ConfigValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *ConfigValue) DeepCopyMapValue() bpf.MapValue {
	var n = *v
	return &n
}

// emitUdpEvent builds a udpEvent and expects caller to set the correct Op value.
func createUdpEvent(k *udpInfoKey, v *udpInfoValue, duration time.Duration) *layer3.MsgIPEventUnix {
	unix := layer3.MsgIPEventUnix{}

	unix.Common = processapi.MsgCommon{
		Op:    0,
		Size:  1,
		Ktime: v.Ktime,
	}
	unix.Tuple = api.MsgIPTuple{
		IPv6:  v.IPv6,
		SAddr: v.SAddr,
		DAddr: v.DAddr,
		SPort: v.SPort,
		DPort: v.DPort,
		Proto: 0,
	}
	unix.SockCookie = k.Cookie
	unix.Return = 0
	unix.ProcessKey = processapi.MsgExecveKey{
		Pid:   v.Pid,
		Ktime: v.PidKtime,
	}
	unix.SocketStats = api.MsgSocketStatsUnix{
		BytesSubmitted:   v.SubmittedBytes,
		BytesConsumed:    v.ConsumedBytes,
		BytesSent:        v.TXBytes,
		BytesReceived:    v.RXBytes,
		ConsumedSegs:     uint32(v.ConsumedSegs),
		SegsIn:           uint32(v.SegsIn),
		SubmittedSegs:    uint32(v.SubmittedSegs),
		SegsOut:          uint32(v.SegsOut),
		SkDrop:           v.SkDrops,
		SkbConsumeMisses: v.SkbConsumeMisses,
	}
	unix.Duration = duration
	return &unix
}

func createCloseEvent(k *udpInfoKey, v *udpInfoValue, closeTimeNs uint64) *layer3.MsgIPEventUnix {
	//	duration, err := ktime.NanoTimeSince(int64(v.CreateTime))
	var duration time.Duration
	if closeTimeNs > v.CreateTime {
		duration = time.Duration(closeTimeNs - v.CreateTime)
	} else {
		duration = 0
	}
	//	if err != nil {
	//		duration = time.Duration(0)
	//	}
	unix := createUdpEvent(k, v, duration)
	unix.Common.Op = ops.MSG_OP_UDPCLOSE

	return unix
}

func emitCloseEvent(k *udpInfoKey, v *udpInfoValue) {
	unix := createCloseEvent(k, v, v.Ktime)

	observer.AllListeners(unix)
}

func createStatEvent(k *udpInfoKey, v *udpInfoValue) *layer3.MsgIPEventUnix {
	unix := createUdpEvent(k, v, 0)
	unix.Common.Op = ops.MSG_OP_UDPSTATS

	return unix
}

func emitStatEvent(k *udpInfoKey, v *udpInfoValue) {
	unix := createStatEvent(k, v)

	observer.AllListeners(unix)
}

func udpResetEvent(curr, last *udpInfoValue) bool {
	// If we have fewer bytes or setgs than last measurement this is a
	// sure sign we had a data race. Counters in BPF side are monotonic
	// so a single entry will never be decrementing.
	if curr.ConsumedSegs < last.ConsumedSegs ||
		curr.ConsumedBytes < last.ConsumedBytes ||
		curr.SegsIn < last.SegsIn ||
		curr.RXBytes < last.RXBytes ||
		curr.SubmittedSegs < last.SubmittedSegs ||
		curr.SubmittedBytes < last.SubmittedBytes ||
		curr.SegsOut < last.SegsOut ||
		curr.TXBytes < last.TXBytes {
		return true
	}

	// Its tempting to do a check here to test if the segs are the
	// same, but with different byte counts. The idea being bytes
	// can't appear without a segs inc as well. However, because
	// walker might read partial status of an update its possible
	// in the normal case for this so we can't use this test to
	// indicate a data race happened.
	//
	// Unfortunately what we can't learn is if datapath replaces
	// an old entry with a valid new entry. At which point we will
	// incorrectly diff the entry instead of add the entire value.
	// Hopefully this is rare and experiments show this to be the
	// case. Also note its more common on RX than TX because TX is
	// sender side and would mean application is submitting multiple
	// syscall sends on the same socket where as RX can be triggered
	// by receiving multiple packets on the same socket on the same
	// core.
	return false
}

func udpDiffValues(key *udpInfoKey, last, curr *udpInfoValue) (udpInfoValue, error) {
	// The ktime check is to handle a small but observed race condition where
	// we can read a ktime earlier than a ktime we just read. It requires some
	// unlucky timing but here we go.
	//
	//  cpu0                      cpu1                    cpu2
	// 1 <- ktime_get_ns()
	//                         2 <- ktime_get_ns
	//                         v->ktime = 2
	//                                                 v2 <- read_map_key()
	//  v->ktime = 1
	//                                                 v1 <- read_map_key()
	//
	// and violla time travel from read map side. So just skip these entries
	// using v2 and because we have atomic only incrementing counters we
	// eventually we get a good entry and correct for any bytes at that time.
	if curr.Ktime < last.Ktime {
		return udpInfoValue{}, fmt.Errorf("UDP Skip OOO Event")
	}

	// Test if this curr and last pair indicate a race condition in the
	// datapath caused a map_value to replace the last entry. In this case
	// to avoid dropping bytes on the counter we do not diff the values.
	if udpResetEvent(curr, last) {
		return *curr, nil
	}

	return udpInfoValue{
		SubmittedBytes:   curr.SubmittedBytes - last.SubmittedBytes,
		ConsumedBytes:    curr.ConsumedBytes - last.ConsumedBytes,
		TXBytes:          curr.TXBytes - last.TXBytes,
		RXBytes:          curr.RXBytes - last.RXBytes,
		ConsumedSegs:     curr.ConsumedSegs - last.ConsumedSegs,
		SubmittedSegs:    curr.SubmittedSegs - last.SubmittedSegs,
		SegsIn:           curr.SegsIn - last.SegsIn,
		SegsOut:          curr.SegsOut - last.SegsOut,
		SkDrops:          curr.SkDrops - last.SkDrops,
		SkbConsumeMisses: curr.SkbConsumeMisses - last.SkbConsumeMisses,
		Ktime:            curr.Ktime,
		PidKtime:         curr.PidKtime,
		Pid:              curr.Pid,
		IPv6:             curr.IPv6,
		SAddr:            curr.SAddr,
		DAddr:            curr.DAddr,
		SPort:            curr.SPort,
		DPort:            curr.DPort,
	}, nil
}

func udpGcCb(m *bpf.Map, k bpf.MapKey, v bpf.MapValue) {
	socketmetrics.UDPGCMetricInc(socketmetrics.UDPGCTypeTotalRetrieve)
	udpValue := v.(*udpInfoValue)
	udpKey := k.(*udpInfoKey)

	// This case handles kernels <5.10 where map will have udp stats
	// that are not yet associated to a process between IP stack and
	// socket handling of the UDP data.
	if udpValue.Pid == 0 {
		socketmetrics.UDPGCMetricInc(socketmetrics.UDPGCTypePidIsZero)
		return
	}

	t, err := ktime.NanoTimeSince(int64(udpValue.Ktime))
	if err != nil {
		logger.GetLogger().WithError(err).WithField("time", udpValue.Ktime).Warn("UDP NanoTimeSince failed.")
		socketmetrics.UDPGCMetricInc(socketmetrics.UDPGCTypeNanoTimeSinceFailure)
		return
	}

	last, ok := stats.Get(*udpKey)
	if ok {
		if *udpValue != last {
			diffValue, err := udpDiffValues(udpKey, &last, udpValue)
			if err == nil {
				mapUpdate := v.DeepCopyMapValue().(*udpInfoValue)
				udpKey = k.DeepCopyMapKey().(*udpInfoKey)
				stats.Add(*udpKey, *mapUpdate)
				emitStatEvent(udpKey, &diffValue)
			} else {
				socketmetrics.UDPGCMetricInc(socketmetrics.UDPGCTypeDiffValuesFailure)
			}
		}
	} else {
		udpValue = v.DeepCopyMapValue().(*udpInfoValue)
		stats.Add(*udpKey, *udpValue)
		emitStatEvent(udpKey, udpValue)
	}

	if t > UdpDeleteInterval {
		emitCloseEvent(udpKey, udpValue)
		stats.Remove(*udpKey)
		if pseudoSockets[udpKey.Cookie] != nil {
			delete(pseudoSockets[udpKey.Cookie], udpPseudoSocket{DAddr: udpKey.DAddr, DPort: udpKey.DPort, IPv6: udpKey.IPv6})
		}
		m.DeleteKey(k)
	}
	lrumetrics.LruMapSizeSet("lru_udp_stats_map", stataCacheSize, float64(stats.Len()))
}

func runUdpGC() {
	statsUpdate.Lock()
	defer statsUpdate.Unlock()
	socketmetrics.UDPGCMetricInc(socketmetrics.UDPGCTypeTicker)
	file := filepath.Join(bpf.MapPrefixPath(), UdpMapName)

	m, err := bpf.OpenMap(file)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", file).Warn("UDP GC failed to open file")
		socketmetrics.UDPGCMetricInc(socketmetrics.UDPGCTypeFailedToOpenMap)
		return
	}
	defer m.Close()
	m.MapKey = &udpInfoKey{}
	m.KeySize = 32
	m.MapValue = &udpInfoValue{}
	m.DumpWithCallback(udpGcCb)
}

type udpSensor struct {
	name string
}

func FdCallback(socket *ip.FdLookupValue, pid uint32) {
	saddr := reader.GetIP(socket.Saddr, 0, socket.IPv6 != 0)
	daddr := reader.GetIP(socket.Daddr, 0, socket.IPv6 != 0)
	logger.GetLogger().WithFields(logrus.Fields{"Pid": pid, "Saddr": saddr, "Daddr": daddr, "Sport": socket.Sport, "Dport": socket.Dport, "Protocol": socket.Protocol, "State": socket.State}).Debug("Discovered UDP Socket")
}

func (udp *udpSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	if !configured {
		// As well as loading the existing UDP sockets, ip.LoadSockets will also set the
		// proto_shift field in the fd_lookup_config_map which indicates whether the
		// protocol field of struct sock needs shifting or not.
		// If ip.LoadSockets is disabled or moved, then add a call to ip.ProtocolShift
		// to cause the proto_shift field to be set.
		ip.LoadSockets(FdCallback, IPPROTO_UDP)
	}

	if args.Load.Type == "cgrp_ingress" || args.Load.Type == "cgrp_egress" {
		err := cgroup.LoadCgroupProgram(args.BPFDir, args.MapDir, args.CiliumDir, args.Load, args.Verbose)
		if err != nil {
			return err
		}
	} else if args.Load.Type == "kprobe_udp" {
		err := program.LoadKprobeProgram(args.BPFDir, args.MapDir, args.Load, args.Verbose)
		if err != nil {
			return err
		}
	} else if args.Load.Type == "tc_egress" {
		err := tc.LoadTC(args.BPFDir, args.MapDir, args.CiliumDir, args.Load, args.Version, args.Verbose, [128]byte{})
		if err != nil {
			return err
		}
	}
	if !configured {
		if err := configureUdpSensor(args.MapDir, UdpConfigMapName, Config); err != nil {
			return err
		}
		if err := ip.ConfigureProtocolShift(args.MapDir); err != nil {
			return err
		}
		configured = true
	}
	return nil
}

func configureUdpSensor(mapDir string, mapName string, config *ConfigValue) error {
	m, err := bpf.OpenMap(filepath.Join(mapDir, mapName))
	if err != nil {
		return err
	}
	defer m.Close()

	key := &udpSensorConfigKey{
		Zero: uint32(0),
	}
	m.Update(key, config)
	logger.GetLogger().WithField("config", config.String()).Info("Configured UDP sock statistic sampler: ")
	return nil
}

func unloadUdpSensor() error {
	// We want to make sure we stand configuration up when loading/unloading the sensor.
	configured = false

	gcTimer.Stop()
	if watermarkEnabled {
		burstEvents.Stop()
	}
	return nil
}

func EnableUdpParser(cgroup bool, interval time.Duration) *sensors.Sensor {
	var progs []*program.Program
	var maps []*program.Map
	var versionStr string

	// We want to make sure we stand configuration up when loading/unloading the sensor.
	configured = false

	if !kernels.MinKernelVersion("5.4.0") || !cgroup {
		progs = []*program.Program{
			SkAllocRetLazy,
			SockReleaseLazy,
			InetSendRecvLazy,
			Udp4SendLazy,
			Udp4RetSendLazy,
			Udp6SendLazy,
			Udp6RetSendLazy,
			UdpRecvLazy,
			TCEgressTimestamp,
		}
		maps = []*program.Map{
			UdpMapLazyKprobe,
			UdpRetprobeMapLazy,
			UdpConfigLazyMapKprobe,
			UdpPayloadLazyMapKprobe,
			SocketCookieMapLazy,
			SocketCookieStatsLazy,
			FdLookupConfigMapLazy,
		}
		dns.LazyDns = true
		versionStr = "__udp_sensor_probe__"
	} else if !kernels.MinKernelVersion("5.10.0") || !cgroup {
		progs = []*program.Program{
			SkAllocRetLazy,
			SockReleaseLazy,
			InetSendLazy,
			InetRecvLazy,
			Udp4SendLazy,
			Udp4RetSendLazy,
			Udp6SendLazy,
			Udp6RetSendLazy,
			UdpRecvLazy,
			TCEgressTimestamp,
		}
		maps = []*program.Map{
			UdpMapLazy,
			UdpRetprobeMapLazy,
			UdpConfigLazyMap,
			UdpPayloadLazyMap,
			SocketCookieMapLazy,
			SocketCookieStatsLazy,
			FdLookupConfigMapLazy,
		}
		dns.LazyDns = true
		versionStr = "__udp_sensor_probe__"
	} else {
		progs = []*program.Program{
			SockCreate,
			SockRelease,
			InetSend,
			InetRecv,
			Udp4Send,
			Udp4RetSend,
			Udp6Send,
			Udp6RetSend,
			UdpRecv,
			TCEgressTimestamp,
		}
		maps = []*program.Map{
			UdpMap,
			UdpRetprobeMap,
			UdpConfigMap,
			UdpPayloadMap,
			SocketCookieMap,
			SocketCookieStats,
			FdLookupConfigMap,
		}
		versionStr = "__udp_sensor_cgroup__"
	}

	gcTimer.Start(interval)
	logger.GetLogger().WithFields(logrus.Fields{
		"sensorName":     versionStr,
		"statsInterval":  interval,
		"deleteInterval": UdpDeleteInterval,
	}).Infof("Enable UDP")
	udpSensor := sensors.SensorBuilder(versionStr, progs, maps)
	udpSensor.UnloadHook = unloadUdpSensor
	return udpSensor
}

func (udp *udpSensor) SpecHandler(raw interface{}) (*sensors.Sensor, error) {
	spec := raw.(*v1alpha1.TracingPolicySpec)
	var interval = time.Duration(UdpGCIntervalDefault)

	if !spec.Parser.Udp.Enable {
		return nil, nil
	}
	if spec.Parser.Udp.StatsInterval > 0 {
		interval = time.Duration(spec.Parser.Udp.StatsInterval) * time.Second
	}
	if spec.Parser.Udp.DeleteIdleSocketInterval > 0 {
		UdpDeleteInterval = time.Duration(spec.Parser.Udp.DeleteIdleSocketInterval) * time.Second
	}
	Config, _ = ParseUdpSpec(spec)
	return EnableUdpParser(spec.Parser.Udp.Cgroup, interval), nil
}

func handleUdp(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgIPEvent{}
	err := binary.Read(r, native_endian.NativeEndian(), &m)
	if err != nil {
		return nil, err
	}
	msgUnix := ip.MsgToIPUnix(&m, false)

	if m.Common.Op == ops.MSG_OP_UDPCONNECT {
		// Store the pseudo-socket against this cookie
		pseudoSockList := pseudoSockets[m.SockCookie]
		if pseudoSockList == nil {
			pseudoSockets[m.SockCookie] = make(map[udpPseudoSocket]bool)
		}
		pseudoSockets[m.SockCookie][udpPseudoSocket{DAddr: m.Tuple.DAddr, DPort: m.Tuple.DPort, IPv6: m.Tuple.IPv6}] = true
	} else if m.Common.Op == ops.MSG_OP_UDPCLOSE {
		// Close event contains the socket cookie that was closed. We use this
		// as a key into the pseudoSockets map to retrieve the list of pseudo-
		// sockets. Then we send a stats event and a close event for each one,
		// before deleting them from the maps.

		// Access to stats is protected by a lock to prevent corruption.
		statsUpdate.Lock()
		defer statsUpdate.Unlock()

		pseudoSocketList := pseudoSockets[m.SockCookie]
		if len(pseudoSocketList) == 0 {
			return nil, nil
		}

		mapFile := filepath.Join(bpf.MapPrefixPath(), UdpMapName)
		udpMap, err := ebpf.LoadPinnedMap(mapFile, nil)
		if err != nil {
			logger.GetLogger().WithError(err).WithField("file", mapFile).Warn("UDP Close event failed to open map")
			return nil, fmt.Errorf("failed to open udp info map")
		}
		defer udpMap.Close()

		closeEvents := []observer.Event{}

		for psock := range pseudoSocketList {
			// Send stats event
			udpKey := udpInfoKey{Cookie: m.SockCookie, DAddr: psock.DAddr, DPort: psock.DPort, IPv6: psock.IPv6}
			var udpValue udpInfoValue
			err := udpMap.Lookup(udpKey, &udpValue)
			if err != nil {
				continue
			}

			entry, ok := stats.Get(udpKey)
			if ok {
				// Send stats event for the difference from the last one
				if udpValue != entry {
					diffValue, err := udpDiffValues(&udpKey, &entry, &udpValue)
					if err == nil {
						closeEvents = append(closeEvents, createStatEvent(&udpKey, &diffValue))
					} else {
						socketmetrics.UDPGCMetricInc(socketmetrics.UDPGCTypeDiffValuesFailure)
					}
				}
				// Send close event – Duration actually indicates close time
				closeEvents = append(closeEvents, createCloseEvent(&udpKey, &udpValue, m.Duration))
				stats.Remove(udpKey)
			} else {
				// Send stats event – no stats event previously sent
				closeEvents = append(closeEvents, createStatEvent(&udpKey, &udpValue))
				// Send close event – Duration actually indicates close time
				closeEvents = append(closeEvents, createCloseEvent(&udpKey, &udpValue, m.Duration))
			}
		}

		delete(pseudoSockets, m.SockCookie)
		lrumetrics.LruMapSizeSet("lru_udp_stats_map", stataCacheSize, float64(stats.Len()))
		return closeEvents, nil
	}
	return []observer.Event{msgUnix}, nil
}

func init() {
	AddUDP()
}

func AddUDP() {
	var err error

	stats, err = lru.New[udpInfoKey, udpInfoValue](stataCacheSize)
	if err != nil {
		logger.GetLogger().WithError(err).Errorf("UDP cache failed. Disabling UDP")
		return
	}

	udp := &udpSensor{
		name: "UDP sensor",
	}
	sensors.RegisterProbeType("udp_sensor", udp)
	sensors.RegisterSpecHandlerAtInit(udp.name, udp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_UDPCONNECT, handleUdp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_UDPSTATS, handleUdp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_UDPPAYLOAD, handleUdpPayload)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_UDPCLOSE, handleUdp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_PROCESS_NETWORK_BURST, burstEvents.HandleProcessNetworkBurst)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_IP_ERROR, ip.HandleIpError)

	sensors.RegisterProbeType("cgrp_ingress", udp)
	sensors.RegisterProbeType("cgrp_egress", udp)
	sensors.RegisterProbeType("kprobe_udp", udp)
	sensors.RegisterProbeType("tc_egress", udp)
}
