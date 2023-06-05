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
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/timer"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/sirupsen/logrus"
	"github.com/yalue/native_endian"
	"golang.org/x/sys/unix"

	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	"github.com/isovalent/hubble-fgs/pkg/grpc/udp_seq_check_error"
	"github.com/isovalent/hubble-fgs/pkg/metrics/lrumetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
	"github.com/isovalent/hubble-fgs/pkg/reader/network"
	"github.com/isovalent/hubble-fgs/pkg/sensors/ip"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networkWatermarksEvents"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networklatency"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/cgroup"
	"github.com/isovalent/hubble-fgs/pkg/sensors/udp/udpconfig"
)

const (
	UdpGCIntervalDefault = time.Duration(60 * time.Second)
	UdpMapName           = "udp_map"
	UdpRetprobeMapName   = "udp_retprobe_map"
	UdpRetprobeStatsName = "udp_retprobe_map_stats"
	UdpConfigMapName     = "udp_config_map"
	UdpPayloadMapName    = "udp_payload_map"
	SocketMapName        = "socket_map"

	stataCacheSize = 32000
)

type udpPseudoSocket struct {
	DAddr [2]uint64
	DPort uint16
	IPv6  uint8
}

var (
	UdpDeleteInterval = time.Duration(600 * time.Second)
	udpStatsEnable    = false

	stats *lru.Cache[udpInfoKey, udpInfoValue]

	Config           ConfigValue
	configured       = false
	gcTimer          = timer.NewPeriodicTimer("UDP GC Timer", runUdpGC, true)
	watermarkEnabled = false

	pseudoSockets       = make(map[uint64](map[udpPseudoSocket]bool))
	pseudoSocketsUpdate sync.Mutex

	timestampEnabled = false
)

var (
	SkAllocRet = program.Builder(
		"bpf_sock_create.o",
		"sk_alloc",
		"kretprobe/sk_alloc",
		"kretprobe_sk_alloc",
		"kprobe",
	).SetRetProbe(true)

	SockRelease = program.Builder(
		"bpf_sock_release.o",
		"__sk_free",
		"kprobe/__sk_free",
		"kprobe___sk_free",
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

	// Shared socket cookie infrastructure
	SocketCookieMap   = program.MapBuilder(SocketMapName, Udp4Send)
	SocketCookieStats = program.MapBuilder("socket_map_stats", Udp4Send)

	// UDP maps
	UdpMap                     = program.MapBuilder(UdpMapName, InetSend)
	UdpMapLazy                 = program.MapBuilder(UdpMapName, InetSendLazy)
	UdpMapLazyKprobe           = program.MapBuilder(UdpMapName, InetSendRecvLazy)
	UdpRetprobeMap             = program.MapBuilder(UdpRetprobeMapName, Udp4Send)
	UdpRetprobeStats           = program.MapBuilder(UdpRetprobeStatsName, Udp4Send)
	UdpConfigMap               = program.MapBuilder(UdpConfigMapName, InetSend)
	UdpConfigLazyMap           = program.MapBuilder(UdpConfigMapName, InetSendLazy)
	UdpConfigLazyMapKprobe     = program.MapBuilder(UdpConfigMapName, InetSendRecvLazy)
	UdpPayloadMap              = program.MapBuilder(UdpPayloadMapName, InetSend)
	UdpPayloadLazyMap          = program.MapBuilder(UdpPayloadMapName, InetSendLazy)
	UdpPayloadLazyMapKprobe    = program.MapBuilder(UdpPayloadMapName, InetSendRecvLazy)
	FdLookupConfigMap          = program.MapBuilder(ip.FdLookupConfigMapName, SockRelease)
	LatencyConfigMap           = program.MapBuilder(networklatency.ConfigMapName, InetRecv)
	LatencyConfigMapLazy       = program.MapBuilder(networklatency.ConfigMapName, InetRecvLazy)
	LatencyConfigMapLazyKprobe = program.MapBuilder(networklatency.ConfigMapName, InetSendRecvLazy)
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
	Buckets          [8]uint64
	LatencySum       uint64
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

type ConfigValue struct {
	dnsPorts                      [maxDnsPorts]uint16
	watermarksEnable              uint64
	watermarksAvgWindowSizeMs     uint64
	watermarksWindowSize          uint64
	watermarksBurstTriggerPercent uint64
	watermarksDipTriggerPercent   uint64
	seqCheckAppId                 uint64
	seqCheckPorts                 [maxSeqCheckPorts]uint16
}

func (v *ConfigValue) String() string {
	return fmt.Sprintf("dnsPorts: %d, "+
		"watermarkEnable: %d, "+
		"watermarkAvgWindowSizeMs: %d, "+
		"watermarkWindowSize: %d, "+
		"watermarkBurstTriggerPercent: %d, "+
		"watermarkDipTriggerPercent: %d",
		v.dnsPorts, v.watermarksEnable, v.watermarksAvgWindowSizeMs, v.watermarksWindowSize, v.watermarksBurstTriggerPercent,
		v.watermarksDipTriggerPercent)
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
		Latency: api.Histogram{
			B00: v.Buckets[0],
			B01: v.Buckets[1],
			B10: v.Buckets[2],
			B25: v.Buckets[3],
			B50: v.Buckets[4],
			B75: v.Buckets[5],
			B90: v.Buckets[6],
			B99: v.Buckets[7],
		},
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

func udpDiffLatency(last, curr *[8]uint64) [8]uint64 {
	return [8]uint64{
		curr[0] - last[0],
		curr[1] - last[1],
		curr[2] - last[2],
		curr[3] - last[3],
		curr[4] - last[4],
		curr[5] - last[5],
		curr[6] - last[6],
		curr[7] - last[7],
	}
}

func udpDiffValues(_ *udpInfoKey, last, curr *udpInfoValue) (udpInfoValue, error) {
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
		Buckets:          udpDiffLatency(&last.Buckets, &curr.Buckets),
	}, nil
}

var (
	deleteLastKey *udpInfoKey
)

func udpGcCb(m *bpf.Map, k bpf.MapKey, v bpf.MapValue) {
	// Access to TypeTotalRetrieve metrics is serialized by UdpGC.
	socketmetrics.UDPGCMetricIncNoLock(socketmetrics.UDPGCTypeTotalRetrieve)
	udpValue := v.(*udpInfoValue)
	udpKey := k.(*udpInfoKey)

	// If we delete the key out from under the walker it can't find the
	// next key and the result is we start walking from the first element
	// again. Giving us something like O(n!) for walking a list with lots
	// of deletes.
	if deleteLastKey != nil {
		if err := m.DeleteKey(deleteLastKey); err != nil {
			logger.GetLogger().WithError(err).WithField("key", deleteLastKey).Warn("delete key failed.")
		}
		deleteLastKey = nil
	}

	t, err := ktime.NanoTimeSince(int64(udpValue.Ktime))
	if err != nil {
		logger.GetLogger().WithError(err).WithField("time", udpValue.Ktime).Warn("UDP NanoTimeSince failed.")
		socketmetrics.UDPGCMetricInc(socketmetrics.UDPGCTypeNanoTimeSinceFailure)
		return
	}

	// This case handles kernels <5.10 where map will have udp stats
	// that are not yet associated to a process between IP stack and
	// socket handling of the UDP data.
	if udpValue.Pid == 0 {
		socketmetrics.UDPGCMetricInc(socketmetrics.UDPGCTypePidIsZero)
	} else {
		if udpStatsEnable {
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
						socketmetrics.UDPGCMetricInc(socketmetrics.UDPGCTypeDiffValuesFailureGC)
					}
				}
			} else {
				udpValue = v.DeepCopyMapValue().(*udpInfoValue)
				stats.Add(*udpKey, *udpValue)
				emitStatEvent(udpKey, udpValue)
			}
		}
	}

	if t > UdpDeleteInterval {
		if udpValue.Pid != 0 {
			emitCloseEvent(udpKey, udpValue)
		}
		stats.Remove(*udpKey)
		pseudoSocketsUpdate.Lock()
		if pseudoSockets[udpKey.Cookie] != nil {
			delete(pseudoSockets[udpKey.Cookie], udpPseudoSocket{DAddr: udpKey.DAddr, DPort: udpKey.DPort, IPv6: udpKey.IPv6})
		}
		pseudoSocketsUpdate.Unlock()
		deleteLastKey = udpKey
	}
	lrumetrics.LruMapSizeSet("lru_udp_stats_map", stataCacheSize, float64(stats.Len()))
}

func runUdpGC() {
	// Access to UDPGCTypeTicker is serialized by UdpGC
	socketmetrics.UDPGCMetricIncNoLock(socketmetrics.UDPGCTypeTicker)

	file := filepath.Join(bpf.MapPrefixPath(), UdpMapName)

	m, err := bpf.OpenMap(file)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", file).Warn("UDP GC failed to open file")
		// lock is safe only done here inside GC
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
	saddr := network.GetIP(socket.Saddr, 0, socket.IPv6 != 0)
	daddr := network.GetIP(socket.Daddr, 0, socket.IPv6 != 0)
	logger.GetLogger().WithFields(logrus.Fields{"Pid": pid, "Saddr": saddr, "Daddr": daddr, "Sport": socket.Sport, "Dport": socket.Dport, "Protocol": socket.Protocol, "State": socket.State}).Debug("Discovered UDP Socket")
}

func (udp *udpSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	if !configured {
		ip.LoadSockets(FdCallback, unix.IPPROTO_UDP)
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
	} else if args.Load.Type == "udp_tc_egress" {
		err := networklatency.AttachTc(args)
		if err != nil {
			return err
		}
	}
	if !configured {
		if err := configureUdpSensor(args.MapDir, UdpConfigMapName, Config); err != nil {
			return err
		}
		logger.GetLogger().WithField("timestampEnabled", timestampEnabled).Debug("UDP Loader")
		if timestampEnabled {
			if err := networklatency.ConfigureLatency(args.MapDir, unix.IPPROTO_UDP, udpconfig.LatencyConfig); err != nil {
				return err
			}
			networklatency.Start()
		}
		configured = true
	}
	return nil
}

func configureUdpSensor(mapDir string, mapName string, config ConfigValue) error {
	m, err := bpf.OpenMap(filepath.Join(mapDir, mapName))
	if err != nil {
		return err
	}
	defer m.Close()

	key := &udpSensorConfigKey{
		Zero: uint32(0),
	}
	m.Update(key, &config)
	logger.GetLogger().WithField("config", config.String()).Info("Configured UDP sock statistic sampler: ")
	return nil
}

func unloadUdpSensor() error {
	// We want to make sure we stand configuration up when loading/unloading the sensor.
	configured = false

	gcTimer.Stop()
	networklatency.Stop(unix.IPPROTO_UDP)
	if watermarkEnabled {
		networkWatermarksEvents.Stop(unix.IPPROTO_UDP)
	}
	return nil
}

func EnableUdpParser(cgroup, timestampEnable bool, interval time.Duration) *sensors.Sensor {
	var progs []*program.Program
	var maps []*program.Map
	var versionStr string

	// We want to make sure we stand configuration up when loading/unloading the sensor.
	configured = false

	if !kernels.MinKernelVersion("5.4.0") || !cgroup {
		progs = []*program.Program{
			SkAllocRet,
			SockRelease,
			InetSendRecvLazy,
			Udp4Send,
			Udp4RetSend,
			Udp6Send,
			Udp6RetSend,
			UdpRecv,
		}
		maps = []*program.Map{
			UdpMapLazyKprobe,
			UdpRetprobeMap,
			UdpRetprobeStats,
			UdpConfigLazyMapKprobe,
			UdpPayloadLazyMapKprobe,
			SocketCookieMap,
			SocketCookieStats,
			FdLookupConfigMap,
			LatencyConfigMapLazyKprobe,
		}
		dns.LazyDns = true
		versionStr = "__udp_sensor_probe__"
	} else if !kernels.MinKernelVersion("5.10.0") {
		progs = []*program.Program{
			SkAllocRet,
			SockRelease,
			InetSendLazy,
			InetRecvLazy,
			Udp4Send,
			Udp4RetSend,
			Udp6Send,
			Udp6RetSend,
			UdpRecv,
		}
		maps = []*program.Map{
			UdpMapLazy,
			UdpRetprobeMap,
			UdpRetprobeStats,
			UdpConfigLazyMap,
			UdpPayloadLazyMap,
			SocketCookieMap,
			SocketCookieStats,
			FdLookupConfigMap,
			LatencyConfigMapLazy,
		}
		dns.LazyDns = false
		versionStr = "__udp_sensor_probe__"
	} else {
		progs = []*program.Program{
			SkAllocRet,
			SockRelease,
			InetSend,
			InetRecv,
			Udp4Send,
			Udp4RetSend,
			Udp6Send,
			Udp6RetSend,
			UdpRecv,
		}
		maps = []*program.Map{
			UdpMap,
			UdpRetprobeMap,
			UdpRetprobeStats,
			UdpConfigMap,
			UdpPayloadMap,
			SocketCookieMap,
			SocketCookieStats,
			FdLookupConfigMap,
			LatencyConfigMap,
		}
		dns.LazyDns = false
		versionStr = "__udp_sensor_probe__"
	}

	if timestampEnable {
		timestampEnabled = true
		timestampProg, err := networklatency.TCEgressTimestamp(unix.IPPROTO_UDP)
		if err == nil {
			progs = append(progs, timestampProg)
		} else {
			logger.GetLogger().Warn("UDP unsupported by network latency")
		}
	}

	gcTimer.Start(interval)
	logger.GetLogger().WithFields(logrus.Fields{
		"sensorName":     versionStr,
		"statsInterval":  interval,
		"deleteInterval": UdpDeleteInterval,
		"metrics":        udpconfig.MetricsEnabled,
	}).Infof("Enable UDP")
	udpSensor := sensors.SensorBuilder(versionStr, progs, maps)
	udpSensor.UnloadHook = unloadUdpSensor
	return udpSensor
}

func (udp *udpSensor) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	fid policyfilter.PolicyID,
) (*sensors.Sensor, error) {
	spec := policy.TpSpec()

	if !spec.Parser.Udp.Enable {
		return nil, nil
	}

	if fid != policyfilter.NoFilterID {
		return nil, fmt.Errorf("udp sensor does not implement policy filtering")
	}

	if spec.Parser.Udp.Metrics != nil {
		udpconfig.MetricsEnabled = spec.Parser.Udp.Metrics.Enable
	} else {
		udpconfig.MetricsEnabled = true
	}

	/* UDP GC interval tracks UDP stats events and UDP delete events. If
	 * stats interval is 0 indicating no stats are wanted then we program
	 * the timer using the Delete interval and disable stats. Otherwise
	 * we use the stats interval and expect users will program this so that
	 * statsInterval < deleteIntervaInterval. This is a bit squishy, to be
	 * cleaned up and clarrified in docs at some point.
	 */
	var interval = time.Duration(UdpGCIntervalDefault)
	if spec.Parser.Udp.StatsInterval > 0 {
		interval = time.Duration(spec.Parser.Udp.StatsInterval) * time.Second
		udpStatsEnable = true
	} else {
		udpStatsEnable = false
	}

	if spec.Parser.Udp.DeleteIdleSocketInterval > 0 {
		UdpDeleteInterval = time.Duration(spec.Parser.Udp.DeleteIdleSocketInterval) * time.Second
		if !udpStatsEnable {
			interval = UdpDeleteInterval
		}
	}
	Config, udpconfig.LatencyConfig = ParseUdpSpec(spec)
	logger.GetLogger().WithField("enable", spec.Parser.Udp.Latency.Enable).Debug("UDP Latency config")
	return EnableUdpParser(spec.Parser.Udp.Cgroup, spec.Parser.Udp.Latency.Enable, interval), nil
}

func handleUdp(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgIPEvent{}
	err := binary.Read(r, native_endian.NativeEndian(), &m)
	if err != nil {
		return nil, err
	}
	msgUnix := ip.MsgToIPUnix(&m, false, true)

	if m.Common.Op == ops.MSG_OP_UDPCONNECT {
		// Store the pseudo-socket against this cookie
		pseudoSocketsUpdate.Lock()
		pseudoSockList := pseudoSockets[m.SockCookie]
		if pseudoSockList == nil {
			pseudoSockets[m.SockCookie] = make(map[udpPseudoSocket]bool)
		}
		pseudoSockets[m.SockCookie][udpPseudoSocket{DAddr: m.Tuple.DAddr, DPort: m.Tuple.DPort, IPv6: m.Tuple.IPv6}] = true
		pseudoSocketsUpdate.Unlock()
	} else if m.Common.Op == ops.MSG_OP_UDPCLOSE {
		// Close event contains the socket cookie that was closed. We use this
		// as a key into the pseudoSockets map to retrieve the list of pseudo-
		// sockets. Then we send a stats event and a close event for each one,
		// before deleting them from the maps.

		// Access to stats is protected by atomic operations we don't want to
		// serialize handlers on this lock. For mostly error cases.
		pseudoSocketsUpdate.Lock()
		pseudoSocketList := pseudoSockets[m.SockCookie]
		pseudoSocketsUpdate.Unlock()
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

		pseudoSocketsUpdate.Lock()
		delete(pseudoSockets, m.SockCookie)
		pseudoSocketsUpdate.Unlock()
		lrumetrics.LruMapSizeSet("lru_udp_stats_map", stataCacheSize, float64(stats.Len()))
		return closeEvents, nil
	}
	return []observer.Event{msgUnix}, nil
}

func MsgToUdpSeqErrorUnix(m *api.MsgUdpSeqCheckErrorEvent) *udp_seq_check_error.MsgUdpSeqCheckErrorEventUnix {
	unix := &udp_seq_check_error.MsgUdpSeqCheckErrorEventUnix{}

	unix.Common = m.Common
	unix.ProcessKey = m.ProcessKey
	unix.Tuple = m.Tuple
	unix.SockCookie = m.SockCookie
	unix.ApplicationId = m.ApplicationId
	unix.AppSpecificId = m.AppSpecificId
	unix.SeqNumExpected = m.SeqNumExpected
	unix.SeqNumReceived = m.SeqNumReceived

	return unix
}

func handleUdpSeqError(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgUdpSeqCheckErrorEvent{}
	err := binary.Read(r, native_endian.NativeEndian(), &m)
	if err != nil {
		return nil, err
	}
	msgUnix := MsgToUdpSeqErrorUnix(&m)

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
	sensors.RegisterPolicyHandlerAtInit(udp.name, udp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_UDPCONNECT, handleUdp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_UDPSTATS, handleUdp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_UDPPAYLOAD, handleUdpPayload)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_UDPCLOSE, handleUdp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_PROCESS_NETWORK_WATERMARK, networkWatermarksEvents.HandleProcessNetworkWatermarks)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_IP_ERROR, ip.HandleIpError)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_UDP_SEQ_ERROR, handleUdpSeqError)

	sensors.RegisterProbeType("cgrp_ingress", udp)
	sensors.RegisterProbeType("cgrp_egress", udp)
	sensors.RegisterProbeType("kprobe_udp", udp)
	sensors.RegisterProbeType("udp_tc_egress", udp)
}
