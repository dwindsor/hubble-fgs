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
	"time"
	"unsafe"

	lru "github.com/hashicorp/golang-lru"
	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/grpc"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/metrics"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/sensors/burstEventsPoll"
	"github.com/yalue/native_endian"

	"github.com/sirupsen/logrus"
)

const (
	UdpGCIntervalDefault = time.Duration(60 * time.Second)
	UdpMapName           = "udp_map"
	UdpRetprobeMapName   = "udp_retprobe_map"

	stataCacheSize = 32000
)

var (
	UdpDeleteInterval = time.Duration(600 * time.Second)

	stats *lru.Cache

	Config     *ConfigValue
	configured = false
)

var (
	SockCreate = sensors.ProgramBuilder(
		"bpf_sock.o",
		"sock_create",
		"cgroup/sock_create",
		"cgroup_sock_create",
		"cgrp_socket")

	SockRelease = sensors.ProgramBuilder(
		"bpf_sock_release.o",
		"inet_release",
		"kprobe/inet_release",
		"kprobe_sock_release",
		"kprobe")

	InetSend = sensors.ProgramBuilder(
		"bpf_inet_send.o",
		"inet_send",
		"cgroup_skb/egress",
		"cgroup_skb_egress",
		"cgrp_egress",
	)

	InetRecv = sensors.ProgramBuilder(
		"bpf_inet_send.o",
		"inet_recv",
		"cgroup_skb/ingress",
		"cgroup_skb_ingress",
		"cgrp_ingress",
	)

	InetSendLazy = sensors.ProgramBuilder(
		"bpf_inet_send_lazy.o",
		"inet_lazy_send",
		"cgroup_skb/egress",
		"cgroup_skb_egress",
		"cgrp_egress",
	)

	InetRecvLazy = sensors.ProgramBuilder(
		"bpf_inet_send_lazy.o",
		"inet_lazy_recv",
		"cgroup_skb/ingress",
		"cgroup_skb_ingress",
		"cgrp_ingress",
	)

	UdpSend = sensors.ProgramBuilder(
		"bpf_udp_sendmsg.o",
		"udp_sendmsg",
		"kprobe/udp_sendmsg",
		"kprobe_udp_sendmsg",
		"kprobe",
	)

	UdpRetSend = sensors.ProgramBuilder(
		"bpf_udp_sendmsg.o",
		"udp_sendmsg",
		"kretprobe/udp_sendmsg",
		"kretprobe_udp_sendmsg",
		"kprobe",
	).SetRetProbe(true)

	UdpRecv = sensors.ProgramBuilder(
		"bpf_udp_sendmsg.o",
		"skb_consume_udp",
		"kprobe/skb_consume_udp",
		"kprobe_skb_consume_udp",
		"kprobe",
	)

	SocketCookieMap        = sensors.MapBuilder("socket_cookie_to_proc_map", sensors.TCPConnect)
	UdpMap                 = sensors.MapBuilder(UdpMapName, InetSend)
	UdpMapKprobe           = sensors.MapBuilder(UdpMapName, UdpSend)
	UdpRetprobeMap         = sensors.MapBuilder(UdpRetprobeMapName, UdpSend)
	UdpConfigMap           = sensors.MapBuilder("udp_config_map", InetSend)
	UdpConfigLazyMap       = sensors.MapBuilder("udp_config_map", InetSendLazy)
	ProcessNetworkBurstMap = sensors.MapBuilder(burstEventsPoll.ProcessNetworkBurstMapName, InetSend)
)

type udpInfoKey struct {
	Cookie  uint64
	SAddr   uint32
	DAddr   uint32
	SPort   uint16
	DPort   uint16
	Padding uint32
}

type udpInfoValue struct {
	SubmittedBytes uint64
	TXBytes        uint64
	ConsumedBytes  uint64
	RXBytes        uint64
	ConsumedSegs   uint64
	SegsIn         uint64
	SubmittedSegs  uint64
	SegsOut        uint64
	Ktime          uint64
	PidKtime       uint64
	Pid            uint32
	SkDrops        uint32
}

func (k *udpInfoKey) String() string {
	ipDst := reader.GetIP(k.DAddr, api.MSG_OP_IPV4_UDPCONNECT)
	ipSrc := reader.GetIP(k.SAddr, api.MSG_OP_IPV4_UDPCONNECT)
	return fmt.Sprintf("SAddr=%s:%d DAddr=%s:%d Cookie=%d",
		ipSrc, k.SPort, ipDst, api.SwapByte(k.DPort), k.Cookie)
}
func (k *udpInfoKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *udpInfoKey) NewValue() bpf.MapValue {
	return &udpInfoValue{}
}
func (k *udpInfoKey) DeepCopyMapKey() bpf.MapKey {
	return &udpInfoKey{
		SAddr:   k.SAddr,
		DAddr:   k.DAddr,
		DPort:   k.DPort,
		SPort:   k.SPort,
		Cookie:  k.Cookie,
		Padding: 0,
	}
}

func (v *udpInfoValue) String() string {
	return fmt.Sprintf(
		"Pid: %d Ktime %d\n"+
			"SubmittedBytes: %d ConsumedBytes %d\n"+
			"TXBytes: %d RXBytes%d\n"+
			"SubmittedSegs: %d ConsumedSegs: %d\n"+
			"SegsOut: %d SegsIn: %d\n"+
			"SkDrops: %d\n",
		v.Pid, v.Ktime,
		v.SubmittedBytes, v.ConsumedBytes,
		v.TXBytes, v.RXBytes,
		v.SubmittedSegs, v.ConsumedSegs,
		v.SegsOut, v.SegsIn,
		v.SkDrops)
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
	dnsPorts                 [maxDnsPorts]uint16
	watermarkEnable          uint64
	watermarkAvgWindowSizeMs uint64
	watermarkWindowSize      uint64
	watermarkTriggerPercent  uint64
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
func emitUdpEvent(k *udpInfoKey, v *udpInfoValue) *api.MsgIPv4EventUnix {
	unix := api.MsgIPv4EventUnix{}

	unix.Common = api.MsgCommon{
		Op:    0,
		Size:  1,
		Ktime: v.Ktime,
	}
	unix.Tuple = api.MsgIPv4Tuple{
		SAddr: k.SAddr,
		DAddr: k.DAddr,
		SPort: k.SPort,
		DPort: k.DPort,
		Proto: 0,
	}
	unix.SockCookie = k.Cookie
	unix.Return = 0
	unix.ProcessKey = api.MsgExecveKey{
		Pid:   v.Pid,
		Ktime: v.PidKtime,
	}
	unix.SocketStats = api.MsgSocketStatsUnix{
		BytesSubmitted: v.SubmittedBytes,
		BytesConsumed:  v.ConsumedBytes,
		BytesSent:      v.TXBytes,
		BytesReceived:  v.RXBytes,
		ConsumedSegs:   uint32(v.ConsumedSegs),
		SegsIn:         uint32(v.SegsIn),
		SubmittedSegs:  uint32(v.SubmittedSegs),
		SegsOut:        uint32(v.SegsOut),
		SkDrop:         v.SkDrops,
	}
	return &unix
}

func emitCloseEvent(k *udpInfoKey, v *udpInfoValue) {
	unix := emitUdpEvent(k, v)
	unix.Common.Op = api.MSG_OP_IPV4_UDPCLOSE

	observer.AllListeners(unix)
}

func emitStatEvent(k *udpInfoKey, v *udpInfoValue) {
	unix := emitUdpEvent(k, v)
	unix.Common.Op = api.MSG_OP_IPV4_UDPSTATS

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
		SubmittedBytes: curr.SubmittedBytes - last.SubmittedBytes,
		ConsumedBytes:  curr.ConsumedBytes - last.ConsumedBytes,
		TXBytes:        curr.TXBytes - last.TXBytes,
		RXBytes:        curr.RXBytes - last.RXBytes,
		ConsumedSegs:   curr.ConsumedSegs - last.ConsumedSegs,
		SubmittedSegs:  curr.SubmittedSegs - last.SubmittedSegs,
		SegsIn:         curr.SegsIn - last.SegsIn,
		SegsOut:        curr.SegsOut - last.SegsOut,
		SkDrops:        curr.SkDrops - last.SkDrops,
		Ktime:          curr.Ktime,
		PidKtime:       curr.PidKtime,
		Pid:            curr.Pid,
	}, nil
}

func udpGcCb(m *bpf.Map, k bpf.MapKey, v bpf.MapValue) {
	udpValue := v.(*udpInfoValue)
	udpKey := k.(*udpInfoKey)

	// This case handles kernels <5.10 where map will have udp stats
	// that are not yet associated to a process between IP stack and
	// socket handling of the UDP data.
	if udpValue.Pid == 0 {
		return
	}

	t, err := reader.NanoTimeSince(int64(udpValue.Ktime))
	if err != nil {
		logger.GetLogger().WithError(err).WithField("time", udpValue.Ktime).Warn("UDP NanoTimeSince failed.")
		return
	}

	entry, ok := stats.Get(*udpKey)
	if ok {
		last := entry.(udpInfoValue)
		if *udpValue != last {
			diffValue, err := udpDiffValues(udpKey, &last, udpValue)
			if err == nil {
				mapUpdate := v.DeepCopyMapValue().(*udpInfoValue)
				udpKey = k.DeepCopyMapKey().(*udpInfoKey)
				stats.Add(*udpKey, *mapUpdate)
				emitStatEvent(udpKey, &diffValue)
				metrics.LruMapSize.WithLabelValues("lru_udp_stats_map", "32000").Set(float64(stats.Len()))
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
		m.DeleteKey(k)
		metrics.LruMapSize.WithLabelValues("lru_udp_stats_map", "32000").Set(float64(stats.Len()))
	}
}

func runUdpGC() {
	file := filepath.Join(bpf.MapPrefixPath(), UdpMapName)

	m, err := bpf.OpenMap(file)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", file).Warn("UDP GC failed to open file")
		return
	}
	defer m.Close()
	m.MapKey = &udpInfoKey{}
	m.KeySize = 24
	m.MapValue = &udpInfoValue{}
	m.DumpWithCallback(udpGcCb)
}

func udpGC(gcInterval time.Duration) {
	ticker := time.NewTicker(gcInterval)
	go func() {
		for range ticker.C {
			runUdpGC()
		}
	}()
}

type udpSensor struct {
	name string
}

func (udp *udpSensor) LoadProbe(args sensors.LoadProbeArgs) (int, error) {
	err := sensors.LoadCgroupProgram(args.BPFDir, args.MapDir, args.CiliumDir, args.Load)
	if err != nil {
		return -1, err
	}
	if !configured {
		if err := configureUdpSensor(args.MapDir, "udp_config_map", Config); err != nil {
			return -1, err
		}
		configured = true
	}
	return -1, nil
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

func EnableUdpParser(cgroup bool, interval time.Duration) *sensors.Sensor {
	var progs []*sensors.Program
	var maps []*sensors.Map
	var versionStr string

	if !kernels.MinKernelVersion("5.10.0") || !cgroup {
		progs = []*sensors.Program{
			InetSendLazy,
			InetRecvLazy,
			UdpSend,
			UdpRetSend,
			UdpRecv,
		}
		maps = []*sensors.Map{
			UdpMapKprobe,
			UdpRetprobeMap,
			UdpConfigLazyMap,
		}
		grpc.LazyDns = true
		versionStr = "__udp_sensor_probe__"
	} else {
		progs = []*sensors.Program{
			SockCreate,
			SockRelease,
			InetSend,
			InetRecv,
			UdpSend,
			UdpRetSend,
			UdpRecv,
		}
		maps = []*sensors.Map{
			SocketCookieMap,
			UdpMapKprobe,
			UdpRetprobeMap,
			UdpConfigMap,
			UdpMap,
		}
		versionStr = "__udp_sensor_cgroup__"
	}
	udpGC(interval)
	logger.GetLogger().WithFields(logrus.Fields{
		"sensorName":     versionStr,
		"statsInterval":  interval,
		"deleteInterval": UdpDeleteInterval,
	}).Infof("Enable UDP")
	return sensors.SensorBuilder(versionStr, progs, maps)
}

func (udp *udpSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
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

func handleUdpConnect(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgIPv4Event{}
	err := binary.Read(r, native_endian.NativeEndian(), &m)
	if err != nil {
		return nil, err
	}
	msgUnix := observer.MsgToIPv4Unix(&m)
	return []observer.Event{msgUnix}, nil
}

func init() {
	AddUDP()
}

func AddUDP() {
	var err error

	stats, err = lru.New(stataCacheSize)
	if err != nil {
		logger.GetLogger().WithError(err).Errorf("UDP cache failed. Disabling UDP")
		return
	}

	udp := &udpSensor{
		name: "UDP sensor",
	}
	sensors.RegisterProbeType("udp_sensor", udp)
	sensors.RegisterTracingSensorsAtInit(udp.name, udp)
	observer.RegisterEventHandlerAtInit(api.MSG_OP_IPV4_UDPCONNECT, handleUdpConnect)
	observer.RegisterEventHandlerAtInit(api.MSG_OP_IPV4_UDPPAYLOAD, handleUdpPayload)
	observer.RegisterEventHandlerAtInit(api.MSG_OP_IPV4_PROCESS_BURST, burstEventsPoll.HandleProcessNetworkBurst)

	sensors.RegisterProbeType("cgrp_ingress", udp)
	sensors.RegisterProbeType("cgrp_egress", udp)
}
