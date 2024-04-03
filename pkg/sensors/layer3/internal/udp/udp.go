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

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	ossBTF "github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/cilium/tetragon/pkg/sensors/program"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/sirupsen/logrus"
	"github.com/yalue/native_endian"
	"golang.org/x/sys/unix"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	fgsBTF "github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	"github.com/isovalent/hubble-fgs/pkg/grpc/udp_seq_check_error"
	"github.com/isovalent/hubble-fgs/pkg/metrics/lrumetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
	"github.com/isovalent/hubble-fgs/pkg/sensors/ip"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/udpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networkWatermarksEvents"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networklatency"
)

const (
	UdpMapName           = "tg_udp_map"
	UdpVerMapName        = "tg_udp_ver_map"
	UdpRetprobeMapName   = "tg_udp_retprobe_map"
	UdpRetprobeStatsName = "tg_udp_retprobe_map_stats"
	ConfigMapName        = "tg_udp_config_map"
	UdpPayloadMapName    = "tg_udp_payload_map"
	SocketMapName        = "tg_socket_map"
)

var (
	Config            ConfigValue
	WatermarksEnabled = false
	TimestampEnabled  = false

	DisableConnectEvents = false
	DisableListenEvents  = false
	DisableCloseEvents   = false
	DisableStatsEvents   = false
)

var (
	SkUdpAlloc = program.Builder(
		"bpf_udp_sock_create.o",
		"udp_init_sock",
		"kprobe/udp_init_sock",
		"tg_udp_init_sock",
		"kprobe",
	)

	SkUdpAlloc6 = program.Builder(
		"bpf_udp_sock_create.o",
		"udpv6_init_sock",
		"kprobe/udpv6_init_sock",
		"tg_udpv6_init_sock",
		"kprobe",
	)

	SkUdpDestroy = program.Builder(
		"bpf_udp_sock_release.o",
		"udp_destroy_sock",
		"kprobe/udp_destroy_sock",
		"tg_udp_destroy_sock",
		"kprobe")

	SkUdpBind = program.Builder(
		"bpf_udp_bind.o",
		"__cgroup_bpf_run_filter_sk",
		"kprobe/__cgroup_bpf_run_filter_sk",
		"tg_udp_bind_sock",
		"kprobe",
	)

	SkUdpBind_5_15 = program.Builder(
		"bpf_udp_bind_5_15.o",
		"__cgroup_bpf_run_filter_sk",
		"kprobe/__cgroup_bpf_run_filter_sk",
		"tg_udp_bind_sock",
		"kprobe",
	)

	// Dummy (NOP) programs need to be attached to the cgroup hooks in order to cause the __cgroup_bpf_run_filter_sk
	// hook to be called (5.10+).
	SkUdpBindDummy4 = program.Builder(
		"bpf_udp_bind_dummy.o",
		"inet4_bind_dummy",
		"cgroup/post_bind4",
		"tg_udp_bind_dummy4",
		"cgrp_inet4_bind",
	)

	SkUdpBindDummy6 = program.Builder(
		"bpf_udp_bind_dummy.o",
		"inet6_bind_dummy",
		"cgroup/post_bind6",
		"tg_udp_bind_dummy6",
		"cgrp_inet6_bind",
	)

	InetSend = program.Builder(
		"bpf_udp_inet.o",
		"inet_send",
		"cgroup_skb/egress",
		"tg_skb_egress",
		"cgrp_egress",
	)

	InetRecv = program.Builder(
		"bpf_udp_inet.o",
		"inet_recv",
		"cgroup_skb/ingress",
		"tg_skb_ingress",
		"cgrp_ingress",
	)

	InetSendLazy = program.Builder(
		"bpf_udp_inet_lazy.o",
		"inet_lazy_send",
		"cgroup_skb/egress",
		"tg_skb_egress",
		"cgrp_egress",
	)

	InetRecvLazy = program.Builder(
		"bpf_udp_inet_lazy.o",
		"inet_lazy_recv",
		"cgroup_skb/ingress",
		"tg_skb_ingress",
		"cgrp_ingress",
	)

	InetSendRecvLazy = program.Builder(
		"bpf_udp_inet_lazy_kp.o",
		"__cgroup_bpf_run_filter_skb",
		"kprobe/__cgroup_bpf_run_filter_skb",
		"tg_run_filter_skb",
		"kprobe_udp",
	)

	Udp4Send = program.Builder(
		"bpf_udp_send_recv.o",
		"udp_sendmsg",
		"kprobe/udp_sendmsg",
		"tg_udp_sendmsg",
		"kprobe",
	)

	Udp4RetSend = program.Builder(
		"bpf_udp_send_recv.o",
		"udp_sendmsg",
		"kretprobe/udp_sendmsg",
		"tg_ret_udp_sendmsg",
		"kprobe",
	).SetRetProbe(true)

	Udp6Send = program.Builder(
		"bpf_udp_send_recv.o",
		"udpv6_sendmsg",
		"kprobe/udpv6_sendmsg",
		"tg_udpv6_sendmsg",
		"kprobe",
	)

	Udp6RetSend = program.Builder(
		"bpf_udp_send_recv.o",
		"udpv6_sendmsg",
		"kretprobe/udpv6_sendmsg",
		"tg_ret_udpv6_sendmsg",
		"kprobe",
	).SetRetProbe(true)

	UdpRecv = program.Builder(
		"bpf_udp_send_recv.o",
		"skb_consume_udp",
		"kprobe/skb_consume_udp",
		"tg_skb_consume_udp",
		"kprobe",
	)

	// Shared socket cookie infrastructure
	SocketCookieMap        = program.MapBuilder(SocketMapName, Udp4Send)
	SocketCookieStats      = program.MapBuilder("tg_socket_map_stats", Udp4Send)
	SocketTupleMap         = program.MapBuilder("tg_socket_tuple_map", InetSend)
	SocketTupleStats       = program.MapBuilder("tg_socket_tuple_map_stats", InetSend)
	SocketTupleHintMap     = program.MapBuilder("tg_socket_tuple_hint_map", InetSend)
	CfgMap                 = program.MapBuilder("tg_cfg_map", InetSend)
	SocketTupleMapLazy     = program.MapBuilder("tg_socket_tuple_map", InetSendLazy)
	SocketTupleStatsLazy   = program.MapBuilder("tg_socket_tuple_map_stats", InetSendLazy)
	SocketTupleHintMapLazy = program.MapBuilder("tg_socket_tuple_hint_map", InetSendLazy)
	CfgMapLazy             = program.MapBuilder("tg_cfg_map", InetSendLazy)

	// UDP maps
	UdpMap                     = program.MapBuilder(UdpMapName, InetSend)
	UdpMapLazy                 = program.MapBuilder(UdpMapName, InetSendLazy)
	UdpMapLazyKprobe           = program.MapBuilder(UdpMapName, InetSendRecvLazy)
	UdpVerMap                  = program.MapBuilder(UdpVerMapName, InetSend)
	UdpVerMapLazy              = program.MapBuilder(UdpVerMapName, InetSendLazy)
	UdpVerMapLazyKprobe        = program.MapBuilder(UdpVerMapName, InetSendRecvLazy)
	UdpRetprobeMap             = program.MapBuilder(UdpRetprobeMapName, Udp4Send)
	UdpRetprobeStats           = program.MapBuilder(UdpRetprobeStatsName, Udp4Send)
	UdpConfigMap               = program.MapBuilder(ConfigMapName, InetSend)
	UdpConfigLazyMap           = program.MapBuilder(ConfigMapName, InetSendLazy)
	UdpConfigLazyMapKprobe     = program.MapBuilder(ConfigMapName, InetSendRecvLazy)
	UdpPayloadMap              = program.MapBuilder(UdpPayloadMapName, InetSend)
	UdpPayloadLazyMap          = program.MapBuilder(UdpPayloadMapName, InetSendLazy)
	UdpPayloadLazyMapKprobe    = program.MapBuilder(UdpPayloadMapName, InetSendRecvLazy)
	LatencyConfigMap           = program.MapBuilder(networklatency.ConfigMapName, InetRecv)
	LatencyConfigMapLazy       = program.MapBuilder(networklatency.ConfigMapName, InetRecvLazy)
	LatencyConfigMapLazyKprobe = program.MapBuilder(networklatency.ConfigMapName, InetSendRecvLazy)
)

type udpSensorConfigKey struct {
	Zero uint32
}

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

func FdCallback(socket *ip.FdLookupValue, pid uint32) {
	saddr := api.GetIP(socket.Saddr, 0, socket.IPv6 != 0)
	daddr := api.GetIP(socket.Daddr, 0, socket.IPv6 != 0)
	logger.GetLogger().WithFields(logrus.Fields{"Pid": pid, "Saddr": saddr, "Daddr": daddr, "Sport": socket.Sport, "Dport": socket.Dport, "Protocol": socket.Protocol, "State": socket.State}).Debug("Discovered UDP Socket")

	if socket.State != unix.BPF_TCP_CLOSE && socket.State != unix.BPF_TCP_ESTABLISHED {
		return
	}

	udp := layer3.MsgIPEventUnix{}
	udp.Msg = &networkapi.MsgIPEvent{}

	if socket.State == unix.BPF_TCP_CLOSE {
		if DisableListenEvents {
			return
		}
		udp.Msg.Common.Op = ops.MsgOpUDPListen
	} else {
		if DisableConnectEvents {
			return
		}
		udp.Msg.Common.Op = ops.MsgOpUDPConnect
	}

	pathName := filepath.Join(option.Config.ProcFS, fmt.Sprintf("%d", pid))
	stats, err := proc.GetProcStatStrings(pathName)
	if err != nil {
		return
	}
	ktime, err := proc.GetStatsKtime(stats)
	if err != nil {
		return
	}

	udp.Msg.ProcessKey.Pid = pid
	udp.Msg.ProcessKey.Ktime = ktime
	udp.Msg.Common.Ktime = ktime

	udp.Msg.Tuple.IPv6 = socket.IPv6
	udp.Msg.Tuple.SAddr[0] = socket.Saddr[0]
	udp.Msg.Tuple.SAddr[1] = socket.Saddr[1]
	udp.Msg.Tuple.DAddr[0] = socket.Daddr[0]
	udp.Msg.Tuple.DAddr[1] = socket.Daddr[1]
	udp.Msg.Tuple.DPort = socket.Dport
	udp.Msg.Tuple.SPort = socket.Sport
	udp.Msg.Tuple.Proto = 2
	udp.Msg.SockCookie = socket.Sockaddr

	observer.AllListeners(&udp)
}

func ConfigureUdpSensor(mapDir string, mapName string, config ConfigValue) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(mapDir, mapName), nil)
	if err != nil {
		return err
	}
	defer m.Close()

	key := &udpSensorConfigKey{
		Zero: uint32(0),
	}
	m.Put(key, &config)
	logger.GetLogger().WithField("config", config.String()).Info("Configured UDP sock statistic sampler: ")
	return nil
}

func UnloadSensor() error {
	gcTimer.Stop()
	networklatency.Stop(unix.IPPROTO_UDP)
	if WatermarksEnabled {
		networkWatermarksEvents.Stop(unix.IPPROTO_UDP)
	}
	return nil
}

func EnableUdp(cgroup, timestampEnable bool, interval time.Duration) ([]*program.Program, []*program.Map) {
	var progs []*program.Program
	var maps []*program.Map
	var versionStr string

	if !kernels.MinKernelVersion("5.4.0") {
		logger.GetLogger().Infof("Minimum kernel version (5.4) not met for UDP cgroup mode, falling back to socket mode")
		cgroup = false
	}

	spec, err := ossBTF.NewBTF()
	useIPv6InitHook := false
	if err != nil {
		logger.GetLogger().WithError(err).Warn("GetCachedBTF failed")
	} else {
		if spec == nil {
			logger.GetLogger().Warn("GetCachedBTF returned nil")
		} else {
			_, err := fgsBTF.GetFuncProto(spec, SkUdpAlloc6.Attach, false)
			if err == nil {
				useIPv6InitHook = true
			}
		}
	}

	if !cgroup {
		progs = []*program.Program{
			SkUdpAlloc,
			SkUdpDestroy,
			InetSendRecvLazy,
			Udp4Send,
			Udp4RetSend,
			Udp6Send,
			Udp6RetSend,
			UdpRecv,
		}
		if !DisableListenEvents {
			progs = append(progs, SkUdpBind)
		}
		maps = []*program.Map{
			UdpMapLazyKprobe,
			UdpVerMapLazyKprobe,
			UdpRetprobeMap,
			UdpRetprobeStats,
			UdpConfigLazyMapKprobe,
			UdpPayloadLazyMapKprobe,
			SocketCookieMap,
			SocketCookieStats,
			LatencyConfigMapLazyKprobe,
		}
		dns.LazyDns = true
		versionStr = "__udp_sensor_probe__"
	} else if !kernels.MinKernelVersion("5.10.0") {
		progs = []*program.Program{
			SkUdpAlloc,
			SkUdpDestroy,
			InetSendLazy,
			InetRecvLazy,
			Udp4Send,
			Udp4RetSend,
			Udp6Send,
			Udp6RetSend,
			UdpRecv,
		}
		if !DisableListenEvents {
			progs = append(progs, SkUdpBind)
		}
		maps = []*program.Map{
			UdpMapLazy,
			UdpVerMapLazy,
			UdpRetprobeMap,
			UdpRetprobeStats,
			UdpConfigLazyMap,
			UdpPayloadLazyMap,
			SocketCookieMap,
			SocketCookieStats,
			SocketTupleMapLazy,
			SocketTupleStatsLazy,
			SocketTupleHintMapLazy,
			CfgMapLazy,
			LatencyConfigMapLazy,
		}
		dns.LazyDns = false
		versionStr = "__udp_sensor_probe__"
	} else if !kernels.MinKernelVersion("5.15.0") {
		progs = []*program.Program{
			SkUdpAlloc,
			SkUdpDestroy,
			InetSend,
			InetRecv,
			Udp4Send,
			Udp4RetSend,
			Udp6Send,
			Udp6RetSend,
			UdpRecv,
		}
		if !DisableListenEvents {
			progs = append(progs, []*program.Program{SkUdpBind, SkUdpBindDummy4, SkUdpBindDummy6}...)
		}
		maps = []*program.Map{
			UdpMap,
			UdpVerMap,
			UdpRetprobeMap,
			UdpRetprobeStats,
			UdpConfigMap,
			UdpPayloadMap,
			SocketCookieMap,
			SocketCookieStats,
			SocketTupleMap,
			SocketTupleStats,
			SocketTupleHintMap,
			CfgMap,
			LatencyConfigMap,
		}
		dns.LazyDns = false
		versionStr = "__udp_sensor_probe__"
	} else {
		progs = []*program.Program{
			SkUdpAlloc,
			SkUdpDestroy,
			InetSend,
			InetRecv,
			Udp4Send,
			Udp4RetSend,
			Udp6Send,
			Udp6RetSend,
			UdpRecv,
		}
		if !DisableListenEvents {
			progs = append(progs, []*program.Program{SkUdpBind_5_15, SkUdpBindDummy4, SkUdpBindDummy6}...)
		}
		maps = []*program.Map{
			UdpMap,
			UdpVerMap,
			UdpRetprobeMap,
			UdpRetprobeStats,
			UdpConfigMap,
			UdpPayloadMap,
			SocketCookieMap,
			SocketCookieStats,
			SocketTupleMap,
			SocketTupleStats,
			SocketTupleHintMap,
			CfgMap,
			LatencyConfigMap,
		}
		dns.LazyDns = false
		versionStr = "__udp_sensor_probe__"
	}

	if useIPv6InitHook {
		progs = append(progs, SkUdpAlloc6)
	}

	if timestampEnable {
		TimestampEnabled = true
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
		"cgroup":         cgroup,
	}).Infof("Enable UDP")
	return progs, maps
}

func PolicyHandler(spec *v1alpha1.TracingPolicySpec) (bool, time.Duration, error) {
	if spec.Parser.Udp.Metrics != nil {
		udpconfig.MetricsEnabled = spec.Parser.Udp.Metrics.Enable
		udpconfig.CurrentLabels = udpconfig.DefaultLabelFilter().WithEnabledLabels(spec.Parser.Udp.Metrics.LabelFilter)
	} else {
		udpconfig.MetricsEnabled = true
		udpconfig.CurrentLabels = udpconfig.DefaultLabelFilter()
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
	return spec.Parser.Udp.Latency.Enable, interval, nil
}

func handleUdp(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgIPEvent{}
	err := binary.Read(r, native_endian.NativeEndian(), &m)
	if err != nil {
		return nil, err
	}
	msgUnix := ip.MsgToIPUnix(&m)
	pseudoKey := cookieVer{Cookie: m.SockCookie, Version: m.Version}

	switch m.Common.Op {
	case ops.MSG_OP_UDPCONNECT:
		// Store the pseudo-socket against this cookie
		pseudoSocketsUpdate.Lock()
		pseudoSockList := pseudoSockets[pseudoKey]
		if pseudoSockList == nil {
			pseudoSockets[pseudoKey] = make(map[udpPseudoSocket]bool)
		}
		pseudoSockets[pseudoKey][udpPseudoSocket{DAddr: m.Tuple.DAddr, DPort: m.Tuple.DPort, IPv6: m.Tuple.IPv6}] = true
		pseudoSocketsUpdate.Unlock()
		// If there is an existing cache entry for this pseudosocket then it must be stale, so remove it.
		udpKey := udpInfoKey{Cookie: m.SockCookie, Version: m.Version, DAddr: m.Tuple.DAddr, DPort: m.Tuple.DPort, IPv6: m.Tuple.IPv6}
		stats.Remove(udpKey)
		if DisableConnectEvents {
			return []observer.Event{}, nil
		}
	case ops.MSG_OP_UDPCLOSE:
		// Close event contains the socket cookie that was closed. We use this
		// along with the cookie version as a key into the pseudoSockets map
		// to retrieve the list of pseudo-sockets. Then we send a stats event
		// and a close event for each one, before deleting them from the maps.

		// Access to stats is protected by atomic operations we don't want to
		// serialize handlers on this lock. For mostly error cases.
		pseudoSocketsUpdate.Lock()
		pseudoSocketList := pseudoSockets[pseudoKey]
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
			udpKey := udpInfoKey{Cookie: m.SockCookie, Version: m.Version, DAddr: psock.DAddr, DPort: psock.DPort, IPv6: psock.IPv6}
			var udpValue udpInfoValue
			err := udpMap.Lookup(udpKey, &udpValue)
			if err != nil {
				logger.GetLogger().WithError(err).WithField("key", udpKey).Warn("UDP map look up failed for Close event")
				continue
			}

			entry, ok := stats.Get(udpKey)
			if ok {
				// Send stats event for the difference from the last one
				if udpValue != entry {
					diffValue, err := udpDiffValues(&udpKey, &entry, &udpValue)
					if err == nil {
						statsEvent := createStatEvent(&udpKey, &diffValue)
						if DisableStatsEvents {
							layer3.CreateProcessSockStats(statsEvent, false)
						} else {
							closeEvents = append(closeEvents, statsEvent)
						}
					} else {
						socketmetrics.UDPGCMetricInc(socketmetrics.UDPGCTypeDiffValuesFailure)
					}
				}
				// Send close event – Duration actually indicates close time
				if !DisableCloseEvents {
					closeEvents = append(closeEvents, createCloseEvent(&udpKey, &udpValue, m.Duration))
				}
				stats.Remove(udpKey)
			} else {
				// Send stats event – no stats event previously sent
				statsEvent := createStatEvent(&udpKey, &udpValue)
				if DisableStatsEvents {
					layer3.CreateProcessSockStats(statsEvent, false)
				} else {
					closeEvents = append(closeEvents, statsEvent)
				}
				// Send close event – Duration actually indicates close time
				if !DisableCloseEvents {
					closeEvents = append(closeEvents, createCloseEvent(&udpKey, &udpValue, m.Duration))
				}
			}
			err = udpMap.Delete(udpKey)
			if err != nil {
				logger.GetLogger().WithError(err).WithField("key", udpKey).Warn("UDP map delete")
			}
		}

		pseudoSocketsUpdate.Lock()
		delete(pseudoSockets, pseudoKey)
		pseudoSocketsUpdate.Unlock()
		lrumetrics.LruMapSizeSet("lru_udp_stats_map", udpStatsCacheSize, float64(stats.Len()))
		return closeEvents, nil
	}
	return []observer.Event{msgUnix}, nil
}

func MsgToUdpSeqErrorUnix(m *api.MsgUdpSeqCheckErrorEvent) *udp_seq_check_error.MsgUdpSeqCheckErrorEventUnix {
	unix := &udp_seq_check_error.MsgUdpSeqCheckErrorEventUnix{}
	unix.Msg = m
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

func Init() error {
	var err error

	stats, err = lru.New[udpInfoKey, udpInfoValue](udpStatsCacheSize)
	if err != nil {
		return err
	}

	observer.RegisterEventHandlerAtInit(ops.MSG_OP_UDPCONNECT, handleUdp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_UDPPAYLOAD, handleUdpPayload)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_UDPLISTEN, handleUdp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_UDPCLOSE, handleUdp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_PROCESS_NETWORK_WATERMARK, networkWatermarksEvents.HandleProcessNetworkWatermarks)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_IP_ERROR, ip.HandleIpError)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_UDP_SEQ_ERROR, handleUdpSeqError)
	return nil
}
