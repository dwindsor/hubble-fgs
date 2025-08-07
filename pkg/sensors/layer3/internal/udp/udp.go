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
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/cilium/tetragon/pkg/sensors/program"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/yalue/native_endian"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	// api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/constants"
	"github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	"github.com/isovalent/hubble-fgs/pkg/grpc/udp_seq_check_error"
	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/ip"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/udpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networkWatermarksEvents"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networklatency"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

const (
	UdpMapName    = "tg_l3_udpsk"
	ConfigMapName = "tg_l3_udp_cfg"

	MissingStatsErrorInterval = time.Hour
)

var (
	Config            networkapi.UdpConfigValue
	udpGcInterval     time.Duration
	WatermarksEnabled = false
	TimestampEnabled  = false

	DisableConnectEvents = false
	DisableListenEvents  = false
	DisableCloseEvents   = false
	DisableStatsEvents   = false

	LastMissingStats time.Time
)

var (
	// Ensure every program has a type defined by the layer3 sensor to force loading
	// through our own LoadProbe function. This is essential for socket discovery.
	//
	// Kprobes are for systems without fentry support (<v5.5).
	// Fentry are preferred from v5.5.
	SkUdpBindKprobe = program.Builder(
		"bpf_udp_bind.o",
		"__cgroup_bpf_run_filter_sk",
		"kprobe/__cgroup_bpf_run_filter_sk",
		"tg_udp_bind_sock",
		"layer3_sensor",
	)

	SkUdpBindFentry = program.Builder(
		"bpf_udp_bind_fentry.o",
		"fentry",
		"fentry/__cgroup_bpf_run_filter_sk",
		"tg_udp_bind_sock",
		"udp_fentry",
	)

	// Dummy (NOP) programs need to be attached to the cgroup hooks in order to cause the __cgroup_bpf_run_filter_sk
	// hook to be called (5.13+).
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

	InetSendRecvLazy = program.Builder(
		"bpf_udp_inet_lazy_kp.o",
		"__cgroup_bpf_run_filter_skb",
		"kprobe/__cgroup_bpf_run_filter_skb",
		"tg_run_filter_skb",
		"layer3_sensor",
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
	PsVerMap            = program.MapBuilder("tg_l3_udpsk_ver", SkUdpBindKprobe)

	// UDP maps
	UdpMapLazyKprobe       = program.MapBuilder(UdpMapName, InetSendRecvLazy)
	UdpMapStatsLazyKprobe  = program.MapBuilder(udpconfig.UdpMapStatsName, InetSendRecvLazy)
	UdpConfigLazyMapKprobe = program.MapBuilder(ConfigMapName, InetSendRecvLazy)

	LatencyConfigMapLazyKprobe = program.MapBuilder(networklatency.ConfigMapName, InetSendRecvLazy)
)

func fdCallback(socket *networkapi.FdLookupValue, pid uint32) {
	saddr := networkapi.GetIP(socket.Tuple.SAddr, 0, socket.Tuple.IPv6 != 0)
	daddr := networkapi.GetIP(socket.Tuple.DAddr, 0, socket.Tuple.IPv6 != 0)
	logger.GetLogger().Debug("Discovered UDP Socket",
		"Pid", pid,
		"Saddr", saddr,
		"Daddr", daddr,
		"Sport", socket.Tuple.SPort,
		"Dport", socket.Tuple.DPort,
		"Protocol", socket.Protocol,
		"State", socket.State)

	if socket.State != constants.BPF_TCP_CLOSE && socket.State != constants.BPF_TCP_ESTABLISHED {
		return
	}

	udp := layer3.MsgIPEventUnix{}
	udp.Msg = &networkapi.MsgIPEvent{}

	if socket.State == constants.BPF_TCP_CLOSE {
		if DisableListenEvents {
			return
		}
		udp.Msg.Common.Op = ops.MSG_OP_UDPLISTEN
	} else {
		if DisableConnectEvents {
			return
		}
		udp.Msg.Common.Op = ops.MSG_OP_UDPCONNECT
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

	udp.Msg.Tuple.IPv6 = socket.Tuple.IPv6
	udp.Msg.Tuple.SAddr[0] = socket.Tuple.SAddr[0]
	udp.Msg.Tuple.SAddr[1] = socket.Tuple.SAddr[1]
	udp.Msg.Tuple.DAddr[0] = socket.Tuple.DAddr[0]
	udp.Msg.Tuple.DAddr[1] = socket.Tuple.DAddr[1]
	udp.Msg.Tuple.DPort = socket.Tuple.DPort
	udp.Msg.Tuple.SPort = socket.Tuple.SPort
	udp.Msg.Tuple.Proto = 2
	udp.Msg.SockCookie = socket.Sockaddr

	observer.AllListeners(&udp)
}

func ConfigureMaps(mapDir string, mapName string, config networkapi.UdpConfigValue) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(mapDir, mapName), nil)
	if err != nil {
		return err
	}
	defer m.Close()

	// If this is a CLI configuration lets inherit the network events
	// configuration as well.
	config.DisableConnectEvents = 0
	config.DisableCloseEvents = 0
	if enterpriseOption.Config.Layer3CLIEnable && !enterpriseOption.Config.EnableNetworkEvents {
		DisableConnectEvents = true
		DisableCloseEvents = true
		DisableListenEvents = true
		config.DisableConnectEvents = 1
		config.DisableCloseEvents = 1
	}
	// DisableListenEvents can operate independently of disabling all network events.
	config.DisableListenEvents = 0
	if DisableListenEvents {
		config.DisableListenEvents = 1
	}

	key := &networkapi.UdpConfigKey{
		Zero: uint32(0),
	}
	m.Put(key, &config)
	logger.GetLogger().Info("Configured UDP sock statistic sampler", "config", config.String())
	return nil
}

func ConfigureSensor() error {
	ip.LoadSockets(fdCallback, syscall.IPPROTO_UDP, 0)
	udpconfig.UdpMapRemoves = 0
	if udpGcInterval > 0 {
		if gcTimerRunning {
			gcTimer.Stop()
		}
		gcTimer.Start(udpGcInterval)
		gcTimerRunning = true
	}
	return nil
}

func StartIdleSocketGC() {
	if enterpriseOption.Config.EnableUDP && enterpriseOption.Config.UDPIdleSocketTimeout > 0 {
		UdpDeleteInterval = enterpriseOption.Config.UDPIdleSocketTimeout
		gcTimer.Start(UdpDeleteInterval)
		gcTimerRunning = true
	}
}

func UnloadSensor() error {
	if gcTimerRunning {
		gcTimer.Stop()
		gcTimerRunning = false
	}
	udpStatsEnable = false
	// If we enabled via CLI switches, run the GC so it can reap idle
	// pseudo-sockets.
	StartIdleSocketGC()
	TimestampEnabled = false
	networklatency.Stop(syscall.IPPROTO_UDP)
	if WatermarksEnabled {
		networkWatermarksEvents.Stop(syscall.IPPROTO_UDP)
		WatermarksEnabled = false
	}
	udpconfig.MetricsEnabled = false
	Config = networkapi.UdpConfigValue{}
	if enterpriseOption.Config.Layer3CLIEnable {
		ConfigureMaps(bpf.MapPrefixPath(), ConfigMapName, Config)
	}
	return nil
}

func bindProg() *program.Program {
	if utils.SupportFentry() {
		return SkUdpBindFentry
	}
	return SkUdpBindKprobe
}

func EnableUdp(cgroup, timestampEnable bool) ([]*program.Program, []*program.Program, []*program.Map) {
	var progsInitSock []*program.Program
	var progsCollectStats []*program.Program
	var maps []*program.Map
	var versionStr string

	if !utils.CGroupSKBAvailable() {
		logger.GetLogger().Info("Minimum kernel version (5.4 or RHEL equivalent) not met for UDP cgroup mode, falling back to socket mode")
		cgroup = false
	}

	versionStr = "__udp_sensor_probe__"

	maps = []*program.Map{
		SocketMap,
		SocketMapStats,
		SocketVersionMap,
		SocketTupleMap,
		SocketTupleMapStats,
		SocketTupleRevMap,
		SocketTupleHintMap,
		ConfigMap,
		PsVerMap,
	}

	if !cgroup {
		progsCollectStats = []*program.Program{
			InetSendRecvLazy,
		}
		progsInitSock = append(progsInitSock, bindProg())
		maps = append(maps,
			UdpMapLazyKprobe,
			UdpMapStatsLazyKprobe,
			UdpConfigLazyMapKprobe,
			LatencyConfigMapLazyKprobe,
		)
	} else {
		if !DisableListenEvents {
			progsInitSock = append(progsInitSock, bindProg())
			// Some kernels (vanilla v5.13+) need programs attached to socket operations to trigger our
			// hook for UDP bind.
			if utils.UDPBindNeedsDummies() {
				progsInitSock = append(progsInitSock, []*program.Program{SkUdpBindDummy4, SkUdpBindDummy6}...)
			}
		}
	}

	if timestampEnable {
		logger.GetLogger().Info("Enabling UDP latency")
		TimestampEnabled = true
		progsInitSock = append(progsInitSock, networklatency.Timestamp)
	}

	logger.GetLogger().Info("Enable UDP",
		"sensorName", versionStr,
		"deleteInterval", UdpDeleteInterval,
		"metrics", udpconfig.MetricsEnabled,
		"cgroup", cgroup)
	return progsInitSock, progsCollectStats, maps
}

func SetGcInterval(interval time.Duration) {
	udpGcInterval = interval
	logger.GetLogger().Info("UDP configured", "statsInterval", interval)
}

func PolicyHandler(spec *v1alpha1.TracingPolicySpec) (bool, time.Duration, error) {
	if spec.Parser.Udp != nil && spec.Parser.Udp.Metrics != nil {
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
	var interval = time.Duration(0)
	if spec.Parser.Udp != nil && spec.Parser.Udp.StatsInterval > 0 {
		interval = time.Duration(spec.Parser.Udp.StatsInterval) * time.Second
		udpStatsEnable = true
	} else {
		udpStatsEnable = false
	}

	UdpDeleteInterval = enterpriseOption.Config.UDPIdleSocketTimeout
	if spec.Parser.Udp != nil && spec.Parser.Udp.DeleteIdleSocketInterval > 0 {
		UdpDeleteInterval = time.Duration(spec.Parser.Udp.DeleteIdleSocketInterval) * time.Second
	}
	if !udpStatsEnable {
		interval = UdpDeleteInterval
	}
	Config, udpconfig.LatencyConfig = ParseUdpSpec(spec)
	udpLatencyEnable := spec.Parser.Udp != nil && spec.Parser.Udp.Latency.Enable
	logger.GetLogger().Debug("UDP Latency config", "enable", udpLatencyEnable)
	return udpLatencyEnable, interval, nil
}

func handleUdp(r *bytes.Reader) ([]observer.Event, error) {
	m := networkapi.MsgIPEvent{}
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
		pseudoSockets[pseudoKey][udpPseudoSocket{SAddr: m.Tuple.SAddr, SPort: m.Tuple.SPort, DAddr: m.Tuple.DAddr,
			DPort: m.Tuple.DPort, IPv6: m.Tuple.IPv6, PsVersion: m.PsVersion}] = true
		pseudoSocketsUpdate.Unlock()
		// If there is an existing cache entry for this pseudo-socket then it must be stale, so remove it.
		udpStatsKey := udpStatsKey{Cookie: m.SockCookie, Version: m.Version, Tuple: networkapi.MsgIPTuple{
			SAddr: m.Tuple.SAddr, SPort: m.Tuple.SPort, DAddr: m.Tuple.DAddr, DPort: m.Tuple.DPort, IPv6: m.Tuple.IPv6, Proto: syscall.IPPROTO_UDP},
			PsVersion: m.PsVersion,
		}
		stats.Remove(udpStatsKey)
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
			logger.GetLogger().Warn("UDP Close event failed to open map", logfields.Error, err, "file", mapFile)
			return nil, fmt.Errorf("failed to open udp info map")
		}
		defer udpMap.Close()
		mapStatsFile := filepath.Join(bpf.MapPrefixPath(), udpconfig.UdpMapStatsName)
		udpMapStats, err := ebpf.LoadPinnedMap(mapStatsFile, nil)
		if err != nil {
			logger.GetLogger().Warn("UDP Close event failed to open map", logfields.Error, err, "file", mapFile)
			return nil, fmt.Errorf("failed to open udp info map stats")
		}
		defer udpMapStats.Close()

		closeEvents := []observer.Event{}

		for psock := range pseudoSocketList {
			// Send stats event
			udpKey := networkapi.UdpInfoKey{Cookie: m.SockCookie, Version: m.Version, Tuple: networkapi.MsgIPTuple{
				SAddr: psock.SAddr, SPort: psock.SPort, DAddr: psock.DAddr, DPort: psock.DPort, IPv6: psock.IPv6, Proto: syscall.IPPROTO_UDP,
			}}
			udpStatsKey := udpStatsKey{Cookie: m.SockCookie, Version: m.Version, Tuple: networkapi.MsgIPTuple{
				SAddr: psock.SAddr, SPort: psock.SPort, DAddr: psock.DAddr, DPort: psock.DPort, IPv6: psock.IPv6, Proto: syscall.IPPROTO_UDP},
				PsVersion: psock.PsVersion}
			var udpValue networkapi.UdpInfoValue
			err := udpMap.Lookup(udpKey, &udpValue)
			if err != nil {
				socketmetrics.UDPGCMetricInc(socketmetrics.UDPGCTypeCloseEventMissingSocket)
				if time.Since(LastMissingStats) > MissingStatsErrorInterval {
					logger.GetLogger().Warn("UDP map look up failed for Close event. BPF UDP map might be too small, or IdleSocketDeleteInterval might be too large?",
						logfields.Error, err, "key", udpKey)
					LastMissingStats = time.Now()
				}
				// Entry has been evicted from the BPF map (likely LRU overspill).
				// We can still (and should) send a close event, although stats and duration will be 0.
				if !DisableCloseEvents {
					closeEvents = append(closeEvents, createCloseEvent(&udpKey, &networkapi.UdpInfoValue{
						Ktime:    m.Common.Ktime,
						Pid:      m.ProcessKey.Pid,
						PidKtime: m.ProcessKey.Ktime,
					}, 0))
				}
				// And we should remove the entry from our local stats cache.
				stats.Remove(udpStatsKey)
				continue
			}

			entry, ok := stats.Get(udpStatsKey)
			if ok {
				// Send stats event for the difference from the last one
				if udpValue != entry {
					diffValue, err := udpDiffValues(&udpKey, &entry, &udpValue)
					if err == nil {
						statsEvent := createStatEvent(&udpKey, &diffValue)
						if DisableStatsEvents {
							layer3.CreateProcessSockStats(statsEvent, false)
						} else if udpStatsEnable {
							closeEvents = append(closeEvents, statsEvent)
						}
					} else {
						socketmetrics.UDPGCMetricInc(socketmetrics.UDPGCTypeDiffValuesFailure)
					}
				}
				if !DisableCloseEvents {
					closeEvents = append(closeEvents, createCloseEvent(&udpKey, &udpValue, m.CloseTime))
				}
				stats.Remove(udpStatsKey)
			} else {
				// Send stats event – no stats event previously sent
				statsEvent := createStatEvent(&udpKey, &udpValue)
				if DisableStatsEvents {
					layer3.CreateProcessSockStats(statsEvent, false)
				} else if udpStatsEnable {
					closeEvents = append(closeEvents, statsEvent)
				}
				if !DisableCloseEvents {
					closeEvents = append(closeEvents, createCloseEvent(&udpKey, &udpValue, m.CloseTime))
				}
			}
			err = udpMap.Delete(udpKey)
			if err != nil {
				logger.GetLogger().Warn("UDP map delete", "logfields.Error", err, "key", udpKey)
			} else {
				decMapStats()
			}
		}

		pseudoSocketsUpdate.Lock()
		delete(pseudoSockets, pseudoKey)
		pseudoSocketsUpdate.Unlock()
		return closeEvents, nil
	}
	return []observer.Event{msgUnix}, nil
}

func MsgToUdpSeqErrorUnix(m *networkapi.MsgUdpSeqCheckErrorEvent) *udp_seq_check_error.MsgUdpSeqCheckErrorEventUnix {
	unix := &udp_seq_check_error.MsgUdpSeqCheckErrorEventUnix{}
	unix.Msg = m
	return unix
}

func handleUdpSeqError(r *bytes.Reader) ([]observer.Event, error) {
	m := networkapi.MsgUdpSeqCheckErrorEvent{}
	err := binary.Read(r, native_endian.NativeEndian(), &m)
	if err != nil {
		return nil, err
	}
	msgUnix := MsgToUdpSeqErrorUnix(&m)

	return []observer.Event{msgUnix}, nil
}

func Init() error {
	var err error

	stats, err = lru.New[udpStatsKey, networkapi.UdpInfoValue](udpStatsCacheSize)
	if err != nil {
		return err
	}

	observer.RegisterEventHandlerAtInit(ops.MSG_OP_UDPCONNECT, handleUdp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_UDPPAYLOAD, handleUdpPayload)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_UDPLISTEN, handleUdp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_UDPCLOSE, handleUdp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_PROCESS_NETWORK_WATERMARK, networkWatermarksEvents.HandleProcessNetworkWatermarks)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_UDP_SEQ_ERROR, handleUdpSeqError)
	return nil
}
