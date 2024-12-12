//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tcp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"runtime"
	"syscall"
	"time"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors/program"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	"github.com/isovalent/hubble-fgs/pkg/model"
	"github.com/isovalent/hubble-fgs/pkg/model/policy"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/ip"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/tcpCache"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/tcpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networkWatermarksEvents"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networklatency"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var (
	StatsInterval time.Duration // 0 means disabled
	stats         = statsManager{getCollect: func(cache *lru.Cache[networkapi.TcpKey, networkapi.MsgSocketStats]) collectFn {
		return getRunTcpGC(emitSocketStatsEvent, cache)
	}}

	WatermarksEnable           bool
	WatermarksWindowSize       uint64
	WatermarksBurstTriggerMult uint64
	WatermarksDipTriggerMult   uint64
	WatermarksEnabled          = false

	TimestampEnabled = false

	DisableConnect = false
	DisableClose   = false
	DisableAccept  = false
	DisableListen  = false
)

func StatsEnabled() bool {
	return StatsInterval > 0
}

var (
	Connect = program.Builder(
		"bpf_tcp_connect.o",
		"tcp_connect",
		"kprobe/tcp_connect",
		"tg_tcp_connect",
		"layer3_sensor",
	)

	TcpSockops515 = program.Builder(
		"bpf_tcp_sockops_5_15.o",
		"sockops",
		"sockops/tcp_sockops",
		"tg_tcp_sockops",
		"layer3_sensor",
	)

	CloseAndAccept = program.Builder(
		"bpf_tcp_close_and_accept.o",
		"tcp_set_state",
		"kprobe/tcp_set_state",
		"tg_tcp_set_state",
		"kprobe",
	)

	Listen = program.Builder(
		"bpf_tcp_listen.o",
		"__inet_hash",
		"kprobe/__inet_hash",
		"tg___inet_hash",
		"kprobe",
	)

	SecurityAccept = program.Builder(
		"bpf_tcp_security_accept.o",
		"security_socket_accept",
		"fentry/security_socket_accept",
		"tg_tcp_security_accept",
		"tcp_fentry",
	)

	SecurityGraft = program.Builder(
		"bpf_tcp_security_accept.o",
		"security_sock_graft",
		"fentry/security_sock_graft",
		"tg_tcp_security_graft",
		"tcp_fentry",
	)

	Accept = program.Builder(
		"bpf_tcp_accept.o",
		"tcp_create_openreq_child",
		"kprobe/tcp_create_openreq_child",
		"tg_event_tcp_accept",
		"kprobe",
	)

	AcceptRet = program.Builder(
		"bpf_tcp_accept.o",
		"tcp_create_openreq_child",
		"kretprobe/tcp_create_openreq_child",
		"tg_event_tcp_accept_ret",
		"kprobe",
	).SetRetProbe(true)

	SendCheck4 = program.Builder(
		"bpf_tcp_send_check.o",
		"tcp_v4_send_check",
		"kprobe/tcp_v4_send_check",
		"tg_tcp_v4_send_check",
		"layer3_sensor")

	SendCheck6 = program.Builder(
		"bpf_tcp_send_check.o",
		"inet6_csk_xmit",
		"kprobe/inet6_csk_xmit",
		"tg_inet6_csk_xmit",
		"layer3_sensor")

	// RTT Tracer uses kprobe on the TCP ACK Send Check to get the rtt_us value
	// as that is easily obtained. This is probably as good as we can easily get,
	// although open to improvements and discussion.
	RttTracer = program.Builder(
		"bpf_tcp_rtt.o",
		"tcp_ack_update_rtt",
		"kprobe/tcp_ack_update_rtt",
		"tg_tcp_ack_update_rtt",
		"kprobe")

	// Maps for TCP Sockets
	SocketStats        = program.MapBuilder(base.SocketStats.Name, Accept)
	SocketMap          = program.MapBuilder(base.SocketMap.Name, Connect)
	SocketTupleMap     = program.MapBuilder(base.SocketTupleMap.Name, Connect)
	SocketTupleStats   = program.MapBuilder(base.SocketTupleStats.Name, Connect)
	SocketTupleRevMap  = program.MapBuilder(base.SocketTupleRevMap.Name, Connect)
	SocketTupleHintMap = program.MapBuilder(base.SocketTupleHintMap.Name, Connect)

	// Maps for TCP Sockets on Sockops
	SocketOpsMap          = program.MapBuilder(base.SocketMap.Name, TcpSockops515)
	SocketOpsTupleMap     = program.MapBuilder(base.SocketTupleMap.Name, TcpSockops515)
	SocketOpsTupleStats   = program.MapBuilder(base.SocketTupleStats.Name, TcpSockops515)
	SocketOpsTupleRevMap  = program.MapBuilder(base.SocketTupleRevMap.Name, TcpSockops515)
	SocketOpsTupleHintMap = program.MapBuilder(base.SocketTupleHintMap.Name, TcpSockops515)

	SecurityAcceptMap = program.MapBuilder("tg_tcp_accept_socket_to_sk_map", SecurityAccept)
	SecurityGraftMap  = program.MapBuilder("tg_tcp_accept_socket_to_sk_map", SecurityGraft)

	// Endpoint Models
	EndpointIdMap            = program.MapUser("tg_endpoint_id_map", TcpSockops515)
	BpfEndpointIdMap         = program.MapUser("tg_bpf_endpoint_id_map", TcpSockops515)
	ProcessTreeMap           = program.MapUser("process_tree_map", TcpSockops515)
	ProcessTreeBinaryUUIDMap = program.MapUser("process_tree_binary_uid_map", TcpSockops515)
	ProcessTreeUUIDBinaryMap = program.MapUser("process_tree_uid_binary_map", TcpSockops515)
	DestinationEndpointMap   = program.MapUser("destination_endpoint_map", TcpSockops515)
	ListenEndpointMap        = program.MapUser("listen_endpoint_map", TcpSockops515)

	// TCP Runtime maps
	CfgMap          = program.MapBuilder("tg_cfg_map", Connect)
	CfgOpsMap       = program.MapBuilder("tg_cfg_map", TcpSockops515)
	AcceptSocketMap = program.MapBuilder("tg_tcp_accept_sock_map", Accept)
	TcpSocketMap    = program.MapBuilder("tg_tcpsocket_map", Connect)
	TcpOpsSocketMap = program.MapBuilder("tg_tcpsocket_map", TcpSockops515)
	TcpSocketStats  = program.MapBuilder("tg_tcpsocket_map_stats", Accept)
	VerMap          = program.MapBuilder("tg_ver_map", Connect)
	VerOpsMap       = program.MapBuilder("tg_ver_map", TcpSockops515)

	// Parser maps
	HTTPContext    = program.MapBuilder("tg_http_map", TcpSockops515)
	TLSContext     = program.MapBuilder("tg_tls_map", TcpSockops515)
	TLSMapStats    = program.MapBuilder("tg_tls_map_stats", Connect)
	TLSOpsMapStats = program.MapBuilder("tg_tls_map_stats", TcpSockops515)
	TLSBottles     = program.MapBuilder("tg_bottles", TcpSockops515)
	TLSBottleStats = program.MapBuilder("tg_bottle_map_stats", TcpSockops515)

	// Maps for watermarks detection
	SendCheckSampler            = program.MapBuilder("tg_tcp_send_check_sampler", SendCheck4)
	ProcessNetworkWatermarksMap = program.MapBuilder(networkWatermarksEvents.ProcessNetworkWatermarksMapName, SendCheck4)

	// Map for disabling events
	EventDisableConfig    = program.MapBuilder("tg_event_disable_config", Connect)
	EventDisableConfigOps = program.MapBuilder("tg_event_disable_config", TcpSockops515)
)

func ConfigureSensor() error {
	getRunningSockets(true, true)
	tcpCache.StartGc()
	return nil
}

func UnloadSensor() error {
	TimestampEnabled = false

	networklatency.Stop(unix.IPPROTO_TCP)
	if WatermarksEnabled {
		networkWatermarksEvents.Stop(syscall.IPPROTO_TCP)
	}
	tcpconfig.MetricsEnabled = false
	if StatsEnabled() {
		stats.disable()
		StatsInterval = 0
	}
	tcpCache.StopGc()
	return policy.ClearDnsQuota()
}

func processModelMapsEnable() []*program.Map {
	maps := []*program.Map{
		EndpointIdMap,
		BpfEndpointIdMap,
		ProcessTreeMap,
		ProcessTreeBinaryUUIDMap,
		ProcessTreeUUIDBinaryMap,
		DestinationEndpointMap,
		ListenEndpointMap,
	}
	return maps
}

func EnableTcp(timestampEnable bool) ([]*program.Program, []*program.Map) {
	TimestampEnabled = false

	progs := []*program.Program{}

	mapsOps := []*program.Map{
		SocketOpsMap,
		TcpOpsSocketMap,
		VerOpsMap,
		SocketOpsTupleMap,
		SocketOpsTupleStats,
		SocketOpsTupleRevMap,
		SocketOpsTupleHintMap,
		TLSOpsMapStats,
		CfgOpsMap,
		EventDisableConfigOps,
	}
	mapsConnect := []*program.Map{
		SocketMap,
		TcpSocketMap,
		VerMap,
		SocketTupleMap,
		SocketTupleStats,
		SocketTupleRevMap,
		SocketTupleHintMap,
		TLSMapStats,
		CfgMap,
		EventDisableConfig,
	}

	maps := []*program.Map{
		SocketStats,
		TcpSocketStats,
		AcceptSocketMap,
		HTTPContext,
		TLSContext,
		TLSBottles,
		TLSBottleStats,
		SendCheckSampler,
		ProcessNetworkWatermarksMap,
	}

	// Kernels before 5.15 are difficult to support BPF in kernel models
	// for connect maps. The main issue is lack of atomic operations to
	// support multiple cores accessing the map.
	if !kernels.MinKernelVersion("5.14.0") {
		progs = append(progs, []*program.Program{
			Connect,
			CloseAndAccept,
			Listen,
			Accept,
			AcceptRet,
		}...)
		maps = append(maps, mapsConnect...)
	} else {
		if runtime.GOARCH != "amd64" {
			progs = append(progs, []*program.Program{
				Connect,
				CloseAndAccept,
				Listen,
				Accept,
				AcceptRet,
			}...)
			maps = append(maps, mapsConnect...)
		} else {
			progs = append(progs, TcpSockops515, SecurityAccept, SecurityGraft)
			maps = append(maps, mapsOps...)
			maps = append(maps, processModelMapsEnable()...)
			maps = append(maps, SecurityAcceptMap, SecurityGraftMap)
		}
	}

	if tcpconfig.RttHistogramMax != 0 {
		progs = append(progs, RttTracer)
	}

	/* Kernels <=5.4 do not have probe_read() support for cgroup/skb programs
	 * so we fall back on kprobes here.
	 */
	if !kernels.MinKernelVersion("5.5.0") {
		progs = append(progs, SendCheck4)
		progs = append(progs, SendCheck6)
	}

	if kernels.MinKernelVersion("5.4.0") {
		if timestampEnable {
			logger.GetLogger().Info("Enabling TCP latency")
			TimestampEnabled = true
			timestampProg, err := networklatency.TCEgressTimestamp(unix.IPPROTO_TCP)
			if err == nil {
				progs = append(progs, timestampProg)
			} else {
				logger.GetLogger().Warn("TCP unsupported by network latency")
			}
		}
	}

	logger.GetLogger().WithFields(logrus.Fields{
		"statsInterval":              StatsInterval,
		"watermarksEnable":           WatermarksEnable,
		"watermarksWindowSize":       WatermarksWindowSize,
		"watermarksBurstTriggerMult": WatermarksBurstTriggerMult,
		"maxRttHistogram":            tcpconfig.RttHistogramMax,
		"minRttHistogram":            tcpconfig.RttHistogramMin,
		"metrics":                    tcpconfig.MetricsEnabled,
	}).Infof("Enable TCP")
	return progs, maps
}

func configureQos(qos *v1alpha1.QosPolicySpec) error {
	for _, p := range qos.QuotaPolicySpec {
		if len(p.Destination.Dns) > 0 {
			err := policy.AddDnsQuotaPolicy(p.Namespace,
				p.Workload, p.WorkloadKind,
				p.Destination.Dns,
				p.Quota, qos.QuotaResetLimits,
			)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func PolicyHandler(spec *v1alpha1.TracingPolicySpec) (bool, error) {
	model.DefaultNewServer()

	if spec.Parser.Tcp.Qos != nil {
		if !enterpriseOption.Config.EnableProcessTree {
			return false, fmt.Errorf("Failed to load quota policy. Requires enable process tree")
		}

		if err := configureQos(spec.Parser.Tcp.Qos); err != nil {
			return false, err
		}
	}

	if spec.Parser.Tcp.Metrics != nil {
		tcpconfig.MetricsEnabled = spec.Parser.Tcp.Metrics.Enable
		tcpconfig.CurrentLabels = tcpconfig.DefaultLabelFilter().WithEnabledLabels(spec.Parser.Tcp.Metrics.LabelFilter)
	} else {
		tcpconfig.MetricsEnabled = true
		tcpconfig.CurrentLabels = tcpconfig.DefaultLabelFilter()
	}

	if spec.Parser.Tcp.StatsInterval > 0 {
		StatsInterval = time.Duration(spec.Parser.Tcp.StatsInterval) * time.Second
	} else {
		stats.disable()
		StatsInterval = 0
	}
	if spec.Parser.Tcp.Watermarks.Enable && spec.Parser.Tcp.Watermarks.WindowSize > 0 && spec.Parser.Tcp.Watermarks.BurstTriggerPercent > 0 {
		WatermarksEnabled = true
		WatermarksEnable = true
		WatermarksWindowSize = uint64(spec.Parser.Tcp.Watermarks.WindowSize)
		WatermarksBurstTriggerMult = uint64(spec.Parser.Tcp.Watermarks.BurstTriggerPercent)
		WatermarksDipTriggerMult = uint64(spec.Parser.Tcp.Watermarks.DipTriggerPercent)
		go networkWatermarksEvents.Start(spec, syscall.IPPROTO_TCP, false)
	} else if spec.Parser.Tcp.Burst.Enable && spec.Parser.Tcp.Burst.WindowSize > 0 && spec.Parser.Tcp.Burst.TriggerPercent > 0 {
		WatermarksEnabled = true
		WatermarksEnable = true
		WatermarksWindowSize = uint64(spec.Parser.Tcp.Burst.WindowSize)
		WatermarksBurstTriggerMult = uint64(spec.Parser.Tcp.Burst.TriggerPercent)
		go networkWatermarksEvents.Start(spec, syscall.IPPROTO_TCP, true)
	} else {
		WatermarksEnable = false
		WatermarksWindowSize = 0
		WatermarksBurstTriggerMult = 0
		WatermarksDipTriggerMult = 0
	}
	if spec.Parser.Tcp.RttHistogram.Enable {
		tcpconfig.RttHistogramMax = spec.Parser.Tcp.RttHistogram.Max
		tcpconfig.RttHistogramMin = spec.Parser.Tcp.RttHistogram.Min

		if tcpconfig.RttHistogramMax < tcpconfig.RttHistogramMin {
			return false, fmt.Errorf("Misconfigured Rtt Histogram: Min value must be less than Max")
		}
	} else {
		tcpconfig.RttHistogramMax = 0
	}
	tcpconfig.LatencyConfig, _ = networklatency.ParseLatencySpec(spec.Parser.Tcp.Latency, unix.IPPROTO_TCP)

	DisableConnect = spec.Parser.Tcp.DisableEvents.DisableConnect
	DisableClose = spec.Parser.Tcp.DisableEvents.DisableClose
	DisableAccept = spec.Parser.Tcp.DisableEvents.DisableAccept
	DisableListen = spec.Parser.Tcp.DisableEvents.DisableListen
	return spec.Parser.Tcp.Latency.Enable, nil
}

func handleTcpClose(r *bytes.Reader) ([]observer.Event, error) {
	m := networkapi.MsgIPWithStatsEvent{}
	var err error
	err = binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	tcp := ip.MsgToIPWithStatsUnix(&m)
	events := []observer.Event{tcp}
	if StatsEnabled() || enterpriseOption.Config.EnableAWSSonar {
		var c layer3.MsgIPWithStatsEventUnix
		c, err = stats.correctedStatsEvent(*tcp)
		if err == nil {
			// Convert to a TCPStats event by simply setting op code
			c.Msg.Common.Op = ops.MSG_OP_TCPSTATS
			statsKey := networkapi.TcpKey{SockCookie: c.Msg.SockCookie, CreateTime: c.Msg.SocketStats.CreateTime}
			if stats.cache != nil {
				stats.cache.Remove(statsKey)
			}
			if sonarStats.cache != nil {
				sonarStats.cache.Remove(statsKey)
			}
			events = append(events, &c)
		}
	}

	// Remove tuple from the cache.
	tcpCache.RemoveTuple(m.SockCookie, m.Version)

	return events, err
}

func handleTcp(r *bytes.Reader) ([]observer.Event, error) {
	m := networkapi.MsgIPEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	tcp := ip.MsgToIPUnix(&m)

	// Store tuple in the cache.
	tcpTuples, err := tcpCache.GetCache()
	if err == nil {
		socketId := networkapi.MsgSocketId{
			Cookie:  m.SockCookie,
			Version: m.Version,
		}
		tcpTuples.Add(socketId, &m.Tuple)
	} else {
		logger.GetLogger().WithError(err).Warn("handleTcp: GetCache failed")
	}
	return []observer.Event{tcp}, nil
}

func Init() error {
	/* Core set of TCP events */
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_TCPCONNECT, handleTcp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_TCPCONNECTRET, handleTcp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_TCPCLOSE, handleTcpClose)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_BIND, handleTcp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_LISTEN, handleTcp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_ACCEPT, handleTcp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_PROCESS_NETWORK_WATERMARK, networkWatermarksEvents.HandleProcessNetworkWatermarks)
	return nil
}
