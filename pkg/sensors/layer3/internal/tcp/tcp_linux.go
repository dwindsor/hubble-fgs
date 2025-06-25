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
	"syscall"
	"time"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	"github.com/isovalent/hubble-fgs/pkg/model/datapath"
	"github.com/isovalent/hubble-fgs/pkg/model/matchLabels"
	"github.com/isovalent/hubble-fgs/pkg/model/policy"
	model "github.com/isovalent/hubble-fgs/pkg/model/server"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/ip"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/lpm"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/tcpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networkWatermarksEvents"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networklatency"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
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
	// Ensure every program has a type defined by the layer3 sensor to force loading
	// through our own LoadProbe function. This is essential for socket discovery.
	//
	// Kprobes are for systems without fentry support (<v5.5).
	// Fentry are preferred from v5.5.
	// SockOps are more efficient and available from v5.14.
	// SockOps needs the SecurityAccept and SecurityGraft.
	ConnectKprobe = program.Builder(
		"bpf_tcp_connect.o",
		"tcp_connect",
		"kprobe/tcp_connect",
		"tg_tcp_connect_kprobe",
		"layer3_sensor",
	)

	ConnectFentry = program.Builder(
		"bpf_tcp_connect_fentry.o",
		"fentry",
		"fentry/tcp_connect",
		"tg_tcp_connect_fentry",
		"tcp_fentry",
	)

	CloseKprobe = program.Builder(
		"bpf_tcp_close.o",
		"tcp_set_state",
		"kprobe/tcp_set_state",
		"tg_tcp_set_state",
		"layer3_sensor",
	)

	CloseFentry = program.Builder(
		"bpf_tcp_close_fentry.o",
		"fentry",
		"fentry/tcp_set_state",
		"tg_tcp_set_state",
		"tcp_fentry",
	)

	ListenKprobe = program.Builder(
		"bpf_tcp_listen.o",
		"__inet_hash",
		"kprobe/__inet_hash",
		"tg___inet_hash",
		"layer3_sensor",
	)

	ListenFentry = program.Builder(
		"bpf_tcp_listen_fentry.o",
		"fentry",
		"fentry/__inet_hash",
		"tg___inet_hash",
		"tcp_fentry",
	)

	SecurityAcceptKprobe = program.Builder(
		"bpf_tcp_security_accept_kprobe.o",
		"security_socket_accept",
		"kprobe/security_socket_accept",
		"tg_tcp_security_accept",
		"layer3_sensor",
	)

	SecurityAccept = program.Builder(
		"bpf_tcp_security_accept.o",
		"security_socket_accept",
		"fentry/security_socket_accept",
		"tg_tcp_security_accept",
		"tcp_fentry",
	)

	SecurityGraftKprobe = program.Builder(
		"bpf_tcp_security_accept_kprobe.o",
		"security_sock_graft",
		"kprobe/security_sock_graft",
		"tg_tcp_security_graft",
		"layer3_sensor",
	)

	SecurityGraft = program.Builder(
		"bpf_tcp_security_accept.o",
		"security_sock_graft",
		"fentry/security_sock_graft",
		"tg_tcp_security_graft",
		"tcp_fentry",
	)

	SendCheck4 = program.Builder(
		"bpf_tcp_send_check.o",
		"tcp_v4_send_check",
		"kprobe/tcp_v4_send_check",
		"tg_tcp_v4_send_check",
		"layer3_sensor",
	)

	SendCheck6 = program.Builder(
		"bpf_tcp_send_check.o",
		"inet6_csk_xmit",
		"kprobe/inet6_csk_xmit",
		"tg_inet6_csk_xmit",
		"layer3_sensor",
	)

	TcpSockops = program.Builder(
		"bpf_tcp_sockops.o",
		"sockops",
		"sockops/tcp_sockops",
		"tg_tcp_sockops",
		"layer3_sensor",
	)

	TCPResetKprobe = program.Builder(
		"bpf_tcp_rst.o",
		"tcp_reset",
		"kprobe/tcp_reset",
		"tg_event_tcp_reset",
		"layer3_sensor",
	)

	TCPResetFentry = program.Builder(
		"bpf_tcp_rst_fentry.o",
		"tcp_reset",
		"fentry/tcp_reset",
		"tg_event_tcp_reset",
		"tcp_fentry",
	)

	// RTT Tracer uses kprobe or Fentry on the TCP ACK Update RTT to get the rtt_us value
	// as that is easily obtained. This is probably as good as we can easily get,
	// although open to improvements and discussion.
	RttTracerKprobe = program.Builder(
		"bpf_tcp_rtt.o",
		"tcp_ack_update_rtt",
		"kprobe/tcp_ack_update_rtt",
		"tg_tcp_ack_update_rtt",
		"layer3_sensor",
	)

	RttTracerFentry = program.Builder(
		"bpf_tcp_rtt_fentry.o",
		"fentry",
		"fentry/tcp_ack_update_rtt",
		"tg_tcp_ack_update_rtt",
		"tcp_fentry",
	)

	// Maps for TCP Sockets
	SocketMap           = program.MapUserFrom(base.SocketMap)
	SocketMapStats      = program.MapUserFrom(base.SocketStats)
	SocketVersionMap    = program.MapUserFrom(base.SocketVersionMap)
	SocketTupleMap      = program.MapUserFrom(base.SocketTupleMap)
	SocketTupleMapStats = program.MapUserFrom(base.SocketTupleStats)
	SocketTupleRevMap   = program.MapUserFrom(base.SocketTupleRevMap)
	SocketTupleHintMap  = program.MapUserFrom(base.SocketTupleHintMap)
	ConfigMap           = program.MapUserFrom(base.CfgMap)

	FinRxMapKprobe = program.MapBuilder("tg_tcp_finrx_map", CloseKprobe)
	FinRxMapFentry = program.MapBuilder("tg_tcp_finrx_map", CloseFentry)

	// Maps for TCP Sockets on Sockops
	SocketOpsFinRxMap = program.MapBuilder("tg_tcp_finrx_map", TcpSockops)

	SecurityAcceptMap = program.MapBuilder("tg_tcp_accept_socket_to_sk_map", SecurityAccept)

	// TCP Runtime maps
	TcpSocketMapKprobe = program.MapBuilder("tg_tcpsocket_map", ConnectKprobe)
	TcpSocketMapFentry = program.MapBuilder("tg_tcpsocket_map", ConnectFentry)
	TcpOpsSocketMap    = program.MapBuilder("tg_tcpsocket_map", TcpSockops)
	TcpSocketStats     = program.MapBuilder("tg_tcpsocket_map_stats", SecurityGraft)

	// Parser maps
	HTTPContext       = program.MapBuilder("tg_http_map", TcpSockops)
	TLSContext        = program.MapBuilder("tg_tls_map", TcpSockops)
	TLSMapStatsKprobe = program.MapBuilder("tg_tls_map_stats", ConnectKprobe)
	TLSMapStatsFentry = program.MapBuilder("tg_tls_map_stats", ConnectFentry)
	TLSOpsMapStats    = program.MapBuilder("tg_tls_map_stats", TcpSockops)
	TLSBottles        = program.MapBuilder("tg_bottles", TcpSockops)
	TLSBottleStats    = program.MapBuilder("tg_bottle_map_stats", TcpSockops)

	// Maps for watermarks detection
	SendCheckSampler            = program.MapBuilder("tg_tcp_send_check_sampler", SendCheck4)
	ProcessNetworkWatermarksMap = program.MapBuilder(networkWatermarksEvents.ProcessNetworkWatermarksMapName, SendCheck4)

	// Map for disabling events
	EventDisableConfigKprobe = program.MapBuilder("tg_event_disable_config", ConnectKprobe)
	EventDisableConfigFentry = program.MapBuilder("tg_event_disable_config", ConnectFentry)
	EventDisableConfigOps    = program.MapBuilder("tg_event_disable_config", TcpSockops)

	// LPM maps
	Addr6LpmMap = program.MapBuilder(lpm.Addr6lpmMapName, TcpSockops)
	Addr4LpmMap = program.MapBuilder(lpm.Addr4lpmMapName, TcpSockops)
)

func ConfigureMaps() error {
	ConfigureSockStatSampler(StatsInterval,
		WatermarksEnable,
		WatermarksWindowSize,
		WatermarksBurstTriggerMult,
		WatermarksDipTriggerMult,
		tcpconfig.RttHistogramMax,
		tcpconfig.RttHistogramMin)
	ConfigureTCPDisableEvents(DisableConnect, DisableClose, DisableAccept, DisableListen)
	err := configureQuotasDNSMaps(datapath.QuotasInitDNSDomainMappings)
	if err != nil {
		return fmt.Errorf("failed to configure quotas DNS maps: %w", err)
	}
	return nil
}

func configureQuotasDNSMaps(mappings map[endpoint.Endpoint]uint64) error {
	var dnsDomainMap dnsparser.DomainMap
	defer dnsDomainMap.CloseMaps()

	for endpoint, id := range mappings {
		err := dnsDomainMap.Update(endpoint.Dns, id)
		if err != nil {
			return fmt.Errorf("failed to write BPF domain maps: %w", err)
		}
	}

	return nil
}

func ConfigureSensor() error {
	getRunningSockets(true, true)
	return nil
}

func UnloadSensor(tp tracingpolicy.TracingPolicy) error {
	TimestampEnabled = false
	var err error

	networklatency.Stop(unix.IPPROTO_TCP)
	if WatermarksEnabled {
		networkWatermarksEvents.Stop(syscall.IPPROTO_TCP)
		WatermarksEnabled = false
	}
	tcpconfig.ClearConfig()
	if StatsEnabled() {
		stats.disable()
		StatsInterval = 0
	}

	spec := tp.TpSpec()
	name := tp.TpName()

	if spec.Parser.Tcp != nil && spec.Parser.Tcp.Qos != nil {
		qos := spec.Parser.Tcp.Qos

		for _, p := range qos.QuotaPolicySpec {
			networkPolicy := qosSpecToPolicy(&p, qos.QuotaResetLimits)
			err = policy.ClearDnsPolicy(name, networkPolicy)
		}
	}

	DisableConnect = false
	DisableClose = false
	DisableAccept = false
	DisableListen = false
	if enterpriseOption.Config.Layer3CLIEnable {
		ConfigureMaps()
	}
	return err
}

func processModelMapsEnable() []*program.Map {
	Addr6LpmMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	Addr4LpmMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	maps := []*program.Map{
		program.MapUserFrom(base.EndpointIdMap),
		program.MapUserFrom(base.BpfEndpointIdMap),
		program.MapUserFrom(base.ProcessTreeMap),
		program.MapUserFrom(base.ProcessTreeBinaryUUIDMap),
		program.MapUserFrom(base.ProcessTreeUUIDBinaryMap),
		program.MapUserFrom(base.DestinationEndpointMap),
		program.MapUserFrom(base.ListenEndpointMap),
	}
	maps = append(maps, []*program.Map{Addr4LpmMap, Addr6LpmMap}...)
	return maps
}

func EnableTcp(timestampEnable bool) ([]*program.Program, []*program.Program, []*program.Map) {
	TimestampEnabled = false

	progsInitSock := []*program.Program{}
	progsCollectStats := []*program.Program{}

	mapsOps := []*program.Map{
		SocketOpsFinRxMap,
		TcpOpsSocketMap,
		TLSOpsMapStats,
		EventDisableConfigOps,
	}

	mapsConnectKprobe := []*program.Map{
		FinRxMapKprobe,
		TcpSocketMapKprobe,
		TLSMapStatsKprobe,
		EventDisableConfigKprobe,
	}

	mapsConnectFentry := []*program.Map{
		FinRxMapFentry,
		TcpSocketMapFentry,
		TLSMapStatsFentry,
		EventDisableConfigFentry,
	}

	maps := []*program.Map{
		SocketMap,
		SocketMapStats,
		SocketVersionMap,
		SocketTupleMap,
		SocketTupleMapStats,
		SocketTupleRevMap,
		SocketTupleHintMap,
		ConfigMap,
		SecurityAcceptMap,
		TcpSocketStats,
		HTTPContext,
		TLSContext,
		TLSBottles,
		TLSBottleStats,
		SendCheckSampler,
		ProcessNetworkWatermarksMap,
	}

	// Kernels before 5.14 are difficult to support BPF in kernel models
	// for connect maps. The main issue is lack of atomic operations to
	// support multiple cores accessing the map.
	// Kernels before 5.5 don't support Fentry, so use kprobes here.
	// These can be unreliable as they can be preempted.
	if utils.SupportProcessTree() {
		progsInitSock = append(progsInitSock, TcpSockops)
		maps = append(maps, mapsOps...)
		maps = append(maps, processModelMapsEnable()...)
	} else if utils.SupportFentry() {
		progsInitSock = append(progsInitSock, []*program.Program{
			ConnectFentry,
			CloseFentry,
			ListenFentry,
		}...)
		maps = append(maps, mapsConnectFentry...)
	} else {
		progsInitSock = append(progsInitSock, []*program.Program{
			ConnectKprobe,
			CloseKprobe,
			ListenKprobe,
		}...)
		maps = append(maps, mapsConnectKprobe...)
	}

	if utils.SupportFentry() {
		progsInitSock = append(progsInitSock, SecurityAccept, SecurityGraft, TCPResetFentry)
	} else {
		progsInitSock = append(progsInitSock, SecurityAcceptKprobe, SecurityGraftKprobe, TCPResetKprobe)
	}

	if tcpconfig.RttHistogramMax != 0 || enterpriseOption.Config.EnableTCPRTT {
		if utils.SupportFentry() {
			progsCollectStats = append(progsCollectStats, RttTracerFentry)
		} else {
			progsCollectStats = append(progsCollectStats, RttTracerKprobe)
		}
	}

	/* Kernels <=5.4 do not have probe_read() support for cgroup/skb programs
	 * so we fall back on kprobes here.
	 */
	if !utils.CGroupSKBAvailable() || !utils.SupportCGroupSKBProbeRead() {
		progsCollectStats = append(progsCollectStats, SendCheck4)
		progsCollectStats = append(progsCollectStats, SendCheck6)
	}

	if utils.CGroupSKBAvailable() {
		if timestampEnable {
			logger.GetLogger().Info("Enabling TCP latency")
			TimestampEnabled = true
			progsInitSock = append(progsInitSock, networklatency.Timestamp)
		}
	}

	logger.GetLogger().Info("Enable TCP",
		"statsInterval", StatsInterval,
		"watermarksEnable", WatermarksEnable,
		"watermarksWindowSize", WatermarksWindowSize,
		"watermarksBurstTriggerMult", WatermarksBurstTriggerMult,
		"maxRttHistogram", tcpconfig.RttHistogramMax,
		"minRttHistogram", tcpconfig.RttHistogramMin,
		"metrics", tcpconfig.MetricsEnabled)
	return progsInitSock, progsCollectStats, maps
}

func qosSpecToPolicy(p *v1alpha1.QuotaPolicySpec, resetLimits string) *types.TetragonNetworkPolicy {
	mlEqual := matchLabels.LabelSet{
		Labels: make(map[string]string),
	}
	if len(p.MatchLabels) > 0 {
		mlEqual.ParseEquals(p.MatchLabels)
	}

	workload := types.TetragonWorkloadNetworkSubject{
		Namespace: p.Namespace,
		Name:      p.Workload,
		Kind:      p.WorkloadKind,
	}
	subject := types.TetragonNetworkSubject{
		Labels:   types.TetragonNetworkLabels{Equal: mlEqual.GetLabels()},
		Workload: workload,
	}
	fqdn := &types.TetragonNetworkFQDN{
		Names: p.Destination.Dns,
	}
	dest := types.TetragonNetworkDestination{
		FQDN: fqdn,
	}
	quota := &types.TetragonQuotaAction{
		Quota: p.Quota,
		Reset: resetLimits,
	}
	action := types.TetragonNetworkAction{
		QuotaAction: quota,
	}
	return &types.TetragonNetworkPolicy{
		Subject:     subject,
		Destination: dest,
		Action:      action,
	}
}

func configureQos(qos *v1alpha1.QosPolicySpec) error {
	for _, p := range qos.QuotaPolicySpec {
		if len(p.Destination.Dns) > 0 {
			networkPolicy := qosSpecToPolicy(&p, qos.QuotaResetLimits)
			err := policy.AddUnsafeNetworkPolicy("", networkPolicy)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func PolicyHandler(spec *v1alpha1.TracingPolicySpec) (bool, error) {
	model.DefaultNewServer()

	if spec.Parser.Tcp != nil && spec.Parser.Tcp.Qos != nil {
		if !enterpriseOption.Config.EnableApplicationModel {
			return false, fmt.Errorf("failed to load quota policy. Requires enable process tree")
		}

		if err := configureQos(spec.Parser.Tcp.Qos); err != nil {
			return false, err
		}
	}

	if spec.Parser.Tcp != nil && spec.Parser.Tcp.Metrics != nil {
		tcpconfig.MetricsEnabled = spec.Parser.Tcp.Metrics.Enable
		tcpconfig.CurrentLabels = tcpconfig.DefaultLabelFilter().WithEnabledLabels(spec.Parser.Tcp.Metrics.LabelFilter)
	} else {
		tcpconfig.MetricsEnabled = true
		tcpconfig.CurrentLabels = tcpconfig.DefaultLabelFilter()
	}

	if spec.Parser.Tcp != nil && spec.Parser.Tcp.StatsInterval > 0 {
		StatsInterval = time.Duration(spec.Parser.Tcp.StatsInterval) * time.Second
	} else {
		stats.disable()
		StatsInterval = 0
	}
	if spec.Parser.Tcp != nil && spec.Parser.Tcp.Watermarks.Enable && spec.Parser.Tcp.Watermarks.WindowSize > 0 && spec.Parser.Tcp.Watermarks.BurstTriggerPercent > 0 {
		WatermarksEnabled = true
		WatermarksEnable = true
		WatermarksWindowSize = uint64(spec.Parser.Tcp.Watermarks.WindowSize)
		WatermarksBurstTriggerMult = uint64(spec.Parser.Tcp.Watermarks.BurstTriggerPercent)
		WatermarksDipTriggerMult = uint64(spec.Parser.Tcp.Watermarks.DipTriggerPercent)
		go networkWatermarksEvents.Start(spec, syscall.IPPROTO_TCP, false)
	} else if spec.Parser.Tcp != nil && spec.Parser.Tcp.Burst.Enable && spec.Parser.Tcp.Burst.WindowSize > 0 && spec.Parser.Tcp.Burst.TriggerPercent > 0 {
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
	if spec.Parser.Tcp != nil && spec.Parser.Tcp.RttHistogram.Enable || enterpriseOption.Config.EnableTCPRTT {
		tcpconfig.RttHistogramMax = spec.Parser.Tcp.RttHistogram.Max
		tcpconfig.RttHistogramMin = spec.Parser.Tcp.RttHistogram.Min

		if tcpconfig.RttHistogramMax < tcpconfig.RttHistogramMin {
			tcpconfig.RttHistogramMax = 0
			return false, fmt.Errorf("misconfigured Rtt Histogram: Min value must be less than Max")
		}
	} else {
		tcpconfig.RttHistogramMax = 0
	}
	tcpconfig.LatencyConfig, _ = networklatency.ParseLatencySpec(spec.Parser.Tcp.Latency, unix.IPPROTO_TCP)

	if spec.Parser.Tcp != nil {
		DisableConnect = spec.Parser.Tcp.DisableEvents.DisableConnect
		DisableClose = spec.Parser.Tcp.DisableEvents.DisableClose
		DisableAccept = spec.Parser.Tcp.DisableEvents.DisableAccept
		DisableListen = spec.Parser.Tcp.DisableEvents.DisableListen
	}
	tcpLatencyEnable := false
	if spec.Parser.Tcp != nil {
		tcpLatencyEnable = spec.Parser.Tcp.Latency.Enable
	}
	return tcpLatencyEnable, nil
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

		// Explicit check for underflowed bytes_received < 0
		if int64(m.SocketStats.BytesReceived) < 0 {
			logger.GetLogger().Warn("TCP stats underflow in bytesReceived in Close",
				"tuple", m.Tuple,
				"stats", m.SocketStats,
				"cookie", m.SockCookie,
				"version", m.Version,
				"socketFlags", m.SocketFlags,
				"bytesReceived", int64(m.SocketStats.BytesReceived))
			// Correct it to make stats/metrics more sane (but beware that the bug still needs fixing
			// as it likely affects sockets where bytes_received wasn't 0 before the decrement)
			tcp.Msg.SocketStats.BytesReceived = 0
		}

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
		} else {
			logger.GetLogger().Warn("Failed to compute diff for TCP stats in Close",
				logfields.Error, err,
				"tuple", m.Tuple,
				"curr", m.SocketStats,
				"cookie", m.SockCookie,
				"version", m.Version,
				"socketFlags", m.SocketFlags,
				"bytesReceived", int64(m.SocketStats.BytesReceived))
		}
	}

	return events, err
}

func handleTcpConnect(r *bytes.Reader) ([]observer.Event, error) {
	m := networkapi.MsgIPWithTNPEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	tcp := ip.MsgWithTNPToIPUnix(&m)

	return []observer.Event{tcp}, nil
}

func handleTcp(r *bytes.Reader) ([]observer.Event, error) {
	m := networkapi.MsgIPEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	tcp := ip.MsgToIPUnix(&m)

	return []observer.Event{tcp}, nil
}

func Init() error {
	/* Core set of TCP events */
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_TCPCONNECT, handleTcpConnect)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_TCPCONNECTRET, handleTcpConnect)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_TCPCLOSE, handleTcpClose)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_BIND, handleTcp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_LISTEN, handleTcp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_ACCEPT, handleTcp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_PROCESS_NETWORK_WATERMARK, networkWatermarksEvents.HandleProcessNetworkWatermarks)
	return nil
}
