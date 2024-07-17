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
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/ip"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/tcpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networkWatermarksEvents"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networklatency"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var (
	// There is no TCP stats interval default. Building a reasonable
	// default for random env is very difficult and users expected
	// setting the interval to zero would disable it.
	//TcpIntervalDefault            = time.Duration(60 * time.Second)
	Interval                   time.Duration
	StatsEnabled               bool
	WatermarksEnable           bool
	WatermarksWindowSize       uint64
	WatermarksBurstTriggerMult uint64
	WatermarksDipTriggerMult   uint64
	WatermarksEnabled          = false

	stats          *lru.Cache[tcpKey, networkapi.MsgSocketStats]
	statsCacheSize = 32000

	TimestampEnabled = false

	DisableConnect = false
	DisableClose   = false
	DisableAccept  = false
	DisableListen  = false
)

var (
	Connect = program.Builder(
		"bpf_tcp_connect.o",
		"tcp_connect",
		"kprobe/tcp_connect",
		"tg_tcp_connect",
		"layer3_sensor",
	)

	Connect515 = program.Builder(
		"bpf_tcp_connect_5_15.o",
		"tcp_connect",
		"kprobe/tcp_connect",
		"tg_tcp_connect",
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
		"__tcp_ack_snd_check",
		"kprobe/__tcp_ack_snd_check",
		"tg_tcp_ack_snd_check",
		"kprobe")

	// Maps for TCP Sockets
	SocketMap          = program.MapBuilder(base.SocketMap.Name, Connect)
	SocketStats        = program.MapBuilder(base.SocketStats.Name, Accept)
	SocketTupleMap     = program.MapBuilder(base.SocketTupleMap.Name, Connect)
	SocketTupleStats   = program.MapBuilder(base.SocketTupleStats.Name, Connect)
	SocketTupleHintMap = program.MapBuilder(base.SocketTupleHintMap.Name, Connect)

	// Endpoint Models
	EndpointIdMap            = program.MapBuilder("tg_endpoint_id_map", Connect515)
	BpfEndpointIdMap         = program.MapBuilder("tg_bpf_endpoint_id_map", Connect515)
	ProcessTreeMap           = program.MapBuilder("process_tree_map", Connect515)
	ProcessTreeBinaryUUIDMap = program.MapBuilder("process_tree_binary_uid_map", Connect515)
	ProcessTreeUUIDBinaryMap = program.MapBuilder("process_tree_uid_binary_map", Connect515)
	DestinationEndpointMap   = program.MapBuilder("destination_endpoint_map", Connect515)

	// TCP Runtime maps
	CfgMap          = program.MapBuilder("tg_cfg_map", Connect)
	AcceptSocketMap = program.MapBuilder("tg_tcp_accept_sock_map", Accept)
	TcpSocketMap    = program.MapBuilder("tg_tcpsocket_map", Connect)
	TcpSocketStats  = program.MapBuilder("tg_tcpsocket_map_stats", Accept)
	VerMap          = program.MapBuilder("tg_ver_map", Connect)

	// Parser maps
	HTTPContext    = program.MapBuilder("tg_http_map", CloseAndAccept)
	TLSContext     = program.MapBuilder("tg_tls_map", CloseAndAccept)
	TLSMapStats    = program.MapBuilder("tg_tls_map_stats", Connect)
	TLSBottles     = program.MapBuilder("tg_bottles", CloseAndAccept)
	TLSBottleStats = program.MapBuilder("tg_bottle_map_stats", CloseAndAccept)

	// Maps for watermarks detection
	SendCheckSampler            = program.MapBuilder("tg_tcp_send_check_sampler", SendCheck4)
	ProcessNetworkWatermarksMap = program.MapBuilder(networkWatermarksEvents.ProcessNetworkWatermarksMapName, SendCheck4)

	// Map for disabling events
	EventDisableConfig = program.MapBuilder("tg_event_disable_config", Connect)
)

func ConfigureSensor() error {
	getRunningSockets(true, true)
	return nil
}

func UnloadSensor() error {
	TimestampEnabled = false

	networklatency.Stop(unix.IPPROTO_TCP)
	if WatermarksEnabled {
		networkWatermarksEvents.Stop(syscall.IPPROTO_TCP)
	}
	return nil
}

func processModelMapsEnable() []*program.Map {
	maps := []*program.Map{
		EndpointIdMap,
		BpfEndpointIdMap,
		ProcessTreeMap,
		ProcessTreeBinaryUUIDMap,
		ProcessTreeUUIDBinaryMap,
		DestinationEndpointMap,
	}

	EndpointIdMap.SetMaxEntries(enterpriseOption.Config.EndpointCacheSize)
	BpfEndpointIdMap.SetMaxEntries(enterpriseOption.Config.BpfEndpointCacheSize)
	ProcessTreeMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	ProcessTreeBinaryUUIDMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	ProcessTreeUUIDBinaryMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	DestinationEndpointMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)

	return maps
}

func EnableTcp(timestampEnable bool) ([]*program.Program, []*program.Map) {
	TimestampEnabled = false

	progs := []*program.Program{
		CloseAndAccept,
		Listen,
		Accept,
		AcceptRet,
	}

	maps := []*program.Map{
		SocketStats,
		SocketMap,
		TcpSocketMap,
		TcpSocketStats,
		AcceptSocketMap,
		SocketTupleMap,
		SocketTupleStats,
		SocketTupleHintMap,
		CfgMap,
		HTTPContext,
		TLSContext,
		TLSMapStats,
		TLSBottles,
		TLSBottleStats,
		SendCheckSampler,
		ProcessNetworkWatermarksMap,
		EventDisableConfig,
		VerMap,
	}

	// Kernels before 5.15 are difficult to support BPF in kernel models
	// for connect maps. The main issue is lack of atomic operations to
	// support multiple cores accessing the map.
	if !kernels.MinKernelVersion("5.14.0") {
		progs = append(progs, Connect)
	} else {
		if runtime.GOARCH != "amd64" {
			progs = append(progs, Connect)
		} else {
			progs = append(progs, Connect515)
			maps = append(maps, processModelMapsEnable()...)
		}
	}

	if tcpconfig.RttHistogramMax != 0 {
		progs = append(progs, RttTracer)
	}

	/* Kernels <=5.4 do not have support for sk_to_tcp() which means
	 * we can not support reading stats off the TCP socket easily so
	 * for these kernels fall back to extra kprobe hook.
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
		"statsInterval":              Interval,
		"watermarksEnable":           WatermarksEnable,
		"watermarksWindowSize":       WatermarksWindowSize,
		"watermarksBurstTriggerMult": WatermarksBurstTriggerMult,
		"maxRttHistogram":            tcpconfig.RttHistogramMax,
		"minRttHistogram":            tcpconfig.RttHistogramMin,
		"metrics":                    tcpconfig.MetricsEnabled,
	}).Infof("Enable TCP")
	return progs, maps
}

func PolicyHandler(spec *v1alpha1.TracingPolicySpec) (bool, error) {
	if spec.Parser.Tcp.Metrics != nil {
		tcpconfig.MetricsEnabled = spec.Parser.Tcp.Metrics.Enable
		tcpconfig.CurrentLabels = tcpconfig.DefaultLabelFilter().WithEnabledLabels(spec.Parser.Tcp.Metrics.LabelFilter)
	} else {
		tcpconfig.MetricsEnabled = true
		tcpconfig.CurrentLabels = tcpconfig.DefaultLabelFilter()
	}

	if spec.Parser.Tcp.StatsInterval > 0 {
		Interval = time.Duration(spec.Parser.Tcp.StatsInterval) * time.Second
		StatsEnabled = true
	} else {
		StatsEnabled = false
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
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	tcp := ip.MsgToIPWithStatsUnix(&m)
	if StatsEnabled {
		cp := *tcp
		c, err := correctedStatsEvent(cp)
		if err != nil {
			return []observer.Event{tcp}, nil
		}
		// Convert to a TCPStats event by simply setting op code
		c.Msg.Common.Op = ops.MsgOpTCPStats
		statsKey := tcpKey{SockCookie: c.Msg.SockCookie, CreateTime: c.Msg.SocketStats.CreateKtime}
		stats.Remove(statsKey)
		return []observer.Event{tcp, &c}, nil
	}
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
	var err error

	stats, err = lru.New[tcpKey, networkapi.MsgSocketStats](statsCacheSize)
	if err != nil {
		return err
	}

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
