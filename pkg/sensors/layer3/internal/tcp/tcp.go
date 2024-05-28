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
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors/program"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
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
		"kprobe",
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

	// Latency uses TC egress to add timestamp and cgroup skb ingress to calculate
	// datagram latency.
	Latency = program.Builder(
		"bpf_cgroup_net.o",
		"cgroup_ingress",
		"cgroup_skb/ingress",
		"tg_cgroup_ingress",
		"cgrp_ingress",
	)

	LatencyLazy = program.Builder(
		"bpf_cgroup_net_load.o",
		"cgroup_ingress",
		"cgroup_skb/ingress",
		"tg_cgroup_ingress",
		"cgrp_ingress",
	)

	LatencyLazy54 = program.Builder(
		"bpf_cgroup_net_load_5-4.o",
		"cgroup_ingress",
		"cgroup_skb/ingress",
		"tg_cgroup_ingress",
		"cgrp_ingress",
	)

	// Maps for TCP Sockets
	SocketMap          = program.MapBuilder("tg_socket_map", Connect)
	SocketStats        = program.MapBuilder("tg_socket_map_stats", Accept)
	SocketTupleMap     = program.MapBuilder("tg_socket_tuple_map", Connect)
	SocketTupleStats   = program.MapBuilder("tg_socket_tuple_map_stats", Connect)
	SocketTupleHintMap = program.MapBuilder("tg_socket_tuple_hint_map", Connect)
	// Shared Layer3 infrastructure
	TcpCgroupCfgMap       = program.MapBuilder("tg_cgroup_protocol_cfg_map", Latency)
	TcpCgroupCfgMapLazy   = program.MapBuilder("tg_cgroup_protocol_cfg_map", LatencyLazy)
	TcpCgroupCfgMapLazy54 = program.MapBuilder("tg_cgroup_protocol_cfg_map", LatencyLazy54)
	// TCP Runtime maps
	CfgMap          = program.MapBuilder("tg_cfg_map", Connect)
	AcceptSocketMap = program.MapBuilder("tg_tcp_accept_sock_map", Accept)

	// Parser maps
	HTTPContext    = program.MapBuilder("tg_http_map", CloseAndAccept)
	TLSContext     = program.MapBuilder("tg_tls_map", CloseAndAccept)
	TLSMapStats    = program.MapBuilder("tg_tls_map_stats", Connect)
	TLSBottles     = program.MapBuilder("tg_bottles", CloseAndAccept)
	TLSBottleStats = program.MapBuilder("tg_bottle_map_stats", CloseAndAccept)

	// Maps for watermarks detection
	SendCheckSampler            = program.MapBuilder("tg_tcp_send_check_sampler", SendCheck4)
	ProcessNetworkWatermarksMap = program.MapBuilder(networkWatermarksEvents.ProcessNetworkWatermarksMapName, SendCheck4)

	// Map for latency
	LatencyConfigMap     = program.MapBuilder(networklatency.ConfigMapName, Latency)
	LatencyConfigMapLazy = program.MapBuilder(networklatency.ConfigMapName, LatencyLazy)

	// Map for disabling events
	EventDisableConfig = program.MapBuilder("tg_event_disable_config", Connect)
)

func UnloadSensor() error {
	TimestampEnabled = false

	networklatency.Stop(unix.IPPROTO_TCP)
	if WatermarksEnabled {
		networkWatermarksEvents.Stop(syscall.IPPROTO_TCP)
	}
	return nil
}

func EnableTcp(timestampEnable bool) ([]*program.Program, []*program.Map) {
	var progs []*program.Program

	TimestampEnabled = false

	progs = []*program.Program{
		Connect,
		CloseAndAccept,
		Listen,
		Accept,
		AcceptRet,
		SendCheck4,
		SendCheck6,
	}

	if tcpconfig.RttHistogramMax != 0 {
		progs = append(progs, RttTracer)
	}

	maps := []*program.Map{
		SocketStats,
		SocketMap,
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
	}

	if timestampEnable && kernels.MinKernelVersion("5.4.0") {
		logger.GetLogger().Info("Enabling TCP latency")
		TimestampEnabled = true
		timestampProg, err := networklatency.TCEgressTimestamp(unix.IPPROTO_TCP)
		if err == nil {
			progs = append(progs, timestampProg)
		} else {
			logger.GetLogger().Warn("TCP unsupported by network latency")
		}

		if !kernels.MinKernelVersion("5.5.0") {
			progs = append(progs, LatencyLazy54)
			maps = append(maps, LatencyConfigMapLazy)
			maps = append(maps, TcpCgroupCfgMapLazy54)
		} else if !kernels.MinKernelVersion("5.14.0") {
			progs = append(progs, LatencyLazy)
			maps = append(maps, LatencyConfigMapLazy)
			maps = append(maps, TcpCgroupCfgMapLazy)
		} else {
			progs = append(progs, Latency)
			maps = append(maps, LatencyConfigMap)
			maps = append(maps, TcpCgroupCfgMap)
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
