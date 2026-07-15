// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tcp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors/program"
	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	"github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/ip"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/tcpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networkWatermarksEvents"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

var (
	StatsInterval time.Duration // 0 means disabled
	stats         = statsManager{getCollect: func(cache *lru.Cache[networkapi.TcpKey, networkapi.MsgSocketStats]) collectFn {
		return getRunTcpGC(emitSocketStatsEvent, cache)
	}}

	WatermarksEnabled          bool
	WatermarksWindowSize       uint64
	WatermarksBurstTriggerMult uint64
	WatermarksDipTriggerMult   uint64

	DisableConnect = false
	DisableClose   = false
	DisableAccept  = false
	DisableListen  = false
)

func StatsEnabled() bool {
	return StatsInterval > 0
}

func SetConfig(cfg *networkapi.Layer3ConfigValue) error {
	ConfigureSockStatSampler(cfg,
		StatsInterval,
		WatermarksEnabled,
		WatermarksWindowSize,
		WatermarksBurstTriggerMult,
		WatermarksDipTriggerMult,
		tcpconfig.RttHistogramMax,
		tcpconfig.RttHistogramMin)
	// If this is a CLI configuration lets inherit the network events
	// configuration as well.
	if enterpriseOption.Config.Layer3CLIEnable {
		if !enterpriseOption.Config.EnableNetworkEvents {
			DisableConnect = true
			DisableClose = true
			DisableAccept = true
			DisableListen = true

		} else {
			ParseDisableOptions()
		}
	}
	ConfigureTCPDisableEvents(cfg, DisableConnect, DisableClose, DisableAccept, DisableListen)
	return nil
}

func ConfigureSensor() error {
	getRunningSockets(true, true)
	return nil
}

func UnloadSensor(cfg *networkapi.Layer3ConfigValue) error {
	var err error

	if WatermarksEnabled {
		networkWatermarksEvents.Stop(syscall.IPPROTO_TCP)
		WatermarksEnabled = false
		ParseWatermarksOptions()
		ParseRTTOptions()
	}
	tcpconfig.ClearConfig()
	if StatsEnabled() {
		stats.disable()
		StatsInterval = enterpriseOption.Config.TCPStatsInterval
		if StatsInterval > 0 {
			stats.enable(StatsInterval)
		}
	}

	ParseDisableOptions()
	if enterpriseOption.Config.Layer3CLIEnable {
		SetConfig(cfg)
	}
	return err
}

func processModelMapsEnable() []*program.Map {
	maps := []*program.Map{
		program.MapUserFrom(base.EndpointIdMap),
		program.MapUserFrom(base.BpfEndpointIdMap),
		program.MapUserFrom(base.ProcessTreeMap),
		program.MapUserFrom(base.ProcessTreeBinaryUUIDMap),
		program.MapUserFrom(base.DestinationEndpointMap),
		program.MapUserFrom(base.ListenEndpointMap),
	}
	maps = append(maps, []*program.Map{tcpconfig.Addr4LpmMap, tcpconfig.Addr6LpmMap}...)
	return maps
}

func EnableTcp() ([]*program.Program, []*program.Program, []*program.Map) {
	progsInitSock := []*program.Program{}
	progsCollectStats := []*program.Program{}

	tcpconfig.SecurityAcceptMap.SetMaxEntries(enterpriseOption.Config.TCPSocketMapSize)

	maps := []*program.Map{
		tcpconfig.SocketMap,
		tcpconfig.SocketMapStats,
		tcpconfig.SocketVersionMap,
		tcpconfig.SocketTupleMap,
		tcpconfig.SocketTupleMapStats,
		tcpconfig.SocketTupleRevMap,
		tcpconfig.SocketTupleHintMap,
		tcpconfig.ConfigMap,
		tcpconfig.SecurityAcceptMap,
		tcpconfig.TcpSocketStats,
		tcpconfig.HTTPContext,
		tcpconfig.TLSContext,
		tcpconfig.TLSBottles,
		tcpconfig.TLSBottleStats,
		tcpconfig.FinRxMap,
		tcpconfig.TcpSocketMap,
		tcpconfig.TLSMapStats,
	}

	// Kernels before 5.14 are difficult to support BPF in kernel models
	// for connect maps. The main issue is lack of atomic operations to
	// support multiple cores accessing the map.
	// Kernels before 5.5 don't support Fentry, so use kprobes here.
	// These can be unreliable as they can be preempted.
	if utils.SupportProcessTree() {
		if enterpriseOption.Config.EnableBPFDNSPerPod {
			err := dnsparser.RewritePerPodConstants(tcpconfig.TcpSockops.RewriteConstants)
			if err != nil {
				// TODO: when we remove enabling layer3 from CRD, return this error and stop init of sensor
				logger.GetLogger().Error("Failed to rewrite DNS parser constants", logfields.Error, err)
			}
		}
		progsInitSock = append(progsInitSock, tcpconfig.TcpSockops)
		maps = append(maps, processModelMapsEnable()...)
	} else if utils.SupportFentry() {
		progsInitSock = append(progsInitSock, []*program.Program{
			tcpconfig.ConnectFentry,
			tcpconfig.CloseFentry,
			tcpconfig.ListenFentry,
		}...)
	} else {
		progsInitSock = append(progsInitSock, []*program.Program{
			tcpconfig.ConnectKprobe,
			tcpconfig.CloseKprobe,
			tcpconfig.ListenKprobe,
		}...)
	}

	if utils.SupportFentry() {
		progsInitSock = append(progsInitSock, tcpconfig.SecurityAccept, tcpconfig.SecurityGraft, tcpconfig.TCPResetFentry)
	} else {
		progsInitSock = append(progsInitSock, tcpconfig.SecurityAcceptKprobe, tcpconfig.SecurityGraftKprobe, tcpconfig.TCPResetKprobe)
	}

	if tcpconfig.RttHistogramMax != 0 || enterpriseOption.Config.EnableTCPRTT {
		if utils.SupportFentry() {
			progsCollectStats = append(progsCollectStats, tcpconfig.RttTracerFentry)
		} else {
			progsCollectStats = append(progsCollectStats, tcpconfig.RttTracerKprobe)
		}
	}

	/* Kernels <=5.4 do not have probe_read() support for cgroup/skb programs
	 * so we fall back on kprobes here.
	 */
	if !utils.CGroupSKBAvailable() || !utils.SupportCGroupSKBProbeRead() {
		progsCollectStats = append(progsCollectStats, tcpconfig.SendCheck4)
		progsCollectStats = append(progsCollectStats, tcpconfig.SendCheck6)
	}

	logger.GetLogger().Info("Enable TCP",
		"statsInterval", StatsInterval,
		"WatermarksEnabled", WatermarksEnabled,
		"watermarksWindowSize", WatermarksWindowSize,
		"watermarksBurstTriggerMult", WatermarksBurstTriggerMult,
		"maxRttHistogram", tcpconfig.RttHistogramMax,
		"minRttHistogram", tcpconfig.RttHistogramMin,
		"metrics", tcpconfig.MetricsEnabled)
	return progsInitSock, progsCollectStats, maps
}

func SetStatsInterval(interval time.Duration) {
	StatsInterval = interval
	logger.GetLogger().Info("TCP configured", "StatsInterval", interval)
}

func PolicyHandler(spec *v1alpha1.TracingPolicySpec) error {
	if spec.Parser.Tcp != nil && spec.Parser.Tcp.Metrics != nil {
		tcpconfig.MetricsEnabled = spec.Parser.Tcp.Metrics.Enable
		tcpconfig.CurrentLabels = tcpconfig.DefaultLabelFilter().WithEnabledLabels(spec.Parser.Tcp.Metrics.LabelFilter)
	} else {
		ParseMetricsOptions()
	}

	if spec.Parser.Tcp != nil && spec.Parser.Tcp.StatsInterval > 0 {
		StatsInterval = time.Duration(spec.Parser.Tcp.StatsInterval) * time.Second
	} else {
		StatsInterval = enterpriseOption.Config.TCPStatsInterval
		if StatsInterval == 0 {
			stats.disable()
		}
	}
	if spec.Parser.Tcp != nil && spec.Parser.Tcp.Watermarks.Enable && spec.Parser.Tcp.Watermarks.WindowSize > 0 && spec.Parser.Tcp.Watermarks.BurstTriggerPercent > 0 {
		WatermarksEnabled = true
		WatermarksWindowSize = uint64(spec.Parser.Tcp.Watermarks.WindowSize)
		WatermarksBurstTriggerMult = uint64(spec.Parser.Tcp.Watermarks.BurstTriggerPercent)
		WatermarksDipTriggerMult = uint64(spec.Parser.Tcp.Watermarks.DipTriggerPercent)
		if spec.Parser.NetworkWatermarksExitGen.Enable && spec.Parser.NetworkWatermarksExitGen.Interval > 0 {
			go networkWatermarksEvents.Start(time.Duration(spec.Parser.NetworkWatermarksExitGen.Interval)*time.Millisecond, syscall.IPPROTO_TCP, false)
		}
	} else if spec.Parser.Tcp != nil && spec.Parser.Tcp.Burst.Enable && spec.Parser.Tcp.Burst.WindowSize > 0 && spec.Parser.Tcp.Burst.TriggerPercent > 0 {
		WatermarksEnabled = true
		WatermarksWindowSize = uint64(spec.Parser.Tcp.Burst.WindowSize)
		WatermarksBurstTriggerMult = uint64(spec.Parser.Tcp.Burst.TriggerPercent)
		if spec.Parser.NetworkWatermarksExitGen.Enable && spec.Parser.NetworkWatermarksExitGen.Interval > 0 {
			go networkWatermarksEvents.Start(time.Duration(spec.Parser.NetworkWatermarksExitGen.Interval)*time.Millisecond, syscall.IPPROTO_TCP, true)
		}
	} else {
		ParseWatermarksOptions()
	}
	if spec.Parser.Tcp != nil && (spec.Parser.Tcp.RttHistogram.Enable || enterpriseOption.Config.EnableTCPRTT) &&
		(spec.Parser.Tcp.RttHistogram.Max != 0 || spec.Parser.Tcp.RttHistogram.Min != 0) {
		tcpconfig.RttHistogramMax = spec.Parser.Tcp.RttHistogram.Max
		tcpconfig.RttHistogramMin = spec.Parser.Tcp.RttHistogram.Min
	} else {
		ParseRTTOptions()
	}
	if tcpconfig.RttHistogramMax < tcpconfig.RttHistogramMin {
		tcpconfig.RttHistogramMax = 0
		return fmt.Errorf("misconfigured RTT Histogram: Min value must be less than Max")
	}

	if spec.Parser.Tcp != nil {
		DisableConnect = spec.Parser.Tcp.DisableEvents.DisableConnect
		DisableClose = spec.Parser.Tcp.DisableEvents.DisableClose
		DisableAccept = spec.Parser.Tcp.DisableEvents.DisableAccept
		DisableListen = spec.Parser.Tcp.DisableEvents.DisableListen
	} else {
		ParseDisableOptions()
	}
	return nil
}

func ParseDisableOptions() {
	DisableConnect = enterpriseOption.Config.TCPDisableConnectEvents
	DisableClose = enterpriseOption.Config.TCPDisableCloseEvents
	DisableAccept = enterpriseOption.Config.TCPDisableAcceptEvents
	DisableListen = enterpriseOption.Config.TCPDisableListenEvents
}
func ParseMetricsOptions() {
	tcpconfig.MetricsEnabled = enterpriseOption.Config.EnableTCPMetrics
	tcpconfig.CurrentLabels = tcpconfig.DefaultLabelFilter().WithEnabledLabels(enterpriseOption.Config.TCPMetricsLabelFilter)
}

// ParseRTTOptions parses the Tetragon config and sets the config parameters.
func ParseRTTOptions() {
	if enterpriseOption.Config.EnableTCPRTT {
		tcpconfig.RttHistogramMin = enterpriseOption.Config.TCPRTTHistMin
		tcpconfig.RttHistogramMax = enterpriseOption.Config.TCPRTTHistMax
	} else {
		tcpconfig.RttHistogramMin = 0
		tcpconfig.RttHistogramMax = 0
	}
}

// ParseWatermarksOptions parses the Tetragon config and outputs the kernel selectors
// needed for BPF to identify TCP watermarks and run the monitor on it.
func ParseWatermarksOptions() {
	if enterpriseOption.Config.EnableTCPWatermarks {
		WatermarksEnabled = true
		WatermarksWindowSize = uint64(enterpriseOption.Config.TCPWatermarksWindowSizeMs)
		WatermarksBurstTriggerMult = uint64(enterpriseOption.Config.TCPWatermarksBurstTriggerPercent)
		WatermarksDipTriggerMult = uint64(enterpriseOption.Config.TCPWatermarksDipTriggerPercent)
		if enterpriseOption.Config.EnableNetworkWatermarksExitGen && enterpriseOption.Config.NetworkWatermarksExitGenInterval > 0 {
			go networkWatermarksEvents.Start(enterpriseOption.Config.NetworkWatermarksExitGenInterval, syscall.IPPROTO_TCP, false)
		}
	} else {
		WatermarksEnabled = false
		WatermarksWindowSize = 0
		WatermarksBurstTriggerMult = 0
		WatermarksDipTriggerMult = 0
	}
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
