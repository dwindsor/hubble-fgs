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

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	"github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	"github.com/isovalent/hubble-fgs/pkg/model/matchLabels"
	"github.com/isovalent/hubble-fgs/pkg/model/policy"
	model "github.com/isovalent/hubble-fgs/pkg/model/server"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/ip"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/tcpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networkWatermarksEvents"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networklatency"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
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

func SetConfig(cfg *networkapi.Layer3ConfigValue) error {
	ConfigureSockStatSampler(cfg,
		StatsInterval,
		WatermarksEnable,
		WatermarksWindowSize,
		WatermarksBurstTriggerMult,
		WatermarksDipTriggerMult,
		tcpconfig.RttHistogramMax,
		tcpconfig.RttHistogramMin)
	// If this is a CLI configuration lets inherit the network events
	// configuration as well.
	if enterpriseOption.Config.Layer3CLIEnable {
		DisableConnect = !enterpriseOption.Config.EnableNetworkEvents
		DisableClose = !enterpriseOption.Config.EnableNetworkEvents
		DisableAccept = !enterpriseOption.Config.EnableNetworkEvents
		DisableListen = !enterpriseOption.Config.EnableNetworkEvents
	}
	ConfigureTCPDisableEvents(cfg, DisableConnect, DisableClose, DisableAccept, DisableListen)
	return nil
}

func ConfigureSensor() error {
	getRunningSockets(true, true)
	return nil
}

func UnloadSensor(cfg *networkapi.Layer3ConfigValue, tp tracingpolicy.TracingPolicy) error {
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
		program.MapUserFrom(base.ProcessTreeUUIDBinaryMap),
		program.MapUserFrom(base.DestinationEndpointMap),
		program.MapUserFrom(base.ListenEndpointMap),
	}
	maps = append(maps, []*program.Map{tcpconfig.Addr4LpmMap, tcpconfig.Addr6LpmMap}...)
	return maps
}

func EnableTcp(timestampEnable bool) ([]*program.Program, []*program.Program, []*program.Map) {
	TimestampEnabled = false

	progsInitSock := []*program.Program{}
	progsCollectStats := []*program.Program{}

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
		tcpconfig.ProcessNetworkWatermarksMap,
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
		err := dnsparser.RewriteConstants(tcpconfig.TcpSockops.RewriteConstants)
		if err != nil {
			// TODO: when we remove enabling layer3 from CRD, return this error and stop init of sensor
			logger.GetLogger().Error("Failed to rewrite DNS parser constants", logfields.Error, err)
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
