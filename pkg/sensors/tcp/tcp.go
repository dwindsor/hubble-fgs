package tcp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/ip"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networkWatermarksEvents"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networklatency"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/cgroup"
	"github.com/isovalent/hubble-fgs/pkg/sensors/tcp/tcpconfig"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var (
	// There is no TCP stats interval default. Building a reasonable
	// default for random env is very difficult and users expected
	// setting the interval to zero would disable it.
	//TcpIntervalDefault            = time.Duration(60 * time.Second)
	tcpInterval                   time.Duration
	tcpStatsEnabled               bool
	tcpWatermarksEnable           bool
	tcpWatermarksWindowSize       uint64
	tcpWatermarksBurstTriggerMult uint64
	tcpWatermarksDipTriggerMult   uint64
	watermarksEnabled             = false

	stats          *lru.Cache[tcpKey, networkapi.MsgSocketStats]
	stataCacheSize = 32000

	configured       = false
	timestampEnabled = false

	disableConnect = false
	disableClose   = false
	disableAccept  = false
	disableListen  = false
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
		"tcp_sensor")

	SendCheck6 = program.Builder(
		"bpf_tcp_send_check.o",
		"inet6_csk_xmit",
		"kprobe/inet6_csk_xmit",
		"tg_inet6_csk_xmit",
		"tcp_sensor")

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
		"bpf_tcp_recv.o",
		"tcp_recv",
		"cgroup_skb/ingress",
		"tg_skb_ingress",
		"cgrp_tcp_ingress",
	)

	LatencyLazy = program.Builder(
		"bpf_tcp_recv_lazy.o",
		"tcp_recv",
		"cgroup_skb/ingress",
		"tg_skb_ingress",
		"cgrp_tcp_ingress",
	)

	// Maps for TCP Sockets
	SocketMap          = program.MapBuilder("tg_socket_map", Connect)
	SocketStats        = program.MapBuilder("tg_socket_map_stats", Accept)
	SocketTupleMap     = program.MapBuilder("tg_socket_tuple_map", Connect)
	SocketTupleStats   = program.MapBuilder("tg_socket_tuple_map_stats", Connect)
	SocketTupleHintMap = program.MapBuilder("tg_socket_tuple_hint_map", Connect)
	CfgMap             = program.MapBuilder("tg_cfg_map", Connect)
	AcceptSocketMap    = program.MapBuilder("tg_tcp_accept_sock_map", Accept)

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

type tcpBpfKey struct {
	SockCookie uint64
}

func (k *tcpBpfKey) String() string { return fmt.Sprintf("Cookie: %d", k.SockCookie) }

type tcpKey struct {
	SockCookie uint64
	CreateTime uint64
}

type tcpValue struct {
	Key             processapi.MsgExecveKey
	CreateTime      uint64
	ZeroWindow      uint32
	SocketFlags     uint32
	LastTime        uint64
	Sent            uint64
	Recv            uint64
	SegsOut         uint32
	SegsIn          uint32
	RetransmitBytes uint64
	RetransmitSegs  uint32
	SkDrops         uint32
	Srtt            uint32
	Pad1            uint32
	RttBuckets      [8]uint64
	LatencyBuckets  [8]uint64
	AckFinAck       uint8
	Pad2            [7]uint8
	RttSum          uint64
	LatencySum      uint64
	MsgIPTuple      networkapi.MsgIPTuple
}

func (t *tcpValue) String() string {
	return fmt.Sprintf("Pid: %d CreateTime %d Last %d Sent (%d:%d) Recv (%d:%d) Zero %d Retransmit (%d:%d) Drops %d Srtt %d",
		t.Key.Pid,
		t.CreateTime, t.LastTime,
		t.Sent, t.SegsOut, t.Recv, t.SegsIn,
		t.ZeroWindow,
		t.RetransmitBytes, t.RetransmitSegs,
		t.SkDrops, t.Srtt)
}

func (t *tcpValue) ToMsgSocketStatsUnix() *networkapi.MsgSocketStats {
	s := &networkapi.MsgSocketStats{}
	s.Ktime = t.LastTime
	s.CreateKtime = t.CreateTime
	s.BytesSent = t.Sent
	s.BytesReceived = t.Recv
	s.SegsIn = t.SegsIn
	s.SegsOut = t.SegsOut
	s.BytesSubmitted = t.Sent
	s.BytesConsumed = t.Recv
	s.SegsConsumed = 0
	s.SegsSubmitted = 0
	s.SRtt = t.Srtt
	s.RetransmitSegs = t.RetransmitSegs
	s.RetransmitBytes = t.RetransmitBytes
	s.ToZeroWindow = t.ZeroWindow
	s.SkDrop = t.SkDrops
	s.SkbConsumeMisses = 0

	s.Rtt = networkapi.Histogram{
		B00: t.RttBuckets[0],
		B01: t.RttBuckets[1],
		B10: t.RttBuckets[2],
		B25: t.RttBuckets[3],
		B50: t.RttBuckets[4],
		B75: t.RttBuckets[5],
		B90: t.RttBuckets[6],
		B99: t.RttBuckets[7],
		Sum: t.RttSum,
	}

	s.Latency = networkapi.Histogram{
		B00: t.LatencyBuckets[0],
		B01: t.LatencyBuckets[1],
		B10: t.LatencyBuckets[2],
		B25: t.LatencyBuckets[3],
		B50: t.LatencyBuckets[4],
		B75: t.LatencyBuckets[5],
		B90: t.LatencyBuckets[6],
		B99: t.LatencyBuckets[7],
		Sum: t.LatencySum,
	}

	return s
}

func (t *tcpValue) ToMsgIpTuple() *networkapi.MsgIPTuple {
	return &t.MsgIPTuple
}

func unloadTcpSensor() error {
	// We want to make sure we stand configuration up when loading/unloading the sensor.
	configured = false
	timestampEnabled = false

	networklatency.Stop(unix.IPPROTO_TCP)
	if watermarksEnabled {
		networkWatermarksEvents.Stop(IPPROTO_TCP)
	}
	return nil
}

func EnableTcp(timestampEnable bool) *sensors.Sensor {
	var progs []*program.Program

	// We want to make sure we stand configuration up when loading/unloading the sensor.
	configured = false
	timestampEnabled = false

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
		timestampEnabled = true
		timestampProg, err := networklatency.TCEgressTimestamp(unix.IPPROTO_TCP)
		if err == nil {
			progs = append(progs, timestampProg)
		} else {
			logger.GetLogger().Warn("TCP unsupported by network latency")
		}
		if !kernels.MinKernelVersion("5.10.0") {
			progs = append(progs, LatencyLazy)
			maps = append(maps, LatencyConfigMapLazy)
		} else {
			progs = append(progs, Latency)
			maps = append(maps, LatencyConfigMap)
		}
	}

	logger.GetLogger().WithFields(logrus.Fields{
		"statsInterval":              tcpInterval,
		"watermarksEnable":           tcpWatermarksEnable,
		"watermarksWindowSize":       tcpWatermarksWindowSize,
		"watermarksBurstTriggerMult": tcpWatermarksBurstTriggerMult,
		"maxRttHistogram":            tcpconfig.RttHistogramMax,
		"minRttHistogram":            tcpconfig.RttHistogramMin,
		"metrics":                    tcpconfig.MetricsEnabled,
	}).Infof("Enable TCP")
	tcpSensor := sensors.SensorBuilder("tcp_sensors", progs, maps)
	tcpSensor.PreUnloadHook = unloadTcpSensor
	return tcpSensor
}

type tcpSensor struct {
	name string
}

func (tcp *tcpSensor) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	fid policyfilter.PolicyID,
) (*sensors.Sensor, error) {
	spec := policy.TpSpec()

	if !spec.Parser.Tcp.Enable {
		return nil, nil
	}

	if spec.Parser.Tcp.Metrics != nil {
		tcpconfig.MetricsEnabled = spec.Parser.Tcp.Metrics.Enable
		tcpconfig.ConfigureLabels(spec.Parser.Tcp.Metrics.LabelFilters)
	} else {
		tcpconfig.MetricsEnabled = true
	}

	if fid != policyfilter.NoFilterID {
		return nil, fmt.Errorf("tcp sensor does not implement policy filtering")
	}

	if spec.Parser.Tcp.StatsInterval > 0 {
		tcpInterval = time.Duration(spec.Parser.Tcp.StatsInterval) * time.Second
		tcpStatsEnabled = true
	} else {
		tcpStatsEnabled = false
	}
	if spec.Parser.Tcp.Watermarks.Enable && spec.Parser.Tcp.Watermarks.WindowSize > 0 && spec.Parser.Tcp.Watermarks.BurstTriggerPercent > 0 {
		watermarksEnabled = true
		tcpWatermarksEnable = true
		tcpWatermarksWindowSize = uint64(spec.Parser.Tcp.Watermarks.WindowSize)
		tcpWatermarksBurstTriggerMult = uint64(spec.Parser.Tcp.Watermarks.BurstTriggerPercent)
		tcpWatermarksDipTriggerMult = uint64(spec.Parser.Tcp.Watermarks.DipTriggerPercent)
		go networkWatermarksEvents.Start(spec, IPPROTO_TCP, false)
	} else if spec.Parser.Tcp.Burst.Enable && spec.Parser.Tcp.Burst.WindowSize > 0 && spec.Parser.Tcp.Burst.TriggerPercent > 0 {
		watermarksEnabled = true
		tcpWatermarksEnable = true
		tcpWatermarksWindowSize = uint64(spec.Parser.Tcp.Burst.WindowSize)
		tcpWatermarksBurstTriggerMult = uint64(spec.Parser.Tcp.Burst.TriggerPercent)
		go networkWatermarksEvents.Start(spec, IPPROTO_TCP, true)
	} else {
		tcpWatermarksEnable = false
		tcpWatermarksWindowSize = 0
		tcpWatermarksBurstTriggerMult = 0
		tcpWatermarksDipTriggerMult = 0
	}
	if spec.Parser.Tcp.RttHistogram.Enable {
		tcpconfig.RttHistogramMax = spec.Parser.Tcp.RttHistogram.Max
		tcpconfig.RttHistogramMin = spec.Parser.Tcp.RttHistogram.Min

		if tcpconfig.RttHistogramMax < tcpconfig.RttHistogramMin {
			return nil, fmt.Errorf("Misconfigured Rtt Histogram: Min value must be less than Max")
		}
	} else {
		tcpconfig.RttHistogramMax = 0
	}
	tcpconfig.LatencyConfig, _ = networklatency.ParseLatencySpec(spec.Parser.Tcp.Latency, unix.IPPROTO_TCP)

	disableConnect = spec.Parser.Tcp.DisableEvents.DisableConnect
	disableClose = spec.Parser.Tcp.DisableEvents.DisableClose
	disableAccept = spec.Parser.Tcp.DisableEvents.DisableAccept
	disableListen = spec.Parser.Tcp.DisableEvents.DisableListen
	return EnableTcp(spec.Parser.Tcp.Latency.Enable), nil
}

func tcpDiffHistogram(last, curr *networkapi.Histogram, ty, source, dest string) (networkapi.Histogram, error) {
	if curr.B99 < last.B99 ||
		curr.B90 < last.B90 ||
		curr.B75 < last.B75 ||
		curr.B50 < last.B50 ||
		curr.B25 < last.B25 ||
		curr.B10 < last.B10 ||
		curr.B01 < last.B01 ||
		curr.B00 < last.B00 ||
		curr.Sum < last.Sum {
		logger.GetLogger().WithFields(logrus.Fields{"source": source, "dest": dest, "curr": curr, "last": last}).Warnf("TCP %s stats underflow", ty)
		return networkapi.Histogram{}, fmt.Errorf("TCP %s stats invalid diff operation", ty)
	}
	return networkapi.Histogram{
		B99: curr.B99 - last.B99,
		B90: curr.B90 - last.B90,
		B75: curr.B75 - last.B75,
		B50: curr.B50 - last.B50,
		B25: curr.B25 - last.B25,
		B10: curr.B10 - last.B10,
		B01: curr.B01 - last.B01,
		B00: curr.B00 - last.B00,
		Sum: curr.Sum - last.Sum,
	}, nil
}

func tcpDiffValues(last, curr *networkapi.MsgSocketStats, tuple *networkapi.MsgIPTuple) (networkapi.MsgSocketStats, error) {
	source, dest := networkapi.TupleAddrString(tuple, ops.MSG_OP_TCPSTATS)
	if curr.BytesReceived < last.BytesReceived {
		logger.GetLogger().WithFields(logrus.Fields{
			"tuple": tuple,
			"curr":  curr,
			"last":  last,
		}).Warnf("RX TCP stats received bytes underflow")
		return *last, fmt.Errorf("TCP BytesReceived stats invalid diff operation")
	}
	if curr.BytesSent < last.BytesSent {
		logger.GetLogger().WithFields(logrus.Fields{
			"tuple": tuple,
			"curr":  curr,
			"last":  last,
		}).Warnf("TX TCP stats sent bytes underflow")
		return *last, fmt.Errorf("TCP BytesSent stats invalid diff operation")
	}
	rttHist, err := tcpDiffHistogram(&last.Rtt, &curr.Rtt, "RTT", source, dest)
	if err != nil {
		return *last, err
	}
	latencyHist, err := tcpDiffHistogram(&last.Latency, &curr.Latency, "Latency", source, dest)
	if err != nil {
		return *last, err
	}
	return networkapi.MsgSocketStats{
		BytesSubmitted:   0,
		BytesSent:        curr.BytesSent - last.BytesSent,
		BytesConsumed:    0,
		BytesReceived:    curr.BytesReceived - last.BytesReceived,
		SegsConsumed:     0,
		SegsIn:           curr.SegsIn - last.SegsIn,
		SegsSubmitted:    0,
		SegsOut:          curr.SegsOut - last.SegsOut,
		SRtt:             curr.SRtt,
		RetransmitSegs:   curr.RetransmitSegs - last.RetransmitSegs,
		RetransmitBytes:  curr.RetransmitBytes - last.RetransmitBytes,
		ToZeroWindow:     curr.ToZeroWindow - last.ToZeroWindow,
		SkDrop:           curr.SkDrop - last.SkDrop,
		SkbConsumeMisses: 0,
		Rtt:              rttHist,
		Latency:          latencyHist,
	}, nil
}

// There is a race condition where two events are sent from BPF side in close
// proximity time wise to each other. In this case its possible to process the
// events out of order. Specifically it means when we diff the events the 'last'
// event in cache will have a newer time than the 'new' event from BPF side. If
// this happens discard the older event.
func correctedStatsEvent(tcp *layer3.MsgIPWithStatsEventUnix) (*layer3.MsgIPWithStatsEventUnix, error) {
	statsKey := tcpKey{SockCookie: tcp.Msg.SockCookie, CreateTime: tcp.Msg.SocketStats.CreateKtime}
	last, ok := stats.Get(statsKey)
	if ok {
		if tcp.Msg.SocketStats.Ktime < last.Ktime {
			// Current stats message is older than last stats message.
			// This indicates the race has occurred, so we discard.
			return nil, fmt.Errorf("TCP stats message is older than previous")
		}

		// If we already posted an entry and nothings changed skip it.
		if tcp.Msg.SocketStats.Ktime == last.Ktime {
			return nil, fmt.Errorf("TCP stats message duplicate")
		}

		tmpSocketStats, err := tcpDiffValues(&last, &tcp.Msg.SocketStats, &tcp.Msg.Tuple)
		if err != nil {
			return nil, err
		}
		stats.Add(statsKey, tcp.Msg.SocketStats)
		tcp.Msg.SocketStats = tmpSocketStats
	}
	return tcp, nil
}

func handleTcpClose(r *bytes.Reader) ([]observer.Event, error) {
	m := networkapi.MsgIPWithStatsEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	tcp := ip.MsgToIPWithStatsUnix(&m)
	if tcpStatsEnabled {
		cp := *tcp
		c, err := correctedStatsEvent(&cp)
		if err != nil {
			return []observer.Event{tcp}, nil
		}
		// Convert to a TCPStats event by simply setting op code
		c.Msg.Common.Op = ops.MsgOpTCPStats
		statsKey := tcpKey{SockCookie: c.Msg.SockCookie, CreateTime: c.Msg.SocketStats.CreateKtime}
		stats.Remove(statsKey)
		return []observer.Event{tcp, c}, nil
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

func (tcp *tcpSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	getRunningSockets(true, true)

	if args.Load.Type == "cgrp_tcp_ingress" {
		err := cgroup.LoadCgroupProgram(args.BPFDir, args.Load, args.Verbose)
		if err != nil {
			return err
		}
	} else if args.Load.Type == "tcp_tc_egress" {
		err := networklatency.AttachTc(args)
		if err != nil {
			return err
		}
	} else {
		if tcpStatsEnabled {
			configureSockStatSampler(tcpInterval,
				tcpWatermarksEnable,
				tcpWatermarksWindowSize,
				tcpWatermarksBurstTriggerMult,
				tcpWatermarksDipTriggerMult,
				tcpconfig.RttHistogramMax,
				tcpconfig.RttHistogramMin)
		}
		configureTCPDisableEvents(disableConnect, disableClose, disableAccept, disableListen)
		err := program.LoadKprobeProgram(args.BPFDir, args.Load, args.Verbose)
		if err != nil {
			return err
		}
	}

	if !configured {
		if timestampEnabled {
			if err := networklatency.ConfigureLatency(args.BPFDir, unix.IPPROTO_TCP, tcpconfig.LatencyConfig); err != nil {
				return err
			}
			networklatency.Start()
		}
		configured = true
	}

	return nil
}

func init() {
	AddTCP()
}

func AddTCP() {
	var err error

	stats, err = lru.New[tcpKey, networkapi.MsgSocketStats](stataCacheSize)
	if err != nil {
		logger.GetLogger().WithError(err).Errorf("TCP cache failed. Disabling TCP")
		return
	}

	tcp := &tcpSensor{
		name: "TCP sensor",
	}

	sensors.RegisterProbeType("tcp_sensor", tcp)
	sensors.RegisterPolicyHandlerAtInit(tcp.name, tcp)

	/* Core set of TCP events */
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_TCPCONNECT, handleTcp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_TCPCONNECTRET, handleTcp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_TCPCLOSE, handleTcpClose)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_BIND, handleTcp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_LISTEN, handleTcp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_ACCEPT, handleTcp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_PROCESS_NETWORK_WATERMARK, networkWatermarksEvents.HandleProcessNetworkWatermarks)

	sensors.RegisterProbeType("cgrp_tcp_ingress", tcp)
	sensors.RegisterProbeType("tcp_tc_egress", tcp)
}
