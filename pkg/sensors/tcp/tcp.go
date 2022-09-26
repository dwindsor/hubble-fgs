package tcp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	lru "github.com/hashicorp/golang-lru"
	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/burstEvents"
	"github.com/isovalent/hubble-fgs/pkg/sensors/ip"
	"github.com/sirupsen/logrus"
)

var (
	TcpIntervalDefault  = time.Duration(60 * time.Second)
	tcpInterval         time.Duration
	tcpBurstEnable      bool
	tcpBurstWindowSize  uint64
	tcpBurstTriggerMult uint64
	watermarkEnabled    = false

	tcpRttHistogramMax uint32
	tcpRttHistogramMin uint32

	stats          *lru.Cache
	stataCacheSize = 32000
)

var (
	Connect = program.Builder(
		"bpf_tcpmon.o",
		"tcp_connect",
		"kprobe/tcp_connect",
		"kprobe_tcp_connect",
		"kprobe",
	)

	Close = program.Builder(
		"bpf_tcpclose.o",
		"tcp_set_state",
		"kprobe/tcp_set_state",
		"kprobe_tcp_set_state",
		"kprobe",
	)

	Listen = program.Builder(
		"bpf_listen.o",
		"__inet_hash",
		"kprobe/__inet_hash",
		"kprobe___inet_hash",
		"kprobe",
	)

	Accept = program.Builder(
		"bpf_tcpaccept.o",
		"syscalls/sys_exit_accept",
		"tracepoint/syscalls/sys_exit_accept",
		"tracepoint_syscalls_sys_exit_accept",
		"tracepoint",
	)

	Accept4 = program.Builder(
		"bpf_tcpaccept.o",
		"syscalls/sys_exit_accept4",
		"tracepoint/syscalls/sys_exit_accept4",
		"tracepoint_syscalls_sys_exit_accept4",
		"tracepoint",
	)

	AcceptV56 = program.Builder(
		"bpf_tcpaccept_v56.o",
		"syscalls/sys_exit_accept",
		"tracepoint/syscalls/sys_exit_accept",
		"tracepoint_syscalls_sys_exit_accept",
		"tracepoint",
	)

	Accept4V56 = program.Builder(
		"bpf_tcpaccept_v56.o",
		"syscalls/sys_exit_accept4",
		"tracepoint/syscalls/sys_exit_accept4",
		"tracepoint_syscalls_sys_exit_accept4",
		"tracepoint",
	)

	SendCheck4 = program.Builder(
		"bpf_tcp_send_check.o",
		"tcp_v4_send_check",
		"kprobe/tcp_v4_send_check",
		"kprobe_tcp_v4_send_check",
		"tcp_sensor")

	SendCheck6 = program.Builder(
		"bpf_tcp_send_check.o",
		"inet6_csk_xmit",
		"kprobe/inet6_csk_xmit",
		"kprobe_inet6_csk_xmit",
		"tcp_sensor")

	// RTT Tracer uses kprobe because its most general solution for optimization
	// reassons on kernels 5.4+ we might consider using OPS_RTT hook. This is
	// going to collect the timestamp from the received skb. A couple thinigs are
	// worth mentioning. (i) we only collect these on established TCP state where
	// segs_in includes the syn,ack and other friends so expecting counts to add
	// up to segs_in is not valid. Also segs_in accounts for gro segs where here
	// we only do single inc on the bucket for entire skb even if it has many segs.
	// I think this makes some sense but open to discuss it. Anyways, segs_in != sum(count)
	// (ii) TCP will toss out some RTTs when calculating the relevant function is
	// tcp_rcv_rtt_measture_ts, typically this is to deal with underflow.
	RttTracer = program.Builder(
		"bpf_tcp_rtt.o",
		"__tcp_ack_snd_check",
		"kprobe/__tcp_ack_snd_check",
		"kprobe_tcp_ack_snd_check",
		"kprobe")

	// Maps for TCP Sockets
	SocketMap    = program.MapBuilder("socket_map", Connect)
	TlsSocketMap = program.MapBuilder("tls_socket_map", Connect)
	SocketStats  = program.MapBuilder("socket_map_stats", Connect)

	// Parser maps
	HTTPContext    = program.MapBuilder("http_map", Close)
	TLSContext     = program.MapBuilder("tls_map", Close)
	TLSMapStats    = program.MapBuilder("tls_map_stats", Connect)
	TLSBottles     = program.MapBuilder("bottles", Close)
	TLSBottleStats = program.MapBuilder("bottle_map_stats", Close)

	// Maps for burst detection
	SendCheckSampler       = program.MapBuilder("tcp_send_check_sampler", SendCheck4)
	ProcessNetworkBurstMap = program.MapBuilder(burstEvents.ProcessNetworkBurstMapName, SendCheck4)
)

func unloadTcpSensor() error {
	if watermarkEnabled {
		burstEvents.Stop()
	}
	return nil
}

func EnableTcp() *sensors.Sensor {
	var progs []*program.Program

	if !kernels.MinKernelVersion("5.6.0") {
		progs = []*program.Program{
			Connect,
			Close,
			Listen,
			Accept,
			Accept4,
			SendCheck4,
			SendCheck6,
		}
	} else {
		progs = []*program.Program{
			Connect,
			Close,
			Listen,
			AcceptV56,
			Accept4V56,
			SendCheck4,
			SendCheck6,
		}
	}

	if tcpRttHistogramMax != 0 {
		progs = append(progs, RttTracer)
	}

	maps := []*program.Map{
		SocketStats,
		SocketMap,
		TlsSocketMap,
		HTTPContext,
		TLSContext,
		TLSMapStats,
		TLSBottles,
		TLSBottleStats,
		SendCheckSampler,
		ProcessNetworkBurstMap,
	}
	logger.GetLogger().WithFields(logrus.Fields{
		"statsInterval":    tcpInterval,
		"burstEnable":      tcpBurstEnable,
		"burstWindowSize":  tcpBurstWindowSize,
		"burstTriggerMult": tcpBurstTriggerMult,
		"maxRttHistogram":  tcpRttHistogramMax,
		"minRttHistogram":  tcpRttHistogramMin,
	}).Infof("Enable TCP")
	tcpSensor := sensors.SensorBuilder("tcp_sensors", progs, maps)
	tcpSensor.UnloadHook = unloadTcpSensor
	return tcpSensor
}

type tcpSensor struct {
	name string
}

func (tcp *tcpSensor) SpecHandler(raw interface{}) (*sensors.Sensor, error) {
	spec := raw.(*v1alpha1.TracingPolicySpec)
	tcpInterval = time.Duration(TcpIntervalDefault)

	if !spec.Parser.Tcp.Enable {
		return nil, nil
	}
	if spec.Parser.Tcp.StatsInterval > 0 {
		tcpInterval = time.Duration(spec.Parser.Tcp.StatsInterval) * time.Second
	}
	if spec.Parser.Tcp.Burst.Enable && spec.Parser.Tcp.Burst.WindowSize > 0 && spec.Parser.Tcp.Burst.TriggerPercent > 0 {
		watermarkEnabled = true
		tcpBurstEnable = true
		tcpBurstWindowSize = uint64(spec.Parser.Tcp.Burst.WindowSize)
		tcpBurstTriggerMult = uint64(spec.Parser.Tcp.Burst.TriggerPercent)
		go burstEvents.Start(spec)
	} else {
		tcpBurstEnable = false
		tcpBurstWindowSize = 0
		tcpBurstTriggerMult = 0
	}
	if spec.Parser.Tcp.RttHistogram.Enable {
		tcpRttHistogramMax = spec.Parser.Tcp.RttHistogram.Max
		tcpRttHistogramMin = spec.Parser.Tcp.RttHistogram.Min

		if tcpRttHistogramMax < tcpRttHistogramMin {
			return nil, fmt.Errorf("Misconfigured Rtt Histogram: Min value must be less than Max")
		}
	} else {
		tcpRttHistogramMax = 0
	}
	return EnableTcp(), nil
}

func tcpDiffRtt(last, curr *api.Histogram) api.Histogram {
	return api.Histogram{
		B99: curr.B99 - last.B99,
		B90: curr.B90 - last.B90,
		B75: curr.B75 - last.B75,
		B50: curr.B50 - last.B50,
		B25: curr.B25 - last.B25,
		B10: curr.B10 - last.B10,
		B01: curr.B01 - last.B01,
		B00: curr.B00 - last.B00,
	}
}

func tcpDiffValues(last, curr *api.MsgSocketStatsUnix) (api.MsgSocketStatsUnix, error) {
	if curr.BytesReceived < last.BytesReceived {
		logger.GetLogger().Warnf("RX TCP stats underflow: %d < %d", curr.BytesReceived, last.BytesReceived)
		return *last, fmt.Errorf("TCP BytesReceived stats invalid diff operation")
	}
	if curr.BytesSent < last.BytesSent {
		logger.GetLogger().Warnf("TX TCP stats underflow: %d < %d", curr.BytesSent, last.BytesSent)
		return *last, fmt.Errorf("TCP BytesSent stats invalid diff operation")
	}
	return api.MsgSocketStatsUnix{
		BytesSubmitted:   0,
		BytesSent:        curr.BytesSent - last.BytesSent,
		BytesConsumed:    0,
		BytesReceived:    curr.BytesReceived - last.BytesReceived,
		ConsumedSegs:     0,
		SegsIn:           curr.SegsIn - last.SegsIn,
		SubmittedSegs:    0,
		SegsOut:          curr.SegsOut - last.SegsOut,
		SRtt:             curr.SRtt,
		RetransmitSegs:   curr.RetransmitSegs - last.RetransmitSegs,
		RetransmitBytes:  curr.RetransmitBytes - last.RetransmitBytes,
		ToZeroWindow:     curr.ToZeroWindow - last.ToZeroWindow,
		SkDrop:           curr.SkDrop - last.SkDrop,
		SkbConsumeMisses: 0,
		Rtt:              tcpDiffRtt(&last.Rtt, &curr.Rtt),
	}, nil
}

// There is a race condition where two events are sent from BPF side in close
// proximity time wise to each other. In this case its possible to process the
// events out of order. Specifically it means when we diff the events the 'last'
// event in cache will have a newer time than the 'new' event from BPF side. If
// this happens discard the older event.
func correctedStatsEvent(tcp *layer3.MsgIPEventUnix) (*layer3.MsgIPEventUnix, error) {
	entry, ok := stats.Get(tcp.Tuple)
	if ok {
		last := entry.(api.MsgSocketStatsUnix)

		if tcp.SocketStats.Ktime < last.Ktime {
			// Current stats message is older than last stats message.
			// This indicates the race has occurred, so we discard.
			return nil, fmt.Errorf("TCP stats message is older than previous")
		}

		tmpSocketStats, err := tcpDiffValues(&last, &tcp.SocketStats)
		if err != nil {
			return nil, err
		}
		stats.Add(tcp.Tuple, tcp.SocketStats)
		tcp.SocketStats = tmpSocketStats
	} else {
		stats.Add(tcp.Tuple, tcp.SocketStats)
	}
	return tcp, nil
}

func handleTcpStats(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgIPEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	tcp, err := correctedStatsEvent(ip.MsgToIPUnix(&m, true))
	if err != nil {
		return nil, nil
	}
	return []observer.Event{tcp}, nil
}

func handleTcpClose(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgIPEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	tcp := ip.MsgToIPUnix(&m, true)
	if tcpInterval > 0 {
		cp := *tcp
		c, err := correctedStatsEvent(&cp)
		if err != nil {
			return []observer.Event{tcp}, nil
		}
		// Convert to a TCPStats event by simply setting op code
		c.Common.Op = ops.MsgOpTCPStats
		stats.Remove(c.Tuple)
		return []observer.Event{tcp, c}, nil
	}
	return []observer.Event{tcp}, nil
}

func handleTcp(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgIPEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	// Do not include RTT in open, listen, binds
	tcp := ip.MsgToIPUnix(&m, false)
	return []observer.Event{tcp}, nil
}

func (tcp *tcpSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	var err error

	err = nil

	getRunningSockets(true, true)

	if tcpInterval > 0 {
		configureSockStatSampler(tcpInterval, tcpBurstEnable, tcpBurstWindowSize, tcpBurstTriggerMult, tcpRttHistogramMax, tcpRttHistogramMin)
		err = program.LoadKprobeProgram(args.BPFDir, args.MapDir, args.Load, args.Verbose)
	}
	return err
}

func init() {
	AddTCP()
}

func AddTCP() {
	var err error

	stats, err = lru.New(stataCacheSize)
	if err != nil {
		logger.GetLogger().WithError(err).Errorf("TCP cache failed. Disabling TCP")
		return
	}

	tcp := &tcpSensor{
		name: "TCP sensor",
	}

	sensors.RegisterProbeType("tcp_sensor", tcp)
	sensors.RegisterTracingSensorsAtInit(tcp.name, tcp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_TCPSTATS, handleTcpStats)

	/* Core set of TCP events */
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_TCPCONNECT, handleTcp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_TCPCONNECTRET, handleTcp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_TCPCLOSE, handleTcpClose)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_BIND, handleTcp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_LISTEN, handleTcp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_ACCEPT, handleTcp)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_PROCESS_NETWORK_BURST, burstEvents.HandleProcessNetworkBurst)
}
