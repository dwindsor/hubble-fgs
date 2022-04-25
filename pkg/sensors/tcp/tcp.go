package tcp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/sensors/burstEventsPoll"
	"github.com/isovalent/hubble-fgs/pkg/sensors/ipv4"
	"github.com/sirupsen/logrus"

	loader "github.com/isovalent/hubble-fgs/pkg/bpf"
)

var (
	TcpIntervalDefault  = time.Duration(60 * time.Second)
	tcpInterval         time.Duration
	tcpBurstEnable      bool
	tcpBurstWindowSize  uint64
	tcpBurstTriggerMult uint64

	stats          *lru.Cache
	stataCacheSize = 32000
)

var (
	TCPSendCheck = sensors.ProgramBuilder(
		"bpf_tcp_send_check.o",
		"tcp_v4_send_check",
		"kprobe/tcp_v4_send_check",
		"kprobe_tcp_v4_send_check",
		"tcp_sensor")

	TCPSendCheckSampler    = sensors.MapBuilder("tcp_send_check_sampler", TCPSendCheck)
	ProcessNetworkBurstMap = sensors.MapBuilder(burstEventsPoll.ProcessNetworkBurstMapName, TCPSendCheck)
)

func EnableTcp() *sensors.Sensor {
	progs := []*sensors.Program{
		TCPSendCheck,
	}
	maps := []*sensors.Map{
		TCPSendCheckSampler,
	}
	logger.GetLogger().WithFields(logrus.Fields{
		"statsInterval":    tcpInterval,
		"burstEnable":      tcpBurstEnable,
		"burstWindowSize":  tcpBurstWindowSize,
		"burstTriggerMult": tcpBurstTriggerMult,
	}).Infof("Enable TCP")
	return sensors.SensorBuilder("tcp_sensors", progs, maps)
}

type tcpSensor struct {
	name string
}

func (tcp *tcpSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
	tcpInterval = time.Duration(TcpIntervalDefault)

	if !spec.Parser.Tcp.Enable {
		return nil, nil
	}
	if spec.Parser.Tcp.StatsInterval > 0 {
		tcpInterval = time.Duration(spec.Parser.Tcp.StatsInterval) * time.Second
	}
	if spec.Parser.Tcp.Burst.Enable && spec.Parser.Tcp.Burst.WindowSize > 0 && spec.Parser.Tcp.Burst.TriggerPercent > 0 {
		tcpBurstEnable = true
		tcpBurstWindowSize = uint64(spec.Parser.Tcp.Burst.WindowSize)
		tcpBurstTriggerMult = uint64(spec.Parser.Tcp.Burst.TriggerPercent)
		go burstEventsPoll.Start(spec)
	} else {
		tcpBurstEnable = false
		tcpBurstWindowSize = 0
		tcpBurstTriggerMult = 0
	}
	return EnableTcp(), nil
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
		BytesSubmitted:  0,
		BytesSent:       curr.BytesSent - last.BytesSent,
		BytesConsumed:   0,
		BytesReceived:   curr.BytesReceived - last.BytesReceived,
		ConsumedSegs:    0,
		SegsIn:          curr.SegsIn - last.SegsIn,
		SubmittedSegs:   0,
		SegsOut:         curr.SegsOut - last.SegsOut,
		SRtt:            curr.SRtt,
		RetransmitSegs:  curr.RetransmitSegs - last.RetransmitSegs,
		RetransmitBytes: curr.RetransmitBytes - last.RetransmitBytes,
		ToZeroWindow:    curr.ToZeroWindow - last.ToZeroWindow,
		SkDrop:          curr.SkDrop - last.SkDrop,
	}, nil
}

// There is a race condition where two events are sent from BPF side in close
// proximity time wise to each other. In this case its possible to process the
// events out of order. Specifically it means when we diff the events the 'last'
// event in cache will have a newer time than the 'new' event from BPF side. If
// this happens discard the older event.
func correctedStatsEvent(tcp *api.MsgIPv4EventUnix) (*api.MsgIPv4EventUnix, error) {
	entry, ok := stats.Get(tcp.Tuple)
	if ok {
		last := entry.(api.MsgSocketStatsUnix)

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
	m := api.MsgIPv4Event{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	tcp, err := correctedStatsEvent(ipv4.MsgToIPv4Unix(&m))
	if err != nil {
		return nil, nil
	}
	return []observer.Event{tcp}, nil
}

func handleTcpClose(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgIPv4Event{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	tcp := ipv4.MsgToIPv4Unix(&m)
	if tcpInterval > 0 {
		cp := *tcp
		c, err := correctedStatsEvent(&cp)
		// Convert to a TCPStats event by simply setting op code
		c.Common.Op = api.MsgOpIPv4TCPStats
		stats.Remove(c.Tuple)
		if err != nil {
			return []observer.Event{tcp}, nil
		}
		return []observer.Event{tcp, c}, nil
	}
	return []observer.Event{tcp}, nil
}

func handleTcp(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgIPv4Event{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	tcp := ipv4.MsgToIPv4Unix(&m)
	return []observer.Event{tcp}, nil
}

func (tcp *tcpSensor) LoadProbe(args sensors.LoadProbeArgs) (int, error) {
	var err error
	var ret = 0

	err = nil

	if tcpInterval > 0 {
		configureSockStatSampler(tcpInterval, tcpBurstEnable, tcpBurstWindowSize, tcpBurstTriggerMult)
		ret, err = loader.LoadKprobeProgram(args.Version,
			args.Verbose,
			uintptr(btf.GetCachedBTF()),
			args.Load.Name,
			args.Load.Attach,
			args.Load.Label,
			filepath.Join(args.BPFDir, args.Load.PinPath),
			args.MapDir,
			args.Load.RetProbe)
	}
	getRunningSockets(true, true)
	return ret, err
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
	observer.RegisterEventHandlerAtInit(api.MSG_OP_IPV4_TCPSTATS, handleTcpStats)

	/* Core set of TCP events */
	observer.RegisterEventHandlerAtInit(api.MSG_OP_IPV4_TCPCONNECT, handleTcp)
	observer.RegisterEventHandlerAtInit(api.MSG_OP_IPV4_TCPCONNECTRET, handleTcp)
	observer.RegisterEventHandlerAtInit(api.MSG_OP_IPV4_TCPCLOSE, handleTcpClose)
	observer.RegisterEventHandlerAtInit(api.MSG_OP_IPV4_BIND, handleTcp)
	observer.RegisterEventHandlerAtInit(api.MSG_OP_IPV4_LISTEN, handleTcp)
	observer.RegisterEventHandlerAtInit(api.MSG_OP_IPV4_ACCEPT, handleTcp)
	observer.RegisterEventHandlerAtInit(api.MSG_OP_IPV4_PROCESS_BURST, burstEventsPoll.HandleProcessNetworkBurst)
}
