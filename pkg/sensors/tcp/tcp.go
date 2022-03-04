package tcp

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
	"github.com/sirupsen/logrus"

	loader "github.com/isovalent/hubble-fgs/pkg/bpf"
)

var (
	TcpIntervalDefault = time.Duration(60 * time.Second)
	tcpInterval        time.Duration

	stats          *lru.Cache
	stataCacheSize = 32000
)

var (
	TCPSendCheck = sensors.ProgramBuilder(
		"bpf_tcp_send_check.o",
		"tcp_v4_send_check",
		"kprobe/tcp_v4_send_check",
		"kprobe_tcp_v4_send_check",

		false,
		true,
		"tcp_sensor")

	TCPSendCheckSampler = sensors.MapBuilder("tcp_send_check_sampler", "", TCPSendCheck)
)

func EnableTcp() *sensors.Sensor {
	progs := []*sensors.Program{
		TCPSendCheck,
	}
	maps := []*sensors.Map{
		TCPSendCheckSampler,
	}
	logger.GetLogger().WithFields(logrus.Fields{
		"statsInterval": tcpInterval,
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
	} else {
		return nil, nil
	}
	return EnableTcp(), nil
}

func tcpDiffValues(last, curr *api.MsgSocketStatsUnix) api.MsgSocketStatsUnix {
	if curr.BytesReceived < last.BytesReceived {
		logger.GetLogger().Warnf("RX TCP stats underflow: %d < %d", curr.BytesReceived, last.BytesReceived)
	}
	if curr.BytesSent < last.BytesSent {
		logger.GetLogger().Warnf("TX TCP stats underflow: %d < %d", curr.BytesReceived, last.BytesReceived)
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
	}
}

func correctedStatsEvent(tcp *api.MsgIPv4EventUnix) *api.MsgIPv4EventUnix {
	entry, ok := stats.Get(tcp.Tuple)
	if ok {
		last := entry.(api.MsgSocketStatsUnix)

		stats.Add(tcp.Tuple, tcp.SocketStats)
		tcp.SocketStats = tcpDiffValues(&last, &tcp.SocketStats)
	} else {
		stats.Add(tcp.Tuple, tcp.SocketStats)
	}
	return tcp
}

func handleTcpStats(r *bytes.Reader) ([]observer.ObserverEvent, error) {
	m := api.MsgIPv4Event{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	tcp := correctedStatsEvent(observer.MsgToIPv4Unix(&m))
	return []observer.ObserverEvent{tcp}, nil
}

func handleTcpClose(r *bytes.Reader) ([]observer.ObserverEvent, error) {
	m := api.MsgIPv4Event{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	tcp := observer.MsgToIPv4Unix(&m)
	if tcpInterval > 0 {
		cp := *tcp
		c := correctedStatsEvent(&cp)
		// Convert to a TCPStats event by simply setting op code
		c.Common.Op = api.MsgOpIPv4TCPStats
		stats.Remove(c.Tuple)
		return []observer.ObserverEvent{tcp, c}, nil
	}
	return []observer.ObserverEvent{tcp}, nil
}

func handleTcp(r *bytes.Reader) ([]observer.ObserverEvent, error) {
	m := api.MsgIPv4Event{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	tcp := observer.MsgToIPv4Unix(&m)
	return []observer.ObserverEvent{tcp}, nil
}

func (tcp *tcpSensor) LoadProbe(args sensors.LoadProbeArgs) (error, int) {
	configureSockStatSampler(tcpInterval)
	return loader.LoadKprobeProgram(args.Version,
		args.Verbose,
		uintptr(btf.GetCachedBTF()),
		args.Load.Name,
		args.Load.Attach,
		args.Load.Label,
		filepath.Join(args.BPFDir, args.Load.PinPath),
		args.MapDir,
		args.Load.RetProbe)
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
}
