package tcp

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"time"

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
)

var (
	TCPSendCheck = sensors.ProgramBuilder(
		"bpf_tcp_send_check.o",
		"tcp_v4_send_check",
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

func handleTcpStats(r *bytes.Reader) ([]observer.ObserverEvent, error) {
	m := api.MsgIPv4Event{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	msgUnix := observer.MsgToIPv4Unix(&m)
	return []observer.ObserverEvent{msgUnix}, nil
}

func (tcp *tcpSensor) LoadProbe(args sensors.LoadProbeArgs) (error, int) {
	configureSockStatSampler(tcpInterval)
	return loader.LoadKprobeProgram(args.Version,
		args.Verbose,
		uintptr(btf.GetCachedBTF()),
		args.Load.Name,
		args.Load.X64Attach,
		args.Load.Label,
		filepath.Join(args.BPFDir, args.Load.PinPath),
		args.MapDir,
		args.Load.RetProbe)
}

func init() {
	AddTCP()
}

func AddTCP() {
	tcp := &tcpSensor{
		name: "TCP sensor",
	}

	sensors.RegisterProbeType("tcp_sensor", tcp)
	sensors.RegisterTracingSensorsAtInit(tcp.name, tcp)
	observer.RegisterEventHandlerAtInit(api.MSG_OP_IPV4_TCPSTATS, handleTcpStats)
}
