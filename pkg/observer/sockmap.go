package observer

import (
	"path/filepath"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/logger"
)

var (
	ObserverSockopsEstablished = BpfLoadBuilder(
		"bpf_sockops.o",
		"sockops",
		"sockops",
		"sockops/fgs_sockops",
		"sockops_fgs_sockops",
		false,
		true,
		"sockops")

	ObserverSkmsg = BpfLoadBuilder(
		"bpf_skmsg.o",
		"sk_msg",
		"sk_msg",
		"sk_msg/fgs",
		"sk_msg_fgs",
		false,
		true,
		"skmsg")

	ObserverSkSkbVerdict = BpfLoadBuilder(
		"bpf_skskb_verdict.o",
		"sk_skb",
		"sk_skb",
		"sk_skb_verdict/fgs",
		"sk_skb_verdict_fgs",
		false,
		true,
		"sk_skb_verdict")

	ObserverSkSkbParser = BpfLoadBuilder(
		"bpf_skskb_parser.o",
		"sk_skb",
		"sk_skb",
		"sk_skb_parser/fgs",
		"sk_skb_parser_fgs",
		false,
		true,
		"sk_skb_parser")

	ObserverTLSTCIngress = BpfLoadBuilder(
		"bpf_tc_ingress.o",
		"ingress_tcp",
		"ingress_tcp",
		"classifier/ingress_tcp",
		"classifier_ingress_tcp",
		false,
		true,
		"tc_ingress")

	ObserverTLSTCEgress = BpfLoadBuilder(
		"bpf_tc_egress.o",
		"egress_tcp",
		"egress_tcp",
		"tc/egress_tcp",
		"tc_egress_tcp",
		false,
		true,
		"tc_egress")

	/* TLS maps */
	tlsSockMapName       = "tls_sock_map"
	ObserverTCTLSMap     = BpfMapBuilder("tls_map", "tc_ingress", ObserverTLSTCEgress)
	ObserverSockMap      = BpfMapBuilder(tlsSockMapName, "sockops", ObserverSockopsEstablished)
	ObserverTLSMap       = BpfMapBuilder("tls_map", "skmsg", ObserverSkmsg)
	ObserverTLSTailCalls = BpfMapBuilder("tls_calls", "tc_ingress", ObserverTLSTCIngress)
)

type observerTlsSensor struct {
	name string
}

type observerSockopsSensor struct {
	name string
}

func (sockops *observerSockopsSensor) LoadProbe(
	bpfDir, mapDir, ciliumDir string,
	load *BpfLoad,
	version, verbose int, x64 bool) (error, int) {
	return ObserverLoadSockops(bpfDir, mapDir, ciliumDir, load, version, 0, x64, tlsSelectors, httpSelectors)
}

func (tls *observerSockopsSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*ObserverSensor, error) {
	return getSensorFromParserPolicy(spec)
}

type observerSkmsgTlsSensor struct {
	name string
}

func (skmsg *observerSkmsgTlsSensor) LoadProbe(
	bpfDir, mapDir, ciliumDir string,
	load *BpfLoad,
	version, verbose int, x64 bool) (error, int) {
	path := filepath.Join(mapDir, tlsSockMapName)
	err, i := ObserverLoadSkmsg(bpfDir, mapDir, ciliumDir, load, version, 0, x64, path)
	if err != nil {
		return err, i
	}
	if skSkbParserRequired() {
		err, i = ObserverLoadSkSkb(bpfDir, mapDir, ciliumDir, ObserverSkSkbParser, version, 0, x64, path)
		if err != nil {
			return err, i
		}
	}
	return ObserverLoadSkSkbVerdict(bpfDir, mapDir, ciliumDir, ObserverSkSkbVerdict, version, 0, x64, path)
}

func (skmsg *observerSkmsgTlsSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*ObserverSensor, error) {
	return nil, nil
}

type observerSkSkbVerdictTlsSensor struct {
	name string
}

func (skSkbVerdict *observerSkSkbVerdictTlsSensor) LoadProbe(
	bpfDir, mapDir, ciliumDir string,
	load *BpfLoad,
	version, verbose int, x64 bool) (error, int) {
	return ObserverLoadSkSkb(bpfDir, mapDir, ciliumDir, load, version, verbose, x64, filepath.Join(mapDir, tlsSockMapName))
}

func (skmsg *observerSkSkbVerdictTlsSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*ObserverSensor, error) {
	return nil, nil
}

type observerSkSkbParserTlsSensor struct {
	name string
}

func (skSkbParser *observerSkSkbParserTlsSensor) LoadProbe(
	bpfDir, mapDir, ciliumDir string,
	load *BpfLoad,
	version, verbose int, x64 bool) (error, int) {
	return ObserverLoadSkSkb(bpfDir, mapDir, ciliumDir, load, version, verbose, x64, filepath.Join(mapDir, tlsSockMapName))
}

func (skmsg *observerSkSkbParserTlsSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*ObserverSensor, error) {
	return nil, nil
}

func init() {
	skskbVerdict := &observerSkSkbVerdictTlsSensor{
		name: "skskb verdict tls sensor",
	}
	RegisterProbeType("sk_skb_verdict", skskbVerdict)

	if skSkbParserRequired() {
		skskbParser := &observerSkSkbParserTlsSensor{
			name: "skskb parser tls sensor",
		}
		RegisterProbeType("sk_skb_parser", skskbParser)
	}

	skmsg := &observerSkmsgTlsSensor{
		name: "skmsg tls sensor",
	}
	RegisterProbeType("skmsg", skmsg)

	sockops := &observerSockopsSensor{
		name: "sockops loader",
	}
	RegisterProbeType("sockops", sockops)

	tls := &observerTlsSensor{
		name: "tls sensor",
	}
	RegisterProbeType("tc_ingress", tls)
	RegisterProbeType("tc_egress", tls)
	RegisterTracingSensorsAtInit(tls.name, tls)
	RegisterEventHandlerAtInit(api.MSG_OP_TLS, HandleTls)
	RegisterEventHandlerAtInit(api.MSG_OP_TLS_CONT, HandleTlsCont)
}

func EnableTlsParser(tls, tc bool) *ObserverSensor {
	var progs []*BpfLoad
	var maps []*ObserverMap

	if tls {
		logger.GetLogger().Infof("Enable TLS")
		progs = append(progs,
			ObserverSockopsEstablished,
			ObserverSkmsg,
			ObserverSkSkbVerdict,
		)
		if skSkbParserRequired() {
			progs = append(progs, ObserverSkSkbParser)
		}

		maps = append(maps,
			ObserverSockMap,
			ObserverTLSMap,
		)
	}

	if tc {
		logger.GetLogger().Infof("Enable TLS TC")
		progs = append(progs,
			ObserverTLSTCEgress,
			ObserverTLSTCIngress,
		)

		maps = append(maps,
			ObserverTCTLSMap,
			ObserverTLSTailCalls,
		)
	}

	return SensorBuilder("__parser_sensors__", progs, maps)
}

func addParserSensors(parser v1alpha1.ParserPolicySpec) (*ObserverSensor, error) {
	tls, err := addTlsSensor(parser)
	if err != nil {
		return nil, err
	}
	http, err := AddHttpSensor(parser)
	if err != nil {
		return nil, err
	}
	return SensorCombine("__parser_sensors__", http, tls), nil
}

func addTlsSensor(parser v1alpha1.ParserPolicySpec) (*ObserverSensor, error) {
	var err error

	enableTls := false
	enableTlsTc := false

	if !parser.Tls.Enable {
		return nil, nil
	}

	switch parser.Tls.Mode {
	case "socket":
		enableTls = true
	case "tc":
		enableTlsTc = true
	default:
		return nil, nil
	}

	tlsSelectors, err = ParseTlsSpec(&parser.Tls)
	if err != nil {
		return nil, err
	}
	return EnableTlsParser(enableTls, enableTlsTc), nil
}

func getSensorFromParserPolicy(spec *v1alpha1.TracingPolicySpec) (*ObserverSensor, error) {
	return addParserSensors(spec.Parser)
}

func (tls *observerTlsSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*ObserverSensor, error) {
	return nil, nil
}

func (tls *observerTlsSensor) LoadProbe(
	bpfDir, mapDir, ciliumDir string,
	load *BpfLoad,
	version, verbose int, x64 bool) (error, int) {
	return ObserverLoadTC(bpfDir, mapDir, ciliumDir, load, version, Verbosity, tlsSelectors)
}

func skSkbParserRequired() bool {
	// The skskb parser is only needed on 5.10 and earlier kernels.
	// After 5.10 we can run with only the skskb verdict programs
	// improving performance.
	return !kernels.MinKernelVersion("5.10.0")
}
