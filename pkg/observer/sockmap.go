package observer

import (
	"fmt"
	"os"

	"github.com/isovalent/hubble-fgs/pkg/config"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/logger"
)

var (
	ObserverSockopsEstablished = bpfLoad{
		"bpf_sockops.o",
		"sockops",
		"sockops",
		"sockops/fgs_sockops",
		"sockops_fgs_sockops",

		false,
		true,
		"sockops",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverSkmsg = bpfLoad{
		"bpf_skmsg.o",
		"sk_msg",
		"sk_msg",
		"sk_msg/fgs",
		"sk_msg_fgs",

		false,
		true,
		"skmsg",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverSkSkbVerdict = bpfLoad{
		"bpf_skskb_verdict.o",
		"sk_skb",
		"sk_skb",
		"sk_skb_verdict/fgs",
		"sk_skb_verdict_fgs",

		false,
		true,
		"sk_skb_verdict",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverSkSkbParser = bpfLoad{
		"bpf_skskb_parser.o",
		"sk_skb",
		"sk_skb",
		"sk_skb_parser/fgs",
		"sk_skb_parser_fgs",

		false,
		true,
		"sk_skb_parser",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}
	/* TLS maps */
	ObserverTCTLSMap     = ObserverMap{"tls_map", "tc_ingress", &ObserverTLSTCEgress, bpfLoadStateIdle(), -1}
	ObserverSockMap      = ObserverMap{"fgs_sock_map", "sockops", &ObserverSockopsEstablished, bpfLoadStateIdle(), -1}
	ObserverTLSMap       = ObserverMap{"tls_map", "skmsg", &ObserverSkmsg, bpfLoadStateIdle(), -1}
	ObserverTLSTailCalls = ObserverMap{"tls_calls", "tc_ingress", &ObserverTLSTCIngress, bpfLoadStateIdle(), -1}
)

type observerTlsSensor struct {
	name string
}

func init() {
	tls := &observerTlsSensor{
		name: "tls sensor",
	}
	registerTracingSensorsAtIinit(tls.name, tls)
}

func EnableTlsParser(tls, tc bool) *observerSensor {
	var progs []*bpfLoad
	var maps []*ObserverMap

	if tls {
		logger.GetLogger().Infof("Enable TLS")
		progs = append(progs,
			&ObserverSockopsEstablished,
			&ObserverSkmsg,
			&ObserverSkSkbVerdict,
			&ObserverSkSkbParser,
		)

		maps = append(maps,
			&ObserverSockMap,
			&ObserverTLSMap,
		)
	}

	if tc {
		logger.GetLogger().Infof("Enable TLS TC")
		progs = append(progs,
			&ObserverTLSTCEgress,
			&ObserverTLSTCIngress,
		)

		maps = append(maps,
			&ObserverTCTLSMap,
			&ObserverTLSTailCalls,
		)
	}

	return &observerSensor{
		name:  "__parser_sensors__",
		progs: progs,
		maps:  maps,
	}
}

func addParserSensors(parser v1alpha1.ParserPolicySpec) (*observerSensor, error) {
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

	return EnableTlsParser(enableTls, enableTlsTc), nil
}

func getSensorFromParserPolicy(spec *v1alpha1.TracingPolicySpec) (*observerSensor, error) {
	return addParserSensors(spec.Parser)
}

func (tls *observerTlsSensor) specHandler(spec *v1alpha1.TracingPolicySpec) (*observerSensor, error) {
	return getSensorFromParserPolicy(spec)
}

func getSensorFromParserPolicyString(yaml string) (*observerSensor, error) {
	cnf, err := config.ReadConfigYaml(yaml)
	if err != nil {
		return nil, err
	}
	return addParserSensors(cnf.Spec.Parser)
}

func getSensorFromParserPolicyFname(fname string) (*observerSensor, error) {
	yamlData, err := os.ReadFile(fname)
	if err != nil {
		return nil, fmt.Errorf("failed to read yaml file %s: %w", fname, err)
	}
	return getSensorFromParserPolicyString(string(yamlData))
}
