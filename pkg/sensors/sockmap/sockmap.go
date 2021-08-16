//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package sockmap

import (
	"path/filepath"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/sensors/http"
	"github.com/isovalent/hubble-fgs/pkg/sensors/sockops"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

var (
	Skmsg = observer.BpfLoadBuilder(
		"bpf_skmsg.o",
		"sk_msg",
		"sk_msg",
		"sk_msg/fgs",
		"sk_msg_fgs",
		false,
		true,
		"skmsg")

	SkSkbVerdict = observer.BpfLoadBuilder(
		"bpf_skskb_verdict.o",
		"sk_skb",
		"sk_skb",
		"sk_skb_verdict/fgs",
		"sk_skb_verdict_fgs",
		false,
		true,
		"sk_skb_verdict")

	SkSkbParser = observer.BpfLoadBuilder(
		"bpf_skskb_parser.o",
		"sk_skb",
		"sk_skb",
		"sk_skb_parser/fgs",
		"sk_skb_parser_fgs",
		false,
		true,
		"sk_skb_parser")

	TLSTCIngress = observer.BpfLoadBuilder(
		"bpf_tc_ingress.o",
		"ingress_tcp",
		"ingress_tcp",
		"classifier/ingress_tcp",
		"classifier_ingress_tcp",
		false,
		true,
		"tc_ingress")

	TLSTCEgress = observer.BpfLoadBuilder(
		"bpf_tc_egress.o",
		"egress_tcp",
		"egress_tcp",
		"tc/egress_tcp",
		"tc_egress_tcp",
		false,
		true,
		"tc_egress")

	/* TLS maps */
	tlsSockMapName = "tls_sock_map"
	TCTLSMap       = observer.BpfMapBuilder("tls_map", "tc_ingress", TLSTCEgress)
	SockMap        = observer.BpfMapBuilder(tlsSockMapName, "sockops", sockops.ObserverSockopsEstablished)
	TLSMap         = observer.BpfMapBuilder("tls_map", "skmsg", Skmsg)
	TLSTailCalls   = observer.BpfMapBuilder("tls_calls", "tc_ingress", TLSTCIngress)
)

func AddTLSSensor(parser v1alpha1.ParserPolicySpec) (*observer.ObserverSensor, error) {
	var err error

	enableTLS := false
	enableTLSTC := false

	if !parser.Tls.Enable {
		return nil, nil
	}

	switch parser.Tls.Mode {
	case "socket":
		enableTLS = true
	case "tc":
		enableTLSTC = true
	default:
		return nil, nil
	}

	tlsSelectors, err = ParseTLSSpec(&parser.Tls)
	if err != nil {
		return nil, err
	}
	return enableTLSParser(enableTLS, enableTLSTC), nil
}

type tlsSensor struct {
	name string
}

type sockopsSensor struct {
	name string
}

func (*sockopsSensor) LoadProbe(
	bpfDir, mapDir, ciliumDir string,
	load *observer.BpfLoad,
	version, verbose int, x64 bool) (error, int) {
	return observer.ObserverLoadSockops(bpfDir, mapDir, ciliumDir, load, version, 0, x64, tlsSelectors, http.Selectors)
}

func (*sockopsSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*observer.ObserverSensor, error) {
	return AddParserSensors(spec.Parser)
}

// AddParserSensors will add and combine the sensors that are enabled inside
// the parser policy spec.
func AddParserSensors(parser v1alpha1.ParserPolicySpec) (*observer.ObserverSensor, error) {
	tls, err := AddTLSSensor(parser)
	if err != nil {
		return nil, err
	}
	http, err := http.AddHTTPSensor(parser)
	if err != nil {
		return nil, err
	}
	return observer.SensorCombine("__parser_sensors__", http, tls), nil
}

type skmsgTLSSensor struct {
	name string
}

func (skmsg *skmsgTLSSensor) LoadProbe(
	bpfDir, mapDir, ciliumDir string,
	load *observer.BpfLoad,
	version, verbose int, x64 bool) (error, int) {
	path := filepath.Join(mapDir, tlsSockMapName)
	err, i := observer.ObserverLoadSkmsg(bpfDir, mapDir, ciliumDir, load, version, 0, x64, path)
	if err != nil {
		return err, i
	}
	if utils.SkSkbParserRequired() {
		err, i = observer.ObserverLoadSkSkb(bpfDir, mapDir, ciliumDir, SkSkbParser, version, 0, x64, path)
		if err != nil {
			return err, i
		}
	}
	return observer.ObserverLoadSkSkbVerdict(bpfDir, mapDir, ciliumDir, SkSkbVerdict, version, 0, x64, path)
}

func (skmsg *skmsgTLSSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*observer.ObserverSensor, error) {
	return nil, nil
}

type skSkbVerdictTLSSensor struct {
	name string
}

func (skSkbVerdict *skSkbVerdictTLSSensor) LoadProbe(
	bpfDir, mapDir, ciliumDir string,
	load *observer.BpfLoad,
	version, verbose int, x64 bool) (error, int) {
	return observer.ObserverLoadSkSkb(bpfDir, mapDir, ciliumDir, load, version, verbose, x64, filepath.Join(mapDir, tlsSockMapName))
}

func (skmsg *skSkbVerdictTLSSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*observer.ObserverSensor, error) {
	return nil, nil
}

type skSkbParserTLSSensor struct {
	name string
}

func (skSkbParser *skSkbParserTLSSensor) LoadProbe(
	bpfDir, mapDir, ciliumDir string,
	load *observer.BpfLoad,
	version, verbose int, x64 bool) (error, int) {
	return observer.ObserverLoadSkSkb(bpfDir, mapDir, ciliumDir, load, version, verbose, x64, filepath.Join(mapDir, tlsSockMapName))
}

func (skmsg *skSkbParserTLSSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*observer.ObserverSensor, error) {
	return nil, nil
}

func init() {
	skskbVerdict := &skSkbVerdictTLSSensor{
		name: "skskb verdict tls sensor",
	}
	observer.RegisterProbeType("sk_skb_verdict", skskbVerdict)

	if utils.SkSkbParserRequired() {
		skskbParser := &skSkbParserTLSSensor{
			name: "skskb parser tls sensor",
		}
		observer.RegisterProbeType("sk_skb_parser", skskbParser)
	}

	skmsg := &skmsgTLSSensor{
		name: "skmsg tls sensor",
	}
	observer.RegisterProbeType("skmsg", skmsg)

	sockops := &sockopsSensor{
		name: "sockops loader",
	}
	observer.RegisterProbeType("sockops", sockops)

	tls := &tlsSensor{
		name: "tls sensor",
	}
	observer.RegisterProbeType("tc_ingress", tls)
	observer.RegisterProbeType("tc_egress", tls)
	observer.RegisterTracingSensorsAtInit(tls.name, tls)
	observer.RegisterEventHandlerAtInit(api.MSG_OP_TLS, HandleTls)
	observer.RegisterEventHandlerAtInit(api.MSG_OP_TLS_CONT, HandleTlsCont)
}

func enableTLSParser(tls, tc bool) *observer.ObserverSensor {
	var progs []*observer.BpfLoad
	var maps []*observer.ObserverMap

	if tls {
		logger.GetLogger().Infof("Enable TLS")
		progs = append(progs,
			sockops.ObserverSockopsEstablished,
			Skmsg,
			SkSkbVerdict,
		)
		if utils.SkSkbParserRequired() {
			progs = append(progs, SkSkbParser)
		}

		maps = append(maps,
			SockMap,
			TLSMap,
		)
	}

	if tc {
		logger.GetLogger().Infof("Enable TLS TC")
		progs = append(progs,
			TLSTCEgress,
			TLSTCIngress,
		)

		maps = append(maps,
			TCTLSMap,
			TLSTailCalls,
		)
	}

	return observer.SensorBuilder("__parser_sensors__", progs, maps)
}

func (tls *tlsSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*observer.ObserverSensor, error) {
	return nil, nil
}

func (tls *tlsSensor) LoadProbe(
	bpfDir, mapDir, ciliumDir string,
	load *observer.BpfLoad,
	version, verbose int, x64 bool) (error, int) {
	return observer.ObserverLoadTC(bpfDir, mapDir, ciliumDir, load, version, observer.Verbosity, tlsSelectors)
}
