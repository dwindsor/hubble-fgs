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
	"github.com/isovalent/hubble-fgs/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/sensors/http"
	"github.com/isovalent/hubble-fgs/pkg/sensors/sockops"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

var (
	// Socket mode
	// Supports 5.4 kernels or newer.

	TLSSkmsg = sensors.ProgramBuilder(
		"bpf_skmsg.o",
		"sk_msg",
		"sk_msg",
		"sk_msg/fgs",
		"sk_msg_fgs",
		false,
		true,
		"skmsg")

	TLSSkSkbVerdict = sensors.ProgramBuilder(
		"bpf_skskb_verdict.o",
		"sk_skb",
		"sk_skb",
		"sk_skb_verdict/fgs",
		"sk_skb_verdict_fgs",
		false,
		true,
		"sk_skb_verdict")

	TLSSkSkbParser = sensors.ProgramBuilder(
		"bpf_skskb_parser.o",
		"sk_skb",
		"sk_skb",
		"sk_skb_parser/fgs",
		"sk_skb_parser_fgs",
		false,
		true,
		"sk_skb_parser")

	// TC mode
	// 4.19 kernels and below.
	// Susceptible to out-of-order packets.

	TLSTCIngress = sensors.ProgramBuilder(
		"bpf_tc_ingress.o",
		"ingress_tcp",
		"ingress_tcp",
		"classifier/ingress_tcp",
		"classifier_ingress_tcp",
		false,
		true,
		"tc_ingress")

	TLSTCEgress = sensors.ProgramBuilder(
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
	TCTLSMap       = sensors.MapBuilder("tls_map", "tc_ingress", TLSTCEgress)
	SockMap        = sensors.MapBuilder(tlsSockMapName, "sockops", sockops.SockopsEstablished)
	TLSMap         = sensors.MapBuilder("tls_map", "skmsg", TLSSkmsg)
	TLSTailCalls   = sensors.MapBuilder("tls_calls", "tc_ingress", TLSTCIngress)
)

func AddTLSSensor(parser v1alpha1.ParserPolicySpec) (*sensors.Sensor, error) {
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

// TODO: Pull this out to into the sockops package. Implement the SpecHandler
// to load this sockops sensor if TLS || HTTP.

type sockopsSensor struct {
	name string
}

func (*sockopsSensor) LoadProbe(args sensors.LoadProbeArgs) (error, int) {
	return sensors.LoadSockops(args.BPFDir, args.MapDir, args.CiliumDir, args.Load, args.Version, args.Verbose, args.X64, tlsSelectors, http.Selectors)
}

func AddSockopsSensors(parser v1alpha1.ParserPolicySpec) (*sensors.Sensor, error) {
	if (parser.Tls.Enable && parser.Tls.Mode == "socket") || parser.Http.Enable {
		var progs []*sensors.Program
		var maps []*sensors.Map

		logger.GetLogger().Infof("Enable Sockops")
		progs = append(progs, sockops.SockopsEstablished)
		maps = append(maps, SockMap)

		return sensors.SensorBuilder("__sockops_sensors__", progs, maps), nil
	}
	return nil, nil
}
func (*sockopsSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
	return AddSockopsSensors(spec.Parser)
}

// AddParserSensors will add and combine the sensors that are enabled inside
// the parser policy spec.
func AddParserSensors(parser v1alpha1.ParserPolicySpec) (*sensors.Sensor, error) {
	return AddTLSSensor(parser)
}

type skmsgTLSSensor struct {
	name string
}

func (skmsg *skmsgTLSSensor) LoadProbe(args sensors.LoadProbeArgs) (error, int) {
	path := filepath.Join(args.MapDir, tlsSockMapName)
	err, i := sensors.LoadSkmsg(args.BPFDir, args.MapDir, args.CiliumDir, args.Load, args.Version, args.Verbose, args.X64, path)
	if err != nil {
		return err, i
	}
	if utils.SkSkbParserRequired() {
		err, i = sensors.LoadSkSkb(args.BPFDir, args.MapDir, args.CiliumDir, TLSSkSkbParser, args.Version, args.Verbose, args.X64, path)
		if err != nil {
			return err, i
		}
	}
	return sensors.LoadSkSkbVerdict(args.BPFDir, args.MapDir, args.CiliumDir, TLSSkSkbVerdict, args.Version, args.Verbose, args.X64, path)
}

func (skmsg *skmsgTLSSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
	return nil, nil
}

type skSkbVerdictTLSSensor struct {
	name string
}

func (skSkbVerdict *skSkbVerdictTLSSensor) LoadProbe(args sensors.LoadProbeArgs) (error, int) {
	return sensors.LoadSkSkb(args.BPFDir, args.MapDir, args.CiliumDir, args.Load, args.Version, args.Verbose, args.X64, filepath.Join(args.MapDir, tlsSockMapName))
}

func (skmsg *skSkbVerdictTLSSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
	return nil, nil
}

type skSkbParserTLSSensor struct {
	name string
}

func (skSkbParser *skSkbParserTLSSensor) LoadProbe(args sensors.LoadProbeArgs) (error, int) {
	return sensors.LoadSkSkb(args.BPFDir, args.MapDir, args.CiliumDir, args.Load, args.Version, args.Verbose, args.X64, filepath.Join(args.MapDir, tlsSockMapName))
}

func (skmsg *skSkbParserTLSSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
	return nil, nil
}

func init() {
	skskbVerdict := &skSkbVerdictTLSSensor{
		name: "skskb verdict tls sensor",
	}
	sensors.RegisterProbeType("sk_skb_verdict", skskbVerdict)

	if utils.SkSkbParserRequired() {
		skskbParser := &skSkbParserTLSSensor{
			name: "skskb parser tls sensor",
		}
		sensors.RegisterProbeType("sk_skb_parser", skskbParser)
	}

	skmsg := &skmsgTLSSensor{
		name: "skmsg tls sensor",
	}
	sensors.RegisterProbeType("skmsg", skmsg)

	sockops := &sockopsSensor{
		name: "sockops loader",
	}
	sensors.RegisterProbeType("sockops", sockops)
	sensors.RegisterTracingSensorsAtInit(sockops.name, sockops)

	tls := &tlsSensor{
		name: "tls sensor",
	}
	sensors.RegisterProbeType("tc_ingress", tls)
	sensors.RegisterProbeType("tc_egress", tls)
	sensors.RegisterTracingSensorsAtInit(tls.name, tls)
	observer.RegisterEventHandlerAtInit(api.MSG_OP_TLS, HandleTLS)
	observer.RegisterEventHandlerAtInit(api.MSG_OP_TLS_CONT, HandleTLSCont)
}

func enableTLSParser(tls, tc bool) *sensors.Sensor {
	var progs []*sensors.Program
	var maps []*sensors.Map

	if tls {
		logger.GetLogger().Infof("Enable TLS")
		progs = append(progs,
			sockops.SockopsEstablished,
			TLSSkmsg,
			TLSSkSkbVerdict,
		)
		if utils.SkSkbParserRequired() {
			progs = append(progs, TLSSkSkbParser)
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

	return sensors.SensorBuilder("__parser_sensors__", progs, maps)
}

func (tls *tlsSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
	return AddParserSensors(spec.Parser)
}

func (tls *tlsSensor) LoadProbe(args sensors.LoadProbeArgs) (error, int) {
	return sensors.LoadTC(args.BPFDir, args.MapDir, args.CiliumDir, args.Load, args.Version, args.Verbose, tlsSelectors)
}
