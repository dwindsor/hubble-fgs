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
	"github.com/isovalent/hubble-fgs/pkg/sensors/sockops"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

var (
	// Socket mode
	// Supports 5.4 kernels or newer.

	TLSSkmsg = sensors.ProgramBuilder(
		"bpf_tls_skmsg.o",
		"sk_msg",
		"sk_msg",
		"sk_msg/fgs_tls",
		"bpf_tls_sk_msg_fgs",
		false,
		true,
		"skmsg")

	TLSSkSkbVerdict = sensors.ProgramBuilder(
		"bpf_tls_skskb_verdict.o",
		"sk_skb",
		"sk_skb",
		"sk_skb/stream_verdict/fgs_tls",
		"bpf_tls_skskb_verdict_fgs",
		false,
		true,
		"sk_skb_verdict")

	TLSSkSkbParser = sensors.ProgramBuilder(
		"bpf_tls_skskb_parser.o",
		"sk_skb",
		"sk_skb",
		"sk_skb/stream_parser/fgs_tls",
		"bpf_tls_skskb_parser_fgs",
		false,
		true,
		"sk_skb_parser")

	SockoptSet = sensors.ProgramBuilder(
		"bpf_setsockopt.o",
		"cgroup",
		"cgroup",
		"cgroup/setsockopt",
		"cgroup_setsockopt",

		false,
		true,
		"cgrp_socketopt",
	)

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
		"classifier/egress_tcp",
		"tc_egress_tcp",
		false,
		true,
		"tc_egress")

	/* TLS maps */
	TCTLSMap         = sensors.MapBuilder("tls_map", "tc_egress", TLSTCEgress)
	TCTLSParserStats = sensors.MapBuilder("tls_parser_stats", "tc_egress", TLSTCEgress)
	TLSParserStats   = sensors.MapBuilder("tls_parser_stats", "sockops", sockops.SockopsEstablished)
	TLSMap           = sensors.MapBuilder("tls_map", "skmsg", TLSSkmsg)
	TLSTailCalls     = sensors.MapBuilder("tls_calls", "tc_ingress", TLSTCIngress)
	TlsFilterMap     = sensors.MapBuilder("tls_filter_map", "sockops", sockops.SockopsEstablished)
	TLSSockMap       = sensors.MapBuilder("tls_sock_map", "sockops", sockops.SockopsEstablished)
)

func AddTLSSensor(parser v1alpha1.ParserPolicySpec) (*sensors.Sensor, error) {
	var err error

	enableTLS := false
	enableTLSTC := false

	if !parser.Tls.Enable {
		return nil, nil
	}

	parserHttps := &parser.Https
	if !parser.Https.Enable {
		parserHttps = nil
	}

	switch parser.Tls.Mode {
	case "socket":
		enableTLS = true
	case "tc":
		enableTLSTC = true
	default:
		return nil, nil
	}

	tlsSelectors, err = ParseTLSSpec(&parser.Tls, parserHttps)
	if err != nil {
		return nil, err
	}

	return enableTLSParser(enableTLS, enableTLSTC), nil
}

type tlsSensor struct {
	name string
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
	path := filepath.Join(args.MapDir, sockops.TlsSockMapName)

	err, i := sensors.LoadSockOpt(args.BPFDir, args.MapDir, args.CiliumDir, SockoptSet, args.Version, args.Verbose, args.X64, path)
	if err != nil {
		return err, i
	}

	err, i = sensors.LoadSkProgram(args.BPFDir, args.MapDir, args.Load, path)
	if err != nil {
		return err, i
	}
	if utils.SkSkbParserRequired() {
		err, i = sensors.LoadSkProgram(args.BPFDir, args.MapDir, TLSSkSkbParser, path)
		if err != nil {
			return err, i
		}
	}
	err, i = sensors.LoadSkProgram(args.BPFDir, args.MapDir, TLSSkSkbVerdict, path)
	if err != nil {
		return err, i
	}

	if err := sensors.SetFilter(args.MapDir, "tls_filter_map", tlsSelectors); err != nil {
		return err, i
	}
	return nil, i
}

func (skmsg *skmsgTLSSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
	return nil, nil
}

type skSkbVerdictTLSSensor struct {
	name string
}

func (skSkbVerdict *skSkbVerdictTLSSensor) LoadProbe(args sensors.LoadProbeArgs) (error, int) {
	return nil, 0
}

func (skmsg *skSkbVerdictTLSSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
	return nil, nil
}

type skSkbParserTLSSensor struct {
	name string
}

func (skSkbParser *skSkbParserTLSSensor) LoadProbe(args sensors.LoadProbeArgs) (error, int) {
	return nil, 0
}

func (skmsg *skSkbParserTLSSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
	return nil, nil
}

type socketOptSensor struct {
	name string
}

func (s *socketOptSensor) LoadProbe(args sensors.LoadProbeArgs) (error, int) {
	return nil, 0
}

func (s *socketOptSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
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

	tls := &tlsSensor{
		name: "tls sensor",
	}

	socketopt := &socketOptSensor{
		name: "socket option sensor",
	}

	sensors.RegisterProbeType("tc_ingress", tls)
	sensors.RegisterProbeType("tc_egress", tls)
	sensors.RegisterProbeType("cgrp_socketopt", socketopt)

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
			SockoptSet,
		)
		if utils.SkSkbParserRequired() {
			progs = append(progs, TLSSkSkbParser)
		}

		maps = append(maps,
			TLSSockMap,
			TLSMap,
			TLSParserStats,
			TlsFilterMap,
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
			TCTLSParserStats,
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
