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
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/sensors/http"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/cgroup"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/sk"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/tc"
	"github.com/isovalent/hubble-fgs/pkg/sensors/sockops"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

var (
	// Socket mode
	// Supports 5.4 kernels or newer.

	Skmsg = program.ProgramBuilder(
		"bpf_tls_skmsg.o",
		"sk_msg",
		"sk_msg/fgs_tls",
		"bpf_tls_sk_msg_fgs",
		"skmsg")

	SkSkbVerdict = program.ProgramBuilder(
		"bpf_tls_skskb_verdict.o",
		"sk_skb",
		"sk_skb/stream_verdict/fgs_tls",
		"bpf_tls_skskb_verdict_fgs",
		"sk_skb_verdict")

	SkSkbParser = program.ProgramBuilder(
		"bpf_tls_skskb_parser.o",
		"sk_skb",
		"sk_skb/stream_parser/fgs_tls",
		"bpf_tls_skskb_parser_fgs",
		"sk_skb_parser")

	SockoptSet = program.ProgramBuilder(
		"bpf_setsockopt.o",
		"cgroup",
		"cgroup/setsockopt",
		"cgroup_setsockopt",
		"cgrp_socketopt",
	)

	// TC mode
	// 4.19 kernels and below.
	// Susceptible to out-of-order packets.

	TCIngress = program.ProgramBuilder(
		"bpf_tc_ingress.o",
		"ingress_tcp",
		"classifier/ingress_tcp",
		"classifier_ingress_tcp",
		"tc_ingress")

	TCEgress = program.ProgramBuilder(
		"bpf_tc_egress.o",
		"egress_tcp",
		"classifier/egress_tcp",
		"tc_egress_tcp",
		"tc_egress")

	// TLS maps
	Map         = program.MapBuilder("tls_map", Skmsg)
	MapStats    = program.MapBuilder("tls_map_stats", Skmsg)
	Bottle      = program.MapBuilder("bottles", Skmsg)
	BottleStats = program.MapBuilder("bottle_map_stats", Skmsg)
	TailCalls   = program.MapBuilder("tls_calls", Skmsg)
	// TC TLS maps
	TCMap         = program.MapBuilder("tls_map", TCEgress)
	TCMapStats    = program.MapBuilder("tls_map_stats", TCEgress)
	TCBottle      = program.MapBuilder("bottles", TCIngress)
	TCBottleStats = program.MapBuilder("bottle_map_stats", TCIngress)
	TCParserStats = program.MapBuilder("tls_parser_stats", TCEgress)
	TCTailCalls   = program.MapBuilder("tls_calls", TCIngress)
	// Sockops Filter
	FilterMap   = sockops.TlsFilterMap
	ParserStats = program.MapBuilder("tls_parser_stats", sockops.SockopsEstablished)
	// Socket links
	SocketMap   = program.MapBuilder("socket_map", Skmsg)
	SocketStats = program.MapBuilder("socket_map_stats", Skmsg)
	// TC Socket Links
	TCSocketMap   = program.MapBuilder("socket_map", TCIngress)
	TCSocketStats = program.MapBuilder("socket_map_stats", TCIngress)

	// HTTP maps
	HTTPMap       = http.HTTPContext
	HTTPTailCalls = http.TailCalls
	HTTPFilterMap = http.HTTPFilterMap
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

func (skmsg *skmsgTLSSensor) LoadProbe(args sensors.LoadProbeArgs) (int, error) {
	err := cgroup.LoadSockOpt(args.BPFDir, args.MapDir, args.CiliumDir, SockoptSet)
	if err != nil {
		return -1, err
	}

	err = sk.LoadSkProgram(args.BPFDir, args.MapDir, args.Load, sockops.TlsSockMap)
	if err != nil {
		return -1, err
	}
	if utils.SkSkbParserRequired() {
		err = sk.LoadSkProgram(args.BPFDir, args.MapDir, SkSkbParser, sockops.TlsSockMap)
		if err != nil {
			return -1, err
		}
	}
	err = sk.LoadSkProgram(args.BPFDir, args.MapDir, SkSkbVerdict, sockops.TlsSockMap)
	if err != nil {
		return -1, err
	}

	if err := sockops.SetFilter(args.MapDir, "tls_filter_map", tlsSelectors); err != nil {
		return -1, err
	}
	return -1, nil
}

func (skmsg *skmsgTLSSensor) SpecHandler(raw interface{}) (*sensors.Sensor, error) {
	return nil, nil
}

type skSkbVerdictTLSSensor struct {
	name string
}

func (skSkbVerdict *skSkbVerdictTLSSensor) LoadProbe(args sensors.LoadProbeArgs) (int, error) {
	return 0, nil
}

func (skSkbVerdict *skSkbVerdictTLSSensor) SpecHandler(raw interface{}) (*sensors.Sensor, error) {
	return nil, nil
}

type skSkbParserTLSSensor struct {
	name string
}

func (skSkbParser *skSkbParserTLSSensor) LoadProbe(args sensors.LoadProbeArgs) (int, error) {
	return 0, nil
}

func (skSkbParser *skSkbParserTLSSensor) SpecHandler(raw interface{}) (*sensors.Sensor, error) {
	return nil, nil
}

type socketOptSensor struct {
	name string
}

func (s *socketOptSensor) LoadProbe(args sensors.LoadProbeArgs) (int, error) {
	return 0, nil
}

func (s *socketOptSensor) SpecHandler(raw interface{}) (*sensors.Sensor, error) {
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
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_TLS, HandleTLS)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_TLS_CONT, HandleTLSCont)
}

func enableTLSParser(tls, tc bool) *sensors.Sensor {
	var progs []*program.Program
	var maps []*program.Map

	if tls {
		logger.GetLogger().Infof("Enable TLS")
		progs = append(progs,
			sockops.SockopsEstablished,
			Skmsg,
			SkSkbVerdict,
			SockoptSet,
		)
		if utils.SkSkbParserRequired() {
			progs = append(progs, SkSkbParser)
		}

		maps = append(maps,
			TailCalls,
			Map, MapStats,
			Bottle, BottleStats,
			FilterMap, ParserStats,
			SocketMap, SocketStats,
			HTTPMap,
			HTTPTailCalls,
			HTTPFilterMap,
		)
	}

	if tc {
		logger.GetLogger().Infof("Enable TLS TC")
		progs = append(progs,
			TCEgress,
			TCIngress,
		)

		maps = append(maps,
			TCMap, TCMapStats,
			TCBottle, TCBottleStats,
			TCParserStats,
			TCTailCalls,
			FilterMap, ParserStats,
			TCSocketMap, TCSocketStats,
		)
	}

	return sensors.SensorBuilder("__parser_sensors__", progs, maps)
}

func (tls *tlsSensor) SpecHandler(raw interface{}) (*sensors.Sensor, error) {
	spec := raw.(*v1alpha1.TracingPolicySpec)
	return AddParserSensors(spec.Parser)
}

func (tls *tlsSensor) LoadProbe(args sensors.LoadProbeArgs) (int, error) {
	err := tc.LoadTC(args.BPFDir, args.MapDir, args.CiliumDir, args.Load, args.Version, args.Verbose, tlsSelectors)
	return -1, err
}
