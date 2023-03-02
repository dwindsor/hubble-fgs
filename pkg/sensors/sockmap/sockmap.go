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
	"fmt"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/sensors/http"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/cgroup"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/sk"
	"github.com/isovalent/hubble-fgs/pkg/sensors/sockops"
	"github.com/isovalent/hubble-fgs/pkg/sensors/tcp"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

var (
	// Socket mode
	// Supports 5.4 kernels or newer.

	Skmsg = program.Builder(
		"bpf_tls_skmsg.o",
		"sk_msg",
		"sk_msg/fgs_tls",
		"bpf_tls_sk_msg_fgs",
		"skmsg")

	SkSkbVerdict = program.Builder(
		"bpf_tls_skskb_verdict.o",
		"sk_skb",
		"sk_skb/stream_verdict/fgs_tls",
		"bpf_tls_skskb_verdict_fgs",
		"sk_skb_verdict")

	SkSkbParser = program.Builder(
		"bpf_tls_skskb_parser.o",
		"sk_skb",
		"sk_skb/stream_parser/fgs_tls",
		"bpf_tls_skskb_parser_fgs",
		"sk_skb_parser")

	SockoptSet = program.Builder(
		"bpf_setsockopt.o",
		"cgroup",
		"cgroup/setsockopt",
		"cgroup_setsockopt",
		"cgrp_socketopt",
	)

	// Cgroup mode
	// Supports 5.4 kernels or newer.

	CGIngress = program.Builder(
		"bpf_tls_inet_send.o",
		"tls_inet_send",
		"cgroup_skb/ingress",
		"cgroup_skb_ingress",
		"tls_cgrp_ingress")

	CGEgress = program.Builder(
		"bpf_tls_inet_send.o",
		"tls_inet_recv",
		"cgroup_skb/egress",
		"cgroup_skb_egress",
		"tls_cgrp_egress")

	// TLS maps
	Map         = tcp.TLSContext
	MapStats    = tcp.TLSMapStats
	Bottle      = tcp.TLSBottles
	BottleStats = tcp.TLSBottleStats
	TailCalls   = program.MapBuilder("tls_calls", Skmsg)
	// CGroup TLS maps
	CGParserStats = program.MapBuilder("tls_parser_stats", CGEgress)
	CGTailCalls   = program.MapBuilder("tls_calls", CGIngress)
	// Sockops Filter
	FilterMap   = sockops.TlsFilterMap
	ParserStats = program.MapBuilder("tls_parser_stats", sockops.SockopsEstablished)
	// Socket links
	SocketMap   = tcp.SocketMap
	SocketStats = tcp.SocketStats

	// HTTP maps
	HTTPMap       = http.HTTPContext
	HTTPTailCalls = http.TailCalls
	HTTPFilterMap = http.HTTPFilterMap
)

func AddTLSSensor(parser v1alpha1.ParserPolicySpec) (*sensors.Sensor, error) {
	enableTLS := false
	enableTLSCG := false

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
		enableTLSCG = true
	case "cgroup":
		enableTLSCG = true
	default:
		return nil, nil
	}

	tlsFilters = ParseTLSSpec(&parser.Tls, parserHttps)
	if len(tlsFilters) > sockops.TLS_MAX_PORTS {
		return nil, fmt.Errorf("TLS parser only supports up to %d MatchPorts selectors, got %d", sockops.TLS_MAX_PORTS, len(tlsFilters))
	}

	if !kernels.MinKernelVersion("5.4") {
		return nil, fmt.Errorf("TLS parser requires kernel version >= 5.4")
	}

	return enableTLSParser(enableTLS, enableTLSCG), nil
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

func (skmsg *skmsgTLSSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	err := cgroup.LoadSockOpt(args.BPFDir, args.MapDir, args.CiliumDir, SockoptSet, args.Verbose)
	if err != nil {
		return err
	}

	err = sk.LoadSkProgram(args.BPFDir, args.MapDir, args.Load, sockops.TlsSockMap, args.Verbose)
	if err != nil {
		return err
	}
	if utils.SkSkbParserRequired() {
		err = sk.LoadSkProgram(args.BPFDir, args.MapDir, SkSkbParser, sockops.TlsSockMap, args.Verbose)
		if err != nil {
			return err
		}
	}
	err = sk.LoadSkProgram(args.BPFDir, args.MapDir, SkSkbVerdict, sockops.TlsSockMap, args.Verbose)
	if err != nil {
		return err
	}

	if err := sockops.SetFilter(args.MapDir, "tls_filter_map", tlsFilters); err != nil {
		return err
	}
	return nil
}

func (skmsg *skmsgTLSSensor) SpecHandler(raw interface{}) (*sensors.Sensor, error) {
	return nil, nil
}

type skSkbVerdictTLSSensor struct {
	name string
}

func (skSkbVerdict *skSkbVerdictTLSSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return nil
}

func (skSkbVerdict *skSkbVerdictTLSSensor) SpecHandler(raw interface{}) (*sensors.Sensor, error) {
	return nil, nil
}

type skSkbParserTLSSensor struct {
	name string
}

func (skSkbParser *skSkbParserTLSSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return nil
}

func (skSkbParser *skSkbParserTLSSensor) SpecHandler(raw interface{}) (*sensors.Sensor, error) {
	return nil, nil
}

type socketOptSensor struct {
	name string
}

func (s *socketOptSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return nil
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

	sensors.RegisterProbeType("tls_cgrp_ingress", tls)
	sensors.RegisterProbeType("tls_cgrp_egress", tls)
	sensors.RegisterProbeType("cgrp_socketopt", socketopt)

	sensors.RegisterSpecHandlerAtInit(tls.name, tls)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_TLS, HandleTLS)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_TLS_CONT, HandleTLSCont)
}

func enableTLSParser(tls, cg bool) *sensors.Sensor {
	var progs []*program.Program
	var maps []*program.Map

	if tls {
		// Socket mode only work on 5.10 onwards
		if kernels.MinKernelVersion("5.10.0") {
			logger.GetLogger().Infof("Enable TLS")
			progs = append(progs,
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
				sockops.TlsSockMap,
				sockops.HttpSockMap,
				sockops.NopSockMap,
				HTTPMap,
				HTTPTailCalls,
				HTTPFilterMap,
			)
		} else {
			logger.GetLogger().Warnf("Cannot Enable TLS Socket mode on kernel <5.10")
		}
	}

	if cg {
		// CGroups only work on 5.4 onwards
		if kernels.MinKernelVersion("5.4.0") {
			logger.GetLogger().Infof("Enable TLS CGroup")
			progs = append(progs,
				CGEgress,
				CGIngress,
			)

			maps = append(maps,
				Map, MapStats,
				Bottle, BottleStats,
				CGParserStats,
				CGTailCalls,
				FilterMap, ParserStats,
				SocketMap, SocketStats,
			)
		} else {
			logger.GetLogger().Warnf("Cannot Enable TLS CGroup on kernel <5.4")
		}
	}

	return sensors.SensorBuilder("__parser_sensors__", progs, maps)
}

func (tls *tlsSensor) SpecHandler(raw interface{}) (*sensors.Sensor, error) {
	spec := raw.(*v1alpha1.TracingPolicySpec)
	return AddParserSensors(spec.Parser)
}

func (tls *tlsSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	if args.Load.Type == "tls_cgrp_ingress" || args.Load.Type == "tls_cgrp_egress" {
		err := cgroup.LoadCgroupProgram(args.BPFDir, args.MapDir, args.CiliumDir, args.Load, args.Verbose)
		if err != nil {
			return err
		}
	}
	if err := sockops.SetFilter(args.MapDir, "tls_filter_map", tlsFilters); err != nil {
		return err
	}

	return nil
}
