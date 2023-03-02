//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package nop

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/sk"
	"github.com/isovalent/hubble-fgs/pkg/sensors/sockops"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"

	// Required for base sensors
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
)

const (
	testMapDir = "testObserver"
)

var (
	filters []uint32
)

var (
	Skmsg = program.Builder(
		"bpf_nop.o",
		"sk_msg",
		"sk_msg/fgsnop",
		"sk_msg_fgs_nop",
		"nop_skmsg")

	SkSkbParser = program.Builder(
		"bpf_nop_parser.o",
		"sk_skb",
		"sk_skb/stream_parser/fgsnop",
		"sk_skb_parser_nop",
		"nop_skskb_parser")

	SkSkbVerdict = program.Builder(
		"bpf_nop_verdict.o",
		"sk_skb",
		"sk_skb/stream_verdict/fgsnop",
		"sk_skb_verdict_nop",
		"nop_skskb_verdict")
)

type sensor struct {
	name string
}

func (nop *sensor) LoadProbe(args sensors.LoadProbeArgs) error {
	err := sk.LoadSkProgram(args.BPFDir, args.MapDir, args.Load, sockops.NopSockMap, args.Verbose)
	if err != nil {
		return err
	}

	if utils.SkSkbParserRequired() {
		err = sk.LoadSkProgram(args.BPFDir, args.MapDir, SkSkbParser, sockops.NopSockMap, args.Verbose)
		if err != nil {
			return err
		}
	}
	return sk.LoadSkProgram(args.BPFDir, args.MapDir, SkSkbVerdict, sockops.NopSockMap, args.Verbose)
}

func (nop *sensor) SpecHandler(raw interface{}) (*sensors.Sensor, error) {
	spec := raw.(*v1alpha1.TracingPolicySpec)
	return AddNopSensor(spec.Parser)
}

type skSkbVerdictSensor struct {
	name string
}

func (skSkbVerdict *skSkbVerdictSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return nil
}

func (skSkbVerdict *skSkbVerdictSensor) SpecHandler(spec interface{}) (*sensors.Sensor, error) {
	return nil, nil
}

type skSkbParserSensor struct {
	name string
}

func (skSkbParser *skSkbParserSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return nil
}

func (skSkbParser *skSkbParserSensor) SpecHandler(spec interface{}) (*sensors.Sensor, error) {
	return nil, nil
}

func init() {
	bpf.SetMapPrefix(testMapDir)
	AddNop()
}

func AddNop() {
	skmsg := &sensor{
		name: "skmsg nop sensor",
	}

	if utils.SkSkbParserRequired() {
		skskbParser := &skSkbParserSensor{
			name: "skskb parser nop sensor",
		}
		sensors.RegisterProbeType("nop_skskb_parser", skskbParser)
	}

	skskbVerdict := &skSkbVerdictSensor{
		name: "skskb verdict nop sensor",
	}

	sensors.RegisterProbeType("nop_skskb_verdict", skskbVerdict)
	sensors.RegisterProbeType("nop_skmsg", skmsg)
	sensors.RegisterSpecHandlerAtInit(skmsg.name, skmsg)
}

/* Add sensor from CRD */
func EnableNopParser() *sensors.Sensor {
	logger.GetLogger().Infof("Enable NOP")

	progs := []*program.Program{
		Skmsg,
		SkSkbVerdict,
	}

	if utils.SkSkbParserRequired() {
		progs = append(progs, SkSkbParser)
	}

	maps := []*program.Map{
		sockops.NopSockMap,
	}

	return sensors.SensorBuilder("__parser_sensors__", progs, maps)
}

// ParseNopSpec parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to run match logic.
func ParseNopSpec(spec *v1alpha1.NopSpec) []uint32 {
	var ports []uint32

	for _, selector := range spec.Selectors {
		ports = append(ports, selector.MatchPorts...)
	}

	return ports
}

func AddNopSensor(parser v1alpha1.ParserPolicySpec) (*sensors.Sensor, error) {
	if !parser.Nop.Enable {
		return nil, nil
	}

	filters = ParseNopSpec(&parser.Nop)
	if len(filters) > sockops.TLS_MAX_PORTS {
		return nil, fmt.Errorf("NOP parser only supports up to %d MatchPorts selectors, got %d", sockops.TLS_MAX_PORTS, len(filters))
	}

	return EnableNopParser(), nil
}
