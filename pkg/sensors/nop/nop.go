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
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/sensors/sockops"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"

	// Required for base sensors
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
)

const (
	testMapDir = "testObserver"
)

var (
	Selectors [128]byte
)

var (
	Skmsg = program.ProgramBuilder(
		"bpf_nop.o",
		"sk_msg",
		"sk_msg/fgsnop",
		"sk_msg_fgs_nop",
		"nop_skmsg")

	SkSkbParser = program.ProgramBuilder(
		"bpf_nop_parser.o",
		"sk_skb",
		"sk_skb/stream_parser/fgsnop",
		"sk_skb_parser_nop",
		"nop_skskb_parser")

	SkSkbVerdict = program.ProgramBuilder(
		"bpf_nop_verdict.o",
		"sk_skb",
		"sk_skb/stream_verdict/fgsnop",
		"sk_skb_verdict_nop",
		"nop_skskb_verdict")
)

type sensor struct {
	name string
}

func (nop *sensor) LoadProbe(args sensors.LoadProbeArgs) (int, error) {
	err := sensors.LoadSkProgram(args.BPFDir, args.MapDir, args.Load, sockops.NopSockMap)
	if err != nil {
		return -1, err
	}

	if utils.SkSkbParserRequired() {
		err = sensors.LoadSkProgram(args.BPFDir, args.MapDir, SkSkbParser, sockops.NopSockMap)
		if err != nil {
			return -1, err
		}
	}
	return -1, sensors.LoadSkProgram(args.BPFDir, args.MapDir, SkSkbVerdict, sockops.NopSockMap)
}

func (nop *sensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
	return AddNopSensor(spec.Parser)
}

type skSkbVerdictSensor struct {
	name string
}

func (skSkbVerdict *skSkbVerdictSensor) LoadProbe(args sensors.LoadProbeArgs) (int, error) {
	return 0, nil
}

func (skSkbVerdict *skSkbVerdictSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
	return nil, nil
}

type skSkbParserSensor struct {
	name string
}

func (skSkbParser *skSkbParserSensor) LoadProbe(args sensors.LoadProbeArgs) (int, error) {
	return 0, nil
}

func (skSkbParser *skSkbParserSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
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
	sensors.RegisterTracingSensorsAtInit(skmsg.name, skmsg)
}

/* Add sensor from CRD */
func EnableNopParser() *sensors.Sensor {
	logger.GetLogger().Infof("Enable NOP")

	progs := []*sensors.Program{
		Skmsg,
		SkSkbVerdict,
	}

	if utils.SkSkbParserRequired() {
		progs = append(progs, SkSkbParser)
	}

	maps := []*sensors.Map{
		sockops.NopSockMap,
	}

	return sensors.SensorBuilder("__parser_sensors__", progs, maps)
}

func parseNopSelector(k *selectors.KernelSelectorState, s v1alpha1.NopSelector) error {
	return utils.ParseMatchPorts(k, s.MatchPorts, 0)
}

// ParseNopSpec parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to run match logic.
//
// Nop selector layout is the following.
//    #OfSelectors         uint32
//    OffsetOfEachSelector uint32
//    #OfMatchPorts        uint32
//    Port1 .... PortN     uint32, uint32, ...
func ParseNopSpec(spec *v1alpha1.NopSpec) ([128]byte, error) {
	var match [128]byte
	var e [4096]byte
	k := &selectors.KernelSelectorState{}

	if len(spec.Selectors) == 0 {
		selectors.WriteSelectorInt32(k, -1)
	} else {
		selectors.WriteSelectorUint32(k, uint32(len(spec.Selectors)))
		soff := make([]uint32, len(spec.Selectors))
		for i := range spec.Selectors {
			soff[i] = selectors.AdvanceSelectorLength(k)
		}

		for i, s := range spec.Selectors {
			selectors.WriteSelectorLength(k, soff[i])
			loff := selectors.AdvanceSelectorLength(k)
			if err := parseNopSelector(k, s); err != nil {
				return match, err
			}
			selectors.WriteSelectorLength(k, loff)
		}
	}

	e = selectors.GetSelectorBuffer(k)
	copy(match[:], e[:128])
	return match, nil
}

func AddNopSensor(parser v1alpha1.ParserPolicySpec) (*sensors.Sensor, error) {
	var err error

	if !parser.Nop.Enable {
		return nil, nil
	}

	Selectors, err = ParseNopSpec(&parser.Nop)
	if err != nil {
		return nil, err
	}
	return EnableNopParser(), nil
}
