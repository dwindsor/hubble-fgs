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
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

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
		"tg_skmsg_nop",
		"nop_skmsg")

	SkSkbParser = program.Builder(
		"bpf_nop_parser.o",
		"sk_skb",
		"sk_skb/stream_parser/fgsnop",
		"tg_skskb_pnop",
		"nop_skskb_parser")

	SkSkbVerdict = program.Builder(
		"bpf_nop_verdict.o",
		"sk_skb",
		"sk_skb/stream_verdict/fgsnop",
		"tg_skskb_vnop",
		"nop_skskb_verdict")
)

type sensor struct {
	name string
}

func (nop *sensor) LoadProbe(args sensors.LoadProbeArgs) error {
	err := sk.LoadSkProgram(args.BPFDir, args.Load, sockops.NopSockMap, args.Verbose)
	if err != nil {
		return err
	}

	if utils.SkSkbParserRequired() {
		err = sk.LoadSkProgram(args.BPFDir, SkSkbParser, sockops.NopSockMap, args.Verbose)
		if err != nil {
			return err
		}
	}
	return sk.LoadSkProgram(args.BPFDir, SkSkbVerdict, sockops.NopSockMap, args.Verbose)
}

func (nop *sensor) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	fid policyfilter.PolicyID,
) (sensors.SensorIface, error) {
	spec := policy.TpSpec()
	nopParser := &spec.Parser.Nop
	if !nopParser.Enable {
		return nil, nil
	}

	if fid != policyfilter.NoFilterID {
		return nil, fmt.Errorf("nop parser sensor does not implement policy filtering")
	}

	filters = ParseNopSpec(nopParser)
	if len(filters) > sockops.TLS_MAX_PORTS {
		return nil, fmt.Errorf("NOP parser only supports up to %d MatchPorts selectors, got %d", sockops.TLS_MAX_PORTS, len(filters))
	}

	return EnableNopParser(), nil
}

type skSkbVerdictSensor struct {
	name string
}

func (skSkbVerdict *skSkbVerdictSensor) LoadProbe(_ sensors.LoadProbeArgs) error {
	return nil
}

type skSkbParserSensor struct {
	name string
}

func (skSkbParser *skSkbParserSensor) LoadProbe(_ sensors.LoadProbeArgs) error {
	return nil
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
	sensors.RegisterPolicyHandlerAtInit(skmsg.name, skmsg)
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
