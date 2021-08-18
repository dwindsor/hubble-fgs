//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package observer

import (
	"bytes"
	"encoding/binary"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/selectors"
)

var (
	httpSelectors [128]byte
)

var (
	ObserverHttpSkmsg = BpfLoadBuilder(
		"bpf_http.o",
		"sk_msg",
		"sk_msg",
		"sk_msg/fgs",
		"sk_msg_fgs",

		false,
		true,
		"http_skmsg")

	/* Http maps */
	ObserverHttpSockMap = BpfMapBuilder("http_sock_map", "sockops", ObserverSockopsEstablished)
)

type observerHttpSensor struct {
	name string
}

func (sockops *observerHttpSensor) LoadProbe(
	bpfDir, mapDir, ciliumDir string,
	load *BpfLoad,
	version, verbose int, x64 bool) (error, int) {
	path := "/sys/fs/bpf/tcpmon/http_sock_map"
	return ObserverLoadSkmsg(bpfDir, mapDir, ciliumDir, load, version, 0, x64, path)
}

func (tls *observerHttpSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*ObserverSensor, error) {
	return getSensorFromParserPolicy(spec)
}

func init() {
	AddHttp()
}

func AddHttp() {
	skmsg := &observerHttpSensor{
		name: "skmsg http sensor",
	}

	RegisterProbeType("http_skmsg", skmsg)
	RegisterTracingSensorsAtInit(skmsg.name, skmsg)
	RegisterEventHandlerAtInit(api.MSG_OP_HTTP, handleHttp)
}

/* Add sensor from CRD */
func EnableHttpParser() *ObserverSensor {
	var progs []*BpfLoad
	var maps []*ObserverMap

	logger.GetLogger().Infof("Enable HTTP")
	progs = append(progs,
		ObserverHttpSkmsg,
	)

	maps = append(maps,
		ObserverHttpSockMap,
	)
	return SensorBuilder("__parser_sensors__", progs, maps)
}

func parseHttpSelector(k *selectors.KernelSelectorState, s v1alpha1.HttpSelector) error {
	return parseMatchPorts(k, s.MatchPorts)
}

// ParseHttpSpec parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to run match logic.
//
// Http selector layout is the following.
//    #OfSelectors         uint32
//    OffsetOfEachSelector uint32
//    #OfMatchPorts        uint32
//    Port1 .... PortN     uint32, uint32, ...
func ParseHttpSpec(spec *v1alpha1.HttpSpec) ([128]byte, error) {
	var match [128]byte
	var e [4096]byte
	k := &selectors.KernelSelectorState{}

	selectors.WriteSelectorUint32(k, uint32(len(spec.Selectors)))
	soff := make([]uint32, len(spec.Selectors))
	for i, _ := range spec.Selectors {
		soff[i] = selectors.AdvanceSelectorLength(k)
	}

	for i, s := range spec.Selectors {
		selectors.WriteSelectorLength(k, soff[i])
		loff := selectors.AdvanceSelectorLength(k)
		if err := parseHttpSelector(k, s); err != nil {
			return match, err
		}
		selectors.WriteSelectorLength(k, loff)
	}

	e = selectors.GetSelectorBuffer(k)
	copy(match[:], e[:128])
	return match, nil
}

func AddHttpSensor(parser v1alpha1.ParserPolicySpec) (*ObserverSensor, error) {
	var err error

	if !parser.Http.Enable {
		return nil, nil
	}

	httpSelectors, err = ParseHttpSpec(&parser.Http)
	if err != nil {
		return nil, err
	}
	return EnableHttpParser(), nil
}

/* HTTP Event handler */
func msgToHttpEventUnix(m *api.MsgHttpEvent) *api.MsgHttpEventUnix {
	return &api.MsgHttpEventUnix{
		Common:     m.Common,
		Tuple:      m.Tuple,
		ProcessKey: m.ProcessKey,
	}
}

func handleHttp(r *bytes.Reader) (interface{}, error) {
	var m *api.MsgHttpEvent

	m = &api.MsgHttpEvent{}
	err := binary.Read(r, binary.LittleEndian, m)
	if err != nil {
		return nil, err
	}

	msgUnix := msgToHttpEventUnix(m)
	return msgUnix, nil
}
