//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package kfree

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/api/calltraceapi"
	api "github.com/isovalent/hubble-fgs/pkg/api/kfreeapi"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/vtuple"
	"github.com/isovalent/hubble-fgs/pkg/vtuplefilter"
)

var (
	ObserverKfreeSkb = sensors.ProgramBuilder(
		"bpf_kfree_skb.o",
		"kfree_skb",
		"kprobe/kfree_skb",
		"event_kfree_skb",
		"kprobe",
	)

	packetdropCfg *PacketdropSensorConfig
)

func init() {
	sensors.RegisterSensorAtInit(createPacketDropSensor())
}

type PacketdropSensorConfig struct {
	FilterStr string              `json:"filter"`
	Filter    vtuplefilter.Filter `json:"-"`
}

type PacketdropSensorImpl struct {
	config PacketdropSensorConfig
}

func createPacketDropSensor() *sensors.Sensor {
	progs := []*sensors.Program{ObserverKfreeSkb}
	maps := []*sensors.Map{}
	impl := PacketdropSensorImpl{}
	packetdropCfg = &impl.config
	return &sensors.Sensor{
		Name:  "packet-drop",
		Progs: progs,
		Maps:  maps,
		Ops:   &impl,
	}
}

func (pd *PacketdropSensorImpl) Loaded(arg sensors.LoadArg) {
	arg.STTManagerHandle.CreateTree("packet-drop")
}

func (pd *PacketdropSensorImpl) Unloaded(arg sensors.UnloadArg) {
	arg.STTManagerHandle.DestroyTree("packet-drop")
}

func (pd *PacketdropSensorImpl) GetConfig(key_ string) (string, error) {
	key := strings.ToLower(key_)
	switch key {

	// As a convention, GetConfig without a key returns a json text
	// representation of all config values.
	case "":
		b, err := json.Marshal(pd.config)
		if err != nil {
			return "", err
		}
		return string(b), nil

	case "filter":
		return fmt.Sprintf("%s", pd.config.FilterStr), nil

	default:
		return "", fmt.Errorf("failed to get config: Unknown config key %s", key)
	}
}

func (pd *PacketdropSensorImpl) SetConfig(key_ string, param string) error {
	key := strings.ToLower(key_)
	switch key {
	case "filter":
		filter, err := vtuplefilter.FromLine(param)
		if err != nil {
			return fmt.Errorf("failed to create filter %s: %s", param, err)
		}
		pd.config.FilterStr = param
		pd.config.Filter = filter

	default:
		return fmt.Errorf("failed to set config: Unknown config key %s", key)
	}

	return nil
}

func msgTuple4ToVTuple(mt *networkapi.MsgIPv4Tuple) (vtuple.Impl, error) {

	getNetPort := func(np uint16) uint16 {
		b16 := make([]byte, 2)
		binary.BigEndian.PutUint16(b16, np)
		ret := (uint16(b16[0]) << 0) | (uint16(b16[1]) << 8)
		return ret
	}

	getNetIp := func(nip uint32) [4]byte {
		b32 := make([]byte, 4)
		binary.BigEndian.PutUint32(b32, nip)
		return [4]byte{b32[3], b32[2], b32[1], b32[0]}
	}

	srcAddr := getNetIp(mt.SAddr)
	dstAddr := getNetIp(mt.DAddr)
	srcPort := getNetPort(mt.SPort)
	dstPort := getNetPort(mt.DPort)
	proto := mt.Proto

	return vtuple.CreateVTupleV4(proto, srcAddr, srcPort, dstAddr, dstPort)
}

func msgToKfreeSkbUnix(m *api.MsgKfreeSkb) *api.MsgKfreeSkbUnix {
	ret := api.MsgKfreeSkbUnix{}

	ret.Common = m.Common

	for i := 0; i < len(m.Calltrace.Stack); i++ {
		addr := m.Calltrace.Stack[i]
		symbol := "<unknown>"
		if addr == 0 {
			break
		}
		if ksym != nil {
			fnOff, err := ksym.GetFnOffset(addr)
			if err == nil {
				symbol = fnOff.ToString()
			}
		}

		ret.Calltrace = append(ret.Calltrace, calltraceapi.StackAddr{Addr: addr, Symbol: symbol})
	}
	ret.Tuple, _ = msgTuple4ToVTuple(&m.Tuple)

	return &ret
}
