// Copyright 2020 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package observer

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/ksyms"
	"github.com/covalentio/hubble-fgs/pkg/logger"
	stt "github.com/covalentio/hubble-fgs/pkg/stacktracetree"
	"github.com/covalentio/hubble-fgs/pkg/vtuple"
	"github.com/covalentio/hubble-fgs/pkg/vtuplefilter"
)

var (
	ObserverKfreeSkb = bpfLoad{
		"", "bpf_kfree_skb.o",
		"kfree_skb",
		"kfree_skb",
		"kprobe/kfree_skb",
		"event_kfree_skb",

		false,
		true,
		"kprobe",
		bpfLoadStateIdle(),

		-1,
	}

	packetdropCfg *PacketdropSensorConfig
)

func init() {
	observerAllPrograms = append(observerAllPrograms, &ObserverKfreeSkb)
	sensor := createPacketDropSensor()
	registerSensor(sensor)

}

type PacketdropSensorConfig struct {
	FilterStr string              `json:"filter"`
	Filter    vtuplefilter.Filter `json:"-"`
}

type PacketdropSensorImpl struct {
	config PacketdropSensorConfig
}

func createPacketDropSensor() *observerSensor {
	progs := []*bpfLoad{&ObserverKfreeSkb}
	maps := []*ObserverMap{}
	impl := PacketdropSensorImpl{}
	packetdropCfg = &impl.config
	return &observerSensor{
		name:  "packet-drop",
		progs: progs,
		maps:  maps,
		impl:  &impl,
	}

}

func (pd *PacketdropSensorImpl) sensorLoaded(arg sensorLoadArg) {
	arg.sttManagerHandle.CreateTree("packet-drop")
}

func (pd *PacketdropSensorImpl) sensorUnloaded(arg sensorUnloadArg) {
	arg.sttManagerHandle.DestroyTree("packet-drop")
}

func (pd *PacketdropSensorImpl) sensorGetConfig(key_ string) (string, error) {
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

func (pd *PacketdropSensorImpl) sensorSetConfig(key_ string, param string) error {
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

func msgTuple4ToVTuple(mt *api.MsgIPv4Tuple) vtuple.VTupleImpl {

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

func msgToKfreeSkbUnix(m *api.MsgKfreeSkb, ksyms *ksyms.Ksyms) *api.MsgKfreeSkbUnix {
	ret := api.MsgKfreeSkbUnix{}

	ret.Common = m.Common

	for i := 0; i < len(m.Calltrace.Stack); i++ {
		addr := m.Calltrace.Stack[i]
		symbol := "<unknown>"
		if addr == 0 {
			break
		}
		if ksyms != nil {
			fnOff, err := ksyms.GetFnOffset(addr)
			if err == nil {
				symbol = fnOff.ToString()
			}
		}

		ret.Calltrace = append(ret.Calltrace, api.StackAddr{Addr: addr, Symbol: symbol})
	}
	ret.Tuple = msgTuple4ToVTuple(&m.Tuple)

	return &ret
}

func (k *ObserverKprobe) handleKfreeSkb(m *api.MsgKfreeSkb) {

	msgUnix := msgToKfreeSkbUnix(m, k.ksyms)

	if false {
		log := logger.GetLogger()
		log.Printf("%s", vtuple.StringRep(&msgUnix.Tuple))
		for _, x := range msgUnix.Calltrace {
			log.Printf("\t%s (0x%x)\n", x.Symbol, x.Addr)
		}
	}

	if packetdropCfg != nil && packetdropCfg.FilterStr != "" {
		if !packetdropCfg.Filter.FilterFn(&msgUnix.Tuple) {
			return
		}
		// log := logger.GetLogger()
		// log.Printf("tuple %s passed the filter %s\n", vtuple.StringRep(&msgUnix.Tuple), packetdropCfg.FilterStr)
	}

	stt_lbl := []string{vtuple.StringRep(&msgUnix.Tuple)}
	stt := stt.SttFromCalltrace(msgUnix.Calltrace, stt_lbl)
	k.ObserverSync.sttManagerHandle.Insert("packet-drop", stt)

	// NB: Currently, we don't push these events to listens, but we might
	// want to change that at some point.
	if false {
		for listener, _ := range k.listeners {
			if err := listener.Notify(msgUnix); err != nil {
				k.log.WithError(err).Debug("Write failure, removing Listener")
				k.RemoveListener(listener)
			}
		}
	}
}
