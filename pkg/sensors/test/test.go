package test

import (
	"bytes"
	"encoding/binary"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/observer"
)

func init() {
	AddTest()
}
func AddTest() {
	observer.RegisterEventHandlerAtInit(api.MSG_OP_TEST, handleTest)
}

func msgToTestUnix(m *api.MsgTestEvent) *api.MsgTestEventUnix {
	return m
}

func handleTest(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgTestEvent{}
	if err := binary.Read(r, binary.LittleEndian, &m); err != nil {
		return nil, err
	}
	msgUnix := msgToTestUnix(&m)
	return []observer.Event{msgUnix}, nil
}
