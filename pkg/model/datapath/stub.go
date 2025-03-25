package datapath

import "github.com/isovalent/hubble-fgs/pkg/model/record"

type DummyBpfProgrammer struct {
	Add      uint64
	AddError uint64
	Del      uint64
	DelError uint64
}

func (p *DummyBpfProgrammer) Start() error {
	return nil
}

func (p *DummyBpfProgrammer) AddSingleRecord(_ *record.DatapathRecord) error {
	return nil
}

func (p *DummyBpfProgrammer) AddRecords(_ []*record.DatapathRecord) error {
	return nil
}

func (p *DummyBpfProgrammer) RemoveSingleRecord(_ *record.DatapathRecord) error {
	return nil
}

func (p *DummyBpfProgrammer) RemoveRecords(_ []*record.DatapathRecord) error {
	return nil
}

func (p *DummyBpfProgrammer) GetBinaryId(_ string) (uint64, error) {
	return uint64(0xffffffff), nil
}
