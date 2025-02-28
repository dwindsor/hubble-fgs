package dns

import (
	"github.com/cilium/ebpf"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

type DummyBpfProgrammer struct {
	Add      uint64
	AddError uint64
	Del      uint64
	DelError uint64
}

func (p *DummyBpfProgrammer) AddNetworkPolicy(_ *types.ProcessTreeKey, _ *types.TetragonNetworkAction, _ *types.TetragonNetworkDestination, _ bool) error {
	return nil
}

func (p *DummyBpfProgrammer) AddSinglePolicy(_ *types.ProcessTreeKey, _ *endpoint.Endpoint, _ *ebpf.Map, _, _, _ uint64, _ bool) error {
	return nil
}

func (p *DummyBpfProgrammer) RemoveNetworkPolicy(_ *types.ProcessTreeKey, _ *types.TetragonNetworkDestination) error {
	return nil
}

func (p *DummyBpfProgrammer) RemoveSinglePolicy(_ *types.ProcessTreeKey, _ *endpoint.Endpoint, _ *ebpf.Map) error {
	return nil
}
