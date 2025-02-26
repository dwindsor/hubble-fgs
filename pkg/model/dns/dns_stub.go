//go:build ebpfStub
// +build ebpfStub

package dns

import (
	"github.com/cilium/ebpf"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

func addNetworkPolicy(src *types.ProcessTreeKey,
	a *types.TetragonNetworkAction,
	d *types.TetragonNetworkDestination,
	init bool) error {
	return nil
}

func removeNetworkPolicy(src *types.ProcessTreeKey, d *types.TetragonNetworkDestination) error {
	return nil
}

func addSingleDnsPolicy(_ *types.ProcessTreeKey, _ *endpoint.Endpoint, _ *ebpf.Map, _, _, _ uint64, _ bool) error {
	return nil
}

func delSingleDnsPolicy(_ *types.ProcessTreeKey, _ *endpoint.Endpoint, _ *ebpf.Map) error {
	return nil
}
