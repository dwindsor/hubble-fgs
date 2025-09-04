package datapath

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"

	"github.com/cilium/cilium/pkg/lock"
)

type kvpair[K any, V any] struct {
	a K
	b V
}
type fakeBPFMap[K fmt.Stringer, V any] struct {
	lock.Map[string, kvpair[K, V]]
}

func (fm *fakeBPFMap[K, V]) Lookup(key K, result *V) error {
	v, exists := fm.Load(key.String())
	if !exists {
		return ebpf.ErrKeyNotExist
	}
	*result = v.b
	return nil
}

func (fm *fakeBPFMap[K, V]) Update(key K, value V, _ ebpf.MapUpdateFlags) error {
	fm.Store(key.String(), kvpair[K, V]{a: key, b: value})
	return nil
}

type fakeLPMMap struct {
}

func (fl *fakeLPMMap) Write(_ string, _ uint64) error {
	return nil
}

func (fl *fakeLPMMap) Delete(_ string) error {
	return nil
}

func getNewFakeBPFProgrammer() *BpfProgrammer {
	ret := &BpfProgrammer{
		dstMap:    &fakeBPFMap[types.DestinationEndpointKey, types.DestinationEndpointValue]{},
		binaryMap: &fakeBPFMap[processTreeBinaryUIDKey, processTreeID]{},
		uidBpfMap: &fakeBPFMap[processTreeID, processTreeBinaryUIDKey]{},
		lpmMap:    &fakeLPMMap{},
	}
	ret.initProgrammerOnce.Do(func() {})
	return ret
}

func TestAddSingleRecord(t *testing.T) {
	bpfProgrammer := getNewFakeBPFProgrammer()
	inputRecord := &record.DatapathRecord{
		Src: &types.ProcessTreeKey{
			NSID:  1,
			Self:  18446744069414584321,
			Depth: 0,
		},
		Endpoint: record.DatapathEndpoint{
			EP:   nil,
			Port: 80,
		},
		Action: &record.DatapathAction{
			QuotaLimit: uint64(0),
			ResetTime:  uint64(0),
			Action:     record.PolicyDeny,
		},
	}

	err := bpfProgrammer.AddSingleRecord(inputRecord, false)
	require.NoError(t, err)

	fakeDstMap := bpfProgrammer.dstMap.(*fakeBPFMap[types.DestinationEndpointKey, types.DestinationEndpointValue])
	sources := []uint64{}
	expectedKey := types.DestinationEndpointKey{
		LocalId:           inputRecord.Src.Self,
		LocalNSId:         inputRecord.Src.NSID,
		DestinationId:     0,
		DestinationSource: types.DestinationSourceBPF,
		DestinationPort:   uint64(inputRecord.Endpoint.Port),
	}
	expectedValue := types.DestinationEndpointValue{
		TxAction: record.PolicyDeny,
		Port:     80,
	}
	fakeDstMap.Range(func(key string, value kvpair[types.DestinationEndpointKey, types.DestinationEndpointValue]) bool {
		sources = append(sources, value.a.DestinationSource)
		// Ignore DestinationSource for comparison
		expectedKey.DestinationSource = value.a.DestinationSource
		require.Equal(t, expectedKey, value.a)
		require.Equal(t, expectedValue, value.b)
		return true
	})
	// We want to have 3 entries with 3 different sources
	require.ElementsMatch(t, sources, []uint64{types.DestinationSourceBPF, types.DestinationSourceDNS, types.DestinationSourceUser})
}
