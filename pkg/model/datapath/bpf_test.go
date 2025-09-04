package datapath

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/netpol/library"

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

type FakeEndpointAdder struct {
}

func (fa *FakeEndpointAdder) AddEndpoint(_ endpoint.Endpoint) (uint64, error) {
	return 42, nil
}

func getNewFakeBPFProgrammer() *BpfProgrammer {
	ret := &BpfProgrammer{
		dstMap:                   &fakeBPFMap[types.DestinationEndpointKey, types.DestinationEndpointValue]{},
		binaryMap:                &fakeBPFMap[processTreeBinaryUIDKey, processTreeID]{},
		uidBpfMap:                &fakeBPFMap[processTreeID, processTreeBinaryUIDKey]{},
		lpmMap:                   &fakeLPMMap{},
		endpointAdder:            &FakeEndpointAdder{},
		policyRepositoryIDReader: library.GetRepository(),
	}
	ret.initProgrammerOnce.Do(func() {})
	return ret
}

type expectedEntry struct {
	key   types.DestinationEndpointKey
	value types.DestinationEndpointValue
}

func verifyDstMap(t *testing.T, bpfProgrammer *BpfProgrammer, expectedEntries []expectedEntry) {
	length := 0
	fakeDstMap := bpfProgrammer.dstMap.(*fakeBPFMap[types.DestinationEndpointKey, types.DestinationEndpointValue])
	for i, expected := range expectedEntries {
		var actualValue types.DestinationEndpointValue
		err := fakeDstMap.Lookup(expected.key, &actualValue)
		require.NoError(t, err)
		require.Equal(t, expected.value, actualValue, "index %d expected value for key %+v", i, expected.key)
	}
	fakeDstMap.Range(func(_ string, _ kvpair[types.DestinationEndpointKey, types.DestinationEndpointValue]) bool {
		length++
		return true
	})
	require.Equal(t, len(expectedEntries), length)
}

func TestAddSingleRecordWithoutEndpoint(t *testing.T) {
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
	expectedEntries := []expectedEntry{
		{
			key: types.DestinationEndpointKey{
				LocalId:           inputRecord.Src.Self,
				LocalNSId:         inputRecord.Src.NSID,
				DestinationId:     0,
				DestinationSource: types.DestinationSourceUser,
				DestinationPort:   uint64(inputRecord.Endpoint.Port),
			},
			value: types.DestinationEndpointValue{
				TxAction: record.PolicyDeny,
				Port:     80,
			},
		},
		{
			key: types.DestinationEndpointKey{
				LocalId:           inputRecord.Src.Self,
				LocalNSId:         inputRecord.Src.NSID,
				DestinationId:     0,
				DestinationSource: types.DestinationSourceBPF,
				DestinationPort:   uint64(inputRecord.Endpoint.Port),
			},
			value: types.DestinationEndpointValue{
				TxAction: record.PolicyDeny,
				Port:     80,
			},
		},
		{
			key: types.DestinationEndpointKey{
				LocalId:           inputRecord.Src.Self,
				LocalNSId:         inputRecord.Src.NSID,
				DestinationId:     0,
				DestinationSource: types.DestinationSourceDNS,
				DestinationPort:   uint64(inputRecord.Endpoint.Port),
			},
			value: types.DestinationEndpointValue{
				TxAction: record.PolicyDeny,
				Port:     80,
			},
		},
	}

	err := bpfProgrammer.AddSingleRecord(inputRecord, false)
	require.NoError(t, err)
	verifyDstMap(t, bpfProgrammer, expectedEntries)
}

func TestAddSingleRecordWithEndpoint(t *testing.T) {
	bpfProgrammer := getNewFakeBPFProgrammer()
	inputRecord := &record.DatapathRecord{
		Src: &types.ProcessTreeKey{
			NSID:  1,
			Self:  18446744069414584321,
			Depth: 0,
		},
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Namespace: "test",
				Name:      "test-ep",
			},
			Port: 80,
		},
		Action: &record.DatapathAction{
			QuotaLimit: uint64(0),
			ResetTime:  uint64(0),
			Action:     record.PolicyDeny,
		},
	}
	expectedEntries := []expectedEntry{
		{
			key: types.DestinationEndpointKey{
				LocalId:           inputRecord.Src.Self,
				LocalNSId:         inputRecord.Src.NSID,
				DestinationId:     42,
				DestinationSource: types.DestinationSourceUser,
				DestinationPort:   uint64(inputRecord.Endpoint.Port),
			},
			value: types.DestinationEndpointValue{
				TxAction: record.PolicyDeny,
				Port:     80,
			},
		},
		// Wildcard entries below should have PolicyNone action
		{
			key: types.DestinationEndpointKey{
				LocalId:           inputRecord.Src.Self,
				LocalNSId:         inputRecord.Src.NSID,
				DestinationId:     42,
				DestinationSource: types.DestinationSourceUser,
				DestinationPort:   uint64(0),
			},
			value: types.DestinationEndpointValue{
				TxAction: record.PolicyNone,
				Port:     0,
			},
		},
		{
			key: types.DestinationEndpointKey{
				LocalId:           0,
				LocalNSId:         inputRecord.Src.NSID,
				DestinationId:     42,
				DestinationSource: types.DestinationSourceUser,
				DestinationPort:   uint64(0),
			},
			value: types.DestinationEndpointValue{
				TxAction: record.PolicyNone,
				Port:     0,
			},
		},
		{
			key: types.DestinationEndpointKey{
				LocalId:           0,
				LocalNSId:         inputRecord.Src.NSID,
				DestinationId:     0,
				DestinationSource: types.DestinationSourceUser,
				DestinationPort:   uint64(0),
			},
			value: types.DestinationEndpointValue{
				TxAction: record.PolicyNone,
				Port:     0,
			},
		},
	}

	err := bpfProgrammer.AddSingleRecord(inputRecord, false)
	require.NoError(t, err)
	verifyDstMap(t, bpfProgrammer, expectedEntries)
}
