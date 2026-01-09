// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package datapath

import (
	"fmt"
	"net/netip"
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

func (fl *fakeLPMMap) Write(_ netip.Prefix, _ uint64) error {
	return nil
}

func (fl *fakeLPMMap) Delete(_ netip.Prefix) error {
	return nil
}

type FakeEndpointAdder struct {
}

func (fa *FakeEndpointAdder) AddEndpoint(_ endpoint.Endpoint) (uint64, error) {
	return 42, nil
}

type FakePolicyRepositoryIDReader struct {
	policyMap map[string]uint64
	ruleMap   map[string]map[string]uint64
}

func (f *FakePolicyRepositoryIDReader) GetId(name string) (uint64, bool) {
	id, ok := f.policyMap[name]
	return id, ok
}

func (f *FakePolicyRepositoryIDReader) GetRuleId(ruleId types.TetragonPolicyUniqueID) (uint64, bool) {
	id, ok := f.ruleMap[ruleId.PolicyName][ruleId.RuleName]
	return id, ok
}

func getNewFakeBPFProgrammer(fakePolicyRepo *FakePolicyRepositoryIDReader) *BpfProgrammer {
	var repo library.PolicyRepositoryIDReader
	if fakePolicyRepo == nil {
		repo = library.GetRepository()
	} else {
		repo = fakePolicyRepo
	}
	ret := &BpfProgrammer{
		dstMap:                   &fakeBPFMap[types.DestinationEndpointKey, types.DestinationEndpointValue]{},
		binaryMap:                &fakeBPFMap[processTreeBinaryUIDKey, processTreeID]{},
		uidBpfMap:                &fakeBPFMap[processTreeID, processTreeBinaryUIDKey]{},
		lpmMap:                   &fakeLPMMap{},
		endpointAdder:            &FakeEndpointAdder{},
		policyRepositoryIDReader: repo,
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
	bpfProgrammer := getNewFakeBPFProgrammer(nil)
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
				Flags:    types.DestFlagPolicyTemplateOnly,
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
				Flags:    types.DestFlagPolicyTemplateOnly,
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
				Flags:    types.DestFlagPolicyTemplateOnly,
			},
		},
	}

	err := bpfProgrammer.AddSingleRecord(inputRecord, false)
	require.NoError(t, err)
	verifyDstMap(t, bpfProgrammer, expectedEntries)
}

func TestAddSingleRecordWithEndpoint(t *testing.T) {
	bpfProgrammer := getNewFakeBPFProgrammer(nil)
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
				Flags:    types.DestFlagPolicyTemplateOnly,
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
				Flags:    types.DestFlagPolicyTemplateOnly,
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
				Flags:    types.DestFlagPolicyTemplateOnly,
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
				Flags:    types.DestFlagPolicyTemplateOnly,
			},
		},
	}

	err := bpfProgrammer.AddSingleRecord(inputRecord, false)
	require.NoError(t, err)
	verifyDstMap(t, bpfProgrammer, expectedEntries)
}

func TestAddSingleRecordWithEndpointAndPolicy(t *testing.T) {
	fakePolicyRepo := &FakePolicyRepositoryIDReader{
		policyMap: map[string]uint64{
			"test-policy": 32,
		},
		ruleMap: map[string]map[string]uint64{
			"test-policy": {
				"test-rule": 72,
			},
		},
	}
	bpfProgrammer := getNewFakeBPFProgrammer(fakePolicyRepo)
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
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "test-policy",
			RuleName:   "test-rule",
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
				Policy:   32,
				RuleID:   72,
				Flags:    types.DestFlagPolicyTemplateOnly,
			},
		},
		// Wildcard entries below should have PolicyNone action and no PolicyID/RuleID
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
				Policy:   0,
				RuleID:   0,
				Flags:    types.DestFlagPolicyTemplateOnly,
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
				Policy:   0,
				RuleID:   0,
				Flags:    types.DestFlagPolicyTemplateOnly,
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
				Policy:   0,
				RuleID:   0,
				Flags:    types.DestFlagPolicyTemplateOnly,
			},
		},
	}

	err := bpfProgrammer.AddSingleRecord(inputRecord, false)
	require.NoError(t, err)
	verifyDstMap(t, bpfProgrammer, expectedEntries)
}
