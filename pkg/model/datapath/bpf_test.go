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

	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/ebpfmap"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/netpol/library"
)

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

func getNewFakeBPFProgrammer(fakePolicyRepo *FakePolicyRepositoryIDReader) *BPFProgrammer {
	var repo library.PolicyRepositoryIDReader
	if fakePolicyRepo == nil {
		repo = library.GetRepository()
	} else {
		repo = fakePolicyRepo
	}
	ret := &BPFProgrammer{
		binaryMap: &ebpfmap.Fake[processTreeBinaryUIDKey, processTreeID]{},
		records:   map[record.RecordKey]record.DatapathRecord{},
	}
	ret.recordBackend = &bpfRecordBackend{
		dstMap:                   &ebpfmap.Fake[types.DestinationEndpointKey, types.DestinationEndpointValue]{},
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

func verifyDstMap(t *testing.T, bpfProgrammer *BPFProgrammer, expectedEntries []expectedEntry) {
	length := 0
	backend := bpfProgrammer.recordBackend.(*bpfRecordBackend)
	fakeDstMap := backend.dstMap.(*ebpfmap.Fake[types.DestinationEndpointKey, types.DestinationEndpointValue])
	for i, expected := range expectedEntries {
		var actualValue types.DestinationEndpointValue
		err := fakeDstMap.Lookup(expected.key, &actualValue)
		require.NoError(t, err)
		require.Equal(t, expected.value, actualValue, "index %d expected value for key %+v", i, expected.key)
	}
	fakeDstMap.Range(func(_ string, _ ebpfmap.KVPair[types.DestinationEndpointKey, types.DestinationEndpointValue]) bool {
		length++
		return true
	})
	require.Equal(t, len(expectedEntries), length)
}

func TestAddRecordWithoutEndpoint(t *testing.T) {
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

	err := bpfProgrammer.addRecord(*inputRecord, false)
	require.NoError(t, err)
	verifyDstMap(t, bpfProgrammer, expectedEntries)
}

func TestAddRecordWithEndpoint(t *testing.T) {
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

	err := bpfProgrammer.addRecord(*inputRecord, false)
	require.NoError(t, err)
	verifyDstMap(t, bpfProgrammer, expectedEntries)
}

func TestAddRecordWithEndpointAndPolicy(t *testing.T) {
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

	err := bpfProgrammer.addRecord(*inputRecord, false)
	require.NoError(t, err)
	verifyDstMap(t, bpfProgrammer, expectedEntries)
}

// mockRecordBackend tracks calls to addRecord and removeRecord for testing cache behavior
type mockRecordBackend struct {
	addRecordCalls    []record.DatapathRecord
	removeRecordCalls []record.DatapathRecord
	addRecordErr      error
	removeRecordErr   error
}

func (m *mockRecordBackend) addRecord(r record.DatapathRecord, _ bool) error {
	m.addRecordCalls = append(m.addRecordCalls, r)
	return m.addRecordErr
}

func (m *mockRecordBackend) removeRecord(r record.DatapathRecord) error {
	m.removeRecordCalls = append(m.removeRecordCalls, r)
	return m.removeRecordErr
}

func newMockBpfProgrammer() (*BPFProgrammer, *mockRecordBackend) {
	mock := &mockRecordBackend{}
	p := &BPFProgrammer{
		recordBackend: mock,
		records:       map[record.RecordKey]record.DatapathRecord{},
	}
	p.initProgrammerOnce.Do(func() {})
	return p, mock
}

func makeTestRecord(nsid, self uint64, port uint32, epName string) *record.DatapathRecord {
	var ep *endpoint.Endpoint
	if epName != "" {
		ep = &endpoint.Endpoint{
			Namespace: "test",
			Name:      epName,
		}
	}
	return &record.DatapathRecord{
		Src: &types.ProcessTreeKey{
			NSID: nsid,
			Self: self,
		},
		Endpoint: record.DatapathEndpoint{
			EP:   ep,
			Port: port,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyDeny,
		},
	}
}

func TestAddRecords_SkipsCachedRecords(t *testing.T) {
	p, mock := newMockBpfProgrammer()

	r1 := makeTestRecord(1, 100, 80, "ep1")

	// First AddRecords should call addRecord
	err := p.AddRecords([]record.DatapathRecord{*r1}, false)
	require.NoError(t, err)
	require.Len(t, mock.addRecordCalls, 1)

	// Second AddRecords with same record should NOT call addRecord (cached)
	err = p.AddRecords([]record.DatapathRecord{*r1}, false)
	require.NoError(t, err)
	require.Len(t, mock.addRecordCalls, 1, "addRecord should not be called for cached record")
}

func TestAddRecords_AddsToCache(t *testing.T) {
	p, mock := newMockBpfProgrammer()

	r1 := makeTestRecord(1, 100, 80, "ep1")
	r2 := makeTestRecord(1, 100, 443, "ep2")

	// Add first record
	err := p.AddRecords([]record.DatapathRecord{*r1}, false)
	require.NoError(t, err)
	require.Len(t, p.records, 1)

	// Add second record
	err = p.AddRecords([]record.DatapathRecord{*r2}, false)
	require.NoError(t, err)
	require.Len(t, p.records, 2)
	require.Len(t, mock.addRecordCalls, 2)
}

func TestAddRecords_MultipleRecordsInSingleCall(t *testing.T) {
	p, mock := newMockBpfProgrammer()

	r1 := makeTestRecord(1, 100, 80, "ep1")
	r2 := makeTestRecord(1, 100, 443, "ep2")
	r3 := makeTestRecord(2, 200, 8080, "ep3")

	err := p.AddRecords([]record.DatapathRecord{*r1, *r2, *r3}, false)
	require.NoError(t, err)
	require.Len(t, mock.addRecordCalls, 3)
	require.Len(t, p.records, 3)
}

func TestAddRecords_DuplicatesInSingleCall(t *testing.T) {
	p, mock := newMockBpfProgrammer()

	r1 := makeTestRecord(1, 100, 80, "ep1")

	// Same record twice in one call - second should be skipped after first is cached
	err := p.AddRecords([]record.DatapathRecord{*r1, *r1}, false)
	require.NoError(t, err)
	require.Len(t, mock.addRecordCalls, 1, "duplicate in same call should be skipped")
	require.Len(t, p.records, 1)
}

func TestAddRecords_DoesNotCacheOnError(t *testing.T) {
	p, mock := newMockBpfProgrammer()
	mock.addRecordErr = fmt.Errorf("BPF error")

	r1 := makeTestRecord(1, 100, 80, "ep1")

	err := p.AddRecords([]record.DatapathRecord{*r1}, false)
	require.Error(t, err)
	require.Len(t, p.records, 0, "failed record should not be cached")
}

func TestRemoveRecords_SkipsNonCachedRecords(t *testing.T) {
	p, mock := newMockBpfProgrammer()

	r1 := makeTestRecord(1, 100, 80, "ep1")

	// Try to remove a record that was never added
	err := p.RemoveRecords([]record.DatapathRecord{*r1})
	require.NoError(t, err)
	require.Len(t, mock.removeRecordCalls, 0, "removeRecord should not be called for non-cached record")
}

func TestRemoveRecords_RemovesFromCache(t *testing.T) {
	p, mock := newMockBpfProgrammer()

	r1 := makeTestRecord(1, 100, 80, "ep1")

	// Add record first
	err := p.AddRecords([]record.DatapathRecord{*r1}, false)
	require.NoError(t, err)
	require.Len(t, p.records, 1)

	// Remove record
	err = p.RemoveRecords([]record.DatapathRecord{*r1})
	require.NoError(t, err)
	require.Len(t, mock.removeRecordCalls, 1)
	require.Len(t, p.records, 0, "record should be removed from cache")
}

func TestRemoveRecords_DoesNotRemoveFromCacheOnError(t *testing.T) {
	p, mock := newMockBpfProgrammer()

	r1 := makeTestRecord(1, 100, 80, "ep1")

	// Add record first
	err := p.AddRecords([]record.DatapathRecord{*r1}, false)
	require.NoError(t, err)
	require.Len(t, p.records, 1)

	// Set error for remove
	mock.removeRecordErr = fmt.Errorf("BPF error")

	// Try to remove - should fail and keep cache intact
	err = p.RemoveRecords([]record.DatapathRecord{*r1})
	require.Error(t, err)
	require.Len(t, p.records, 1, "failed removal should not affect cache")
}

func TestAddRemoveRecords_RoundTrip(t *testing.T) {
	p, mock := newMockBpfProgrammer()

	r1 := makeTestRecord(1, 100, 80, "ep1")
	r2 := makeTestRecord(1, 100, 443, "ep2")

	// Add both records
	err := p.AddRecords([]record.DatapathRecord{*r1, *r2}, false)
	require.NoError(t, err)
	require.Len(t, p.records, 2)

	// Remove first record
	err = p.RemoveRecords([]record.DatapathRecord{*r1})
	require.NoError(t, err)
	require.Len(t, p.records, 1)

	// Try to add first record again - should work since it was removed
	err = p.AddRecords([]record.DatapathRecord{*r1}, false)
	require.NoError(t, err)
	require.Len(t, mock.addRecordCalls, 3, "re-adding removed record should call addRecord")
	require.Len(t, p.records, 2)

	// Remove both records
	err = p.RemoveRecords([]record.DatapathRecord{*r1, *r2})
	require.NoError(t, err)
	require.Len(t, p.records, 0)
}

func TestRemoveRecords_PartialRemoval(t *testing.T) {
	p, mock := newMockBpfProgrammer()

	r1 := makeTestRecord(1, 100, 80, "ep1")
	r2 := makeTestRecord(1, 100, 443, "ep2")
	r3 := makeTestRecord(2, 200, 8080, "ep3")

	// Add only r1 and r2
	err := p.AddRecords([]record.DatapathRecord{*r1, *r2}, false)
	require.NoError(t, err)

	// Try to remove r1, r2, and r3 (r3 was never added)
	err = p.RemoveRecords([]record.DatapathRecord{*r1, *r2, *r3})
	require.NoError(t, err)
	require.Len(t, mock.removeRecordCalls, 2, "only cached records should trigger removeRecord")
	require.Len(t, p.records, 0)
}
