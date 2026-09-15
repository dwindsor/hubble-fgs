// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package workloadid

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/ebpfmap"
)

func newTestState() *State {
	state := newState()
	state.cgroupIDToWorkloadIDMap = &ebpfmap.Fake[CgroupID, WorkloadID]{}
	return state
}

func nginxWorkload() WorkloadMeta {
	return WorkloadMeta{Namespace: "default", Workload: "nginx", Kind: "Deployment"}
}

func corednsWorkload() WorkloadMeta {
	return WorkloadMeta{Namespace: "kube-system", Workload: "coredns", Kind: "Deployment"}
}

func redisWorkload() WorkloadMeta {
	return WorkloadMeta{Namespace: "default", Workload: "redis", Kind: "StatefulSet"}
}

func TestNewState(t *testing.T) {
	state := newState()
	require.NotNil(t, state)
	assert.Equal(t, WorkloadID(1), state.workloadIDCounter)
	assert.NotNil(t, state.idToMeta)
	assert.NotNil(t, state.metaToID)
	assert.NotNil(t, state.cgroupIDResolver)
}

func TestGetStateSingleton(t *testing.T) {
	state1 := GetState()
	state2 := GetState()
	assert.Same(t, state1, state2, "GetState should return the same singleton instance")
}

func TestUpdateNewWorkload(t *testing.T) {
	state := newTestState()
	workload := nginxWorkload()
	cgroupID := CgroupID(1234)

	err := state.Update(workload, cgroupID)
	require.NoError(t, err)

	assert.Equal(t, WorkloadID(2), state.workloadIDCounter, "counter should increment")
	assert.Equal(t, WorkloadID(1), state.metaToID[workload.WorkloadKey])
	assert.Equal(t, workload, state.idToMeta[WorkloadID(1)])

	var result WorkloadID
	err = state.cgroupIDToWorkloadIDMap.Lookup(cgroupID, &result)
	require.NoError(t, err)
	assert.Equal(t, WorkloadID(1), result)
}

func TestUpdateExistingWorkload(t *testing.T) {
	state := newTestState()
	state.workloadIDCounter = 2

	workload := nginxWorkload()
	state.metaToID[workload.WorkloadKey] = WorkloadID(1)
	state.idToMeta[WorkloadID(1)] = workload

	cgroupID := CgroupID(5678)

	err := state.Update(workload, cgroupID)
	require.NoError(t, err)

	assert.Equal(t, WorkloadID(2), state.workloadIDCounter, "counter should not increment for existing workload")

	var result WorkloadID
	err = state.cgroupIDToWorkloadIDMap.Lookup(cgroupID, &result)
	require.NoError(t, err)
	assert.Equal(t, WorkloadID(1), result)
}

func TestUpdateWithoutMapSet(t *testing.T) {
	state := newTestState()
	state.cgroupIDToWorkloadIDMap = nil

	workload := nginxWorkload()
	cgroupID := CgroupID(1234)

	err := state.Update(workload, cgroupID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "the cgroup ID to workload ID map should be set")
}

func TestUpdateMultipleWorkloads(t *testing.T) {
	state := newTestState()

	workloads := []WorkloadMeta{
		nginxWorkload(),
		corednsWorkload(),
		redisWorkload(),
	}

	for i, workload := range workloads {
		cgroupID := CgroupID(1000 + i)
		err := state.Update(workload, cgroupID)
		require.NoError(t, err)

		var result WorkloadID
		err = state.cgroupIDToWorkloadIDMap.Lookup(cgroupID, &result)
		require.NoError(t, err)
		assert.Equal(t, WorkloadID(i+1), result)
	}

	assert.Equal(t, WorkloadID(4), state.workloadIDCounter)
	assert.Len(t, state.metaToID, 3)
	assert.Len(t, state.idToMeta, 3)
}

func TestUpdateSameWorkloadDifferentCgroupID(t *testing.T) {
	state := newTestState()
	workload := nginxWorkload()

	cgroupID1 := CgroupID(1234)
	err := state.Update(workload, cgroupID1)
	require.NoError(t, err)

	cgroupID2 := CgroupID(5678)
	err = state.Update(workload, cgroupID2)
	require.NoError(t, err)

	assert.Equal(t, WorkloadID(2), state.workloadIDCounter, "counter should only increment once")

	var result1, result2 WorkloadID
	err = state.cgroupIDToWorkloadIDMap.Lookup(cgroupID1, &result1)
	require.NoError(t, err)
	assert.Equal(t, WorkloadID(1), result1)

	err = state.cgroupIDToWorkloadIDMap.Lookup(cgroupID2, &result2)
	require.NoError(t, err)
	assert.Equal(t, WorkloadID(1), result2, "both cgroup IDs should map to same workload ID")
}

func TestUpdateRefreshesResourceIdentity(t *testing.T) {
	state := newTestState()
	workload := WorkloadMeta{
		Namespace: "default",
		Workload:  "nginx",
		Kind:      "Deployment",
		UID:       "deployment-uid",
	}
	require.NoError(t, state.Update(workload, CgroupID(1234)))

	require.NoError(t, state.Update(workload, CgroupID(5678)))

	assert.Equal(t, WorkloadID(2), state.workloadIDCounter, "resource version update should reuse the workload ID")
	metadata, ok := state.LookupMeta(WorkloadID(1))
	require.True(t, ok, "updated workload metadata should be found")
	assert.Equal(t, "deployment-uid", metadata.UID, "workload UID should be preserved")
}

func TestLookupIDExists(t *testing.T) {
	state := newTestState()
	workload := nginxWorkload()
	state.metaToID[workload.WorkloadKey] = WorkloadID(1)

	id, ok := state.LookupID(workload.WorkloadKey)
	assert.True(t, ok)
	assert.Equal(t, WorkloadID(1), id)
}

func TestLookupIDNotExists(t *testing.T) {
	state := newTestState()
	workload := nginxWorkload()

	id, ok := state.LookupID(workload.WorkloadKey)
	assert.False(t, ok)
	assert.Equal(t, WorkloadID(0), id)
}

func TestLookupMetaExists(t *testing.T) {
	state := newTestState()
	expectedWorkload := nginxWorkload()
	state.idToMeta[WorkloadID(1)] = expectedWorkload

	workload, ok := state.LookupMeta(WorkloadID(1))
	assert.True(t, ok)
	assert.Equal(t, expectedWorkload, workload)
}

func TestLookupMetaNotExists(t *testing.T) {
	state := newTestState()

	workload, ok := state.LookupMeta(WorkloadID(999))
	assert.False(t, ok)
	assert.Equal(t, WorkloadMeta{}, workload)
}

func TestConcurrentUpdates(t *testing.T) {
	state := newTestState()

	done := make(chan bool)
	numGoroutines := 10

	for i := range numGoroutines {
		go func(idx int) {
			workload := nginxWorkload()
			cgroupID := CgroupID(1000 + idx)
			err := state.Update(workload, cgroupID)
			assert.NoError(t, err)
			done <- true
		}(i)
	}

	for range numGoroutines {
		<-done
	}

	assert.Equal(t, WorkloadID(2), state.workloadIDCounter, "all goroutines should use same workload ID")
	assert.Len(t, state.metaToID, 1)
	assert.Len(t, state.idToMeta, 1)
}

func TestConcurrentLookups(t *testing.T) {
	state := newTestState()
	workload := nginxWorkload()
	state.metaToID[workload.WorkloadKey] = WorkloadID(1)
	state.idToMeta[WorkloadID(1)] = workload

	done := make(chan bool)
	numGoroutines := 100

	for range numGoroutines {
		go func() {
			id, ok := state.LookupID(workload.WorkloadKey)
			assert.True(t, ok)
			assert.Equal(t, WorkloadID(1), id)

			meta, ok := state.LookupMeta(WorkloadID(1))
			assert.True(t, ok)
			assert.Equal(t, workload, meta)

			done <- true
		}()
	}

	for range numGoroutines {
		<-done
	}
}

func TestBPFMapIntegration(t *testing.T) {
	state := newTestState()

	workload1 := nginxWorkload()
	workload2 := corednsWorkload()

	cgid1 := CgroupID(1111)
	cgid2 := CgroupID(2222)

	err := state.Update(workload1, cgid1)
	require.NoError(t, err)

	err = state.Update(workload2, cgid2)
	require.NoError(t, err)

	var wlid1, wlid2 WorkloadID
	err = state.cgroupIDToWorkloadIDMap.Lookup(cgid1, &wlid1)
	require.NoError(t, err)
	assert.Equal(t, WorkloadID(1), wlid1)

	err = state.cgroupIDToWorkloadIDMap.Lookup(cgid2, &wlid2)
	require.NoError(t, err)
	assert.Equal(t, WorkloadID(2), wlid2)

	err = state.cgroupIDToWorkloadIDMap.Delete(cgid1)
	require.NoError(t, err)

	err = state.cgroupIDToWorkloadIDMap.Lookup(cgid1, &wlid1)
	assert.ErrorIs(t, err, ebpf.ErrKeyNotExist)
}

func TestDeleteWrongCgroupID(t *testing.T) {
	state := newTestState()
	workload := nginxWorkload()
	cgroupID := CgroupID(2817)
	wrongCgroupID := CgroupID(9999)

	err := state.Update(workload, cgroupID)
	require.NoError(t, err)

	err = state.DeleteCgroup(wrongCgroupID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get workload ID for cgroupID")
}

func TestDeleteCgroupSingleWorkload(t *testing.T) {
	state := newTestState()
	workload := nginxWorkload()
	cgroupID := CgroupID(12727)

	err := state.Update(workload, cgroupID)
	require.NoError(t, err)

	workloadID, found := state.LookupID(workload.WorkloadKey)
	assert.True(t, found)
	assert.Equal(t, WorkloadID(1), workloadID)

	err = state.DeleteCgroup(cgroupID)
	require.NoError(t, err)

	_, found = state.LookupID(workload.WorkloadKey)
	assert.False(t, found)

	_, found = state.LookupMeta(workloadID)
	assert.False(t, found)
}

func TestDeleteCgroupMultipleWorkloads(t *testing.T) {
	state := newTestState()
	workload := nginxWorkload()
	cgroupID1 := CgroupID(575)
	cgroupID2 := CgroupID(1823)

	err := state.Update(workload, cgroupID1)
	require.NoError(t, err)

	workloadID, found := state.LookupID(workload.WorkloadKey)
	assert.True(t, found)
	assert.Equal(t, WorkloadID(1), workloadID)

	err = state.Update(workload, cgroupID2)
	require.NoError(t, err)

	workloadID2, found := state.LookupID(workload.WorkloadKey)
	assert.True(t, found)
	assert.Equal(t, WorkloadID(1), workloadID2)

	err = state.DeleteCgroup(cgroupID1)
	require.NoError(t, err)

	_, found = state.LookupID(workload.WorkloadKey)
	assert.True(t, found)

	_, found = state.LookupMeta(workloadID)
	assert.True(t, found)

	err = state.DeleteCgroup(cgroupID2)
	require.NoError(t, err)

	_, found = state.LookupID(workload.WorkloadKey)
	assert.False(t, found)

	_, found = state.LookupMeta(workloadID)
	assert.False(t, found)
}
