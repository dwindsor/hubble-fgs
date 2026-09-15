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
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/isovalent/hubble-fgs/pkg/ebpfmap"
	"github.com/isovalent/hubble-fgs/pkg/fscgroupid"
)

const (
	CgroupIDWorkloadIDMapName = "tg_cgid_wlid"

	MaxWorkloadID = 1024
)

// WorkloadKey is how we aggregate identity from the Kubernetes PoV. We want
// Pods' process from the same ReplicaSet to share the same identity.
type WorkloadKey struct {
	Namespace string
	Workload  string
	Kind      string
}

// WorkloadMeta contains additional mutable information (not used for
// aggregation) on the resource in addition of WorkloadKey
type WorkloadMeta struct {
	WorkloadKey
	UID string
}

// WorkloadID is the ID to map between the workload metadata that contains the
// Name, Namespace and Kind of the workload and the cgroup ID of the process.
// The ID is useful for BPF so we can avoid strings in BPF side.
type WorkloadID uint64

type CgroupID uint64

func (cgid CgroupID) String() string {
	return fmt.Sprintf("cgid(%d)", cgid)
}

type State struct {
	// client.Client is embedded for the Reconciler to be able to watch for
	// new Pods via the Kubernetes API.
	client.Client
	// The cgroupIDResolver is used to resolve cgroup IDs from pod UIDs.
	cgroupIDResolver fscgroupid.Resolver
	// The reconciler is registered from the layer3 sensor in configureMaps
	// and can be technically called multiple times because of legacy
	// TracingPolicy l3 configs. Once the layer3 sensor will be guaranteed
	// to be loaded only at start, we will be able to remove this.
	reconcilerRegistered bool

	// workloadIDCounter is the userspace counter used to generate new
	// workload IDs. The counter should be initialized at 1 at construction.
	workloadIDCounter WorkloadID
	// idToMeta stores the link workload ID -> workload metadata
	idToMeta map[WorkloadID]WorkloadMeta
	// metaToID stores the link workload metadata -> workload ID
	metaToID map[WorkloadKey]WorkloadID
	// mu locks the above maps and the counter.
	mu sync.RWMutex

	cgroupIDToWorkloadIDMap ebpfmap.InterfaceTyped[CgroupID, WorkloadID]
}

func newState() *State {
	return &State{
		cgroupIDResolver:  fscgroupid.New(),
		workloadIDCounter: 1,
		idToMeta:          map[WorkloadID]WorkloadMeta{},
		metaToID:          map[WorkloadKey]WorkloadID{},
	}
}

var getState = sync.OnceValue(newState)

// GetState returns the singleton holding the State managing the workload ID.
func GetState() *State {
	return getState()
}

// SetMap needs to be called on loading the BPF maps and program to init the
// workloadid component.
func (s *State) SetMap(workloadIDMap *ebpf.Map) error {
	if workloadIDMap == nil {
		return fmt.Errorf("workload ID map is nil")
	}
	s.cgroupIDToWorkloadIDMap = ebpfmap.NewTyped[CgroupID, WorkloadID](workloadIDMap)
	return nil
}

func (s *State) Update(workload WorkloadMeta, cgroupID CgroupID) error {
	if s.cgroupIDToWorkloadIDMap == nil {
		return fmt.Errorf("the cgroup ID to workload ID map should be set, this is a bug please report")
	}

	// This could be optimized if needed since one path is read-only.
	s.mu.Lock()
	defer s.mu.Unlock()

	key := workload.WorkloadKey
	if workloadID, exist := s.metaToID[key]; exist {
		// Maybe the cgroup ID changed, consistent with previous implem in policyfilter[^1]
		// [^1]: https://github.com/cilium/tetragon/commit/4e2c2fe66941f6afff6605f0c42d8b1371df9383
		err := s.cgroupIDToWorkloadIDMap.Update(cgroupID, workloadID, ebpf.UpdateAny)
		if err != nil {
			return fmt.Errorf("failed to bind the cgroupID %d to existing workloadID %d: %w", cgroupID, workloadID, err)
		}
		return nil
	}

	// This is a new workload, bind to a new stable ID
	err := s.cgroupIDToWorkloadIDMap.Update(cgroupID, s.workloadIDCounter, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed to bind the cgroupID %d to workloadID %d: %w", cgroupID, s.workloadIDCounter, err)
	}
	s.metaToID[key] = s.workloadIDCounter
	s.idToMeta[s.workloadIDCounter] = workload
	s.workloadIDCounter++

	return nil
}

func (s *State) LookupID(workload WorkloadKey) (WorkloadID, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if workloadID, ok := s.metaToID[workload]; ok {
		return workloadID, ok
	}
	return WorkloadID(0), false
}

func (s *State) LookupMeta(workloadID WorkloadID) (WorkloadMeta, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if workloadMeta, ok := s.idToMeta[workloadID]; ok {
		return workloadMeta, ok
	}
	return WorkloadMeta{}, false
}

func (s *State) DeleteCgroup(cgroupID CgroupID) error {
	if s.cgroupIDToWorkloadIDMap == nil {
		return fmt.Errorf("the cgroup ID to workload ID map should be set, this is a bug please report")
	}

	// Find the workload id associated with this cgroup id. We might remove it
	// from idToMeta/metaToID if this was the last reference to this workload
	// id.
	var workloadID WorkloadID
	err := s.cgroupIDToWorkloadIDMap.Lookup(cgroupID, &workloadID)
	if err != nil {
		return fmt.Errorf("failed to get workload ID for cgroupID %d: %w", cgroupID, err)
	}

	if err := s.cgroupIDToWorkloadIDMap.Delete(cgroupID); err != nil {
		return fmt.Errorf("failed to delete cgroupID %d from workload ID map: %w", cgroupID, err)
	}

	var cgid CgroupID
	var wlid WorkloadID
	iter := s.cgroupIDToWorkloadIDMap.Iterate()

	for iter.Next(&cgid, &wlid) {
		if wlid == workloadID {
			// A different cgroup id points to this workload id, don't remove
			// anything.
			return nil
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to iterate over cgroupID to workload ID map: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.metaToID, s.idToMeta[workloadID].WorkloadKey)
	delete(s.idToMeta, workloadID)

	return nil
}
