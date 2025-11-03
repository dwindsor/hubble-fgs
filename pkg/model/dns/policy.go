package dns

import (
	"maps"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/policyfilter"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/matchLabels"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

func (state *PolicyState) removeMatchLabelNetworkPolicy(policy *types.TetragonNetworkPolicy) ([]*record.DatapathRecord, []*record.DatapathRecord, error) {
	state.SrcLock.Lock()
	defer state.SrcLock.Unlock()

	subject := state.Src[policy.PolicyUID]

	var beforeSubjs []*record.DatapathRecord
	var afterSubjs []*record.DatapathRecord

	subjectLabels := &matchLabels.LabelSet{
		Labels: policy.Subject.Labels.Equal,
		Policy: policy,
	}

	if subject != nil {
		for _, s := range subject.Subjects {
			records := state.SrcAdd(s, subjectLabels, false)
			beforeSubjs = append(beforeSubjs, records...)
		}
	}

	state.Src.Remove(policy.PolicyUID)
	state.Dst.Remove(policy.PolicyUID)

	for _, v := range state.Src {
		if v == nil {
			continue
		}
		for _, src := range v.Subjects {
			sRecords, err := state.AddSrcPolicy(src, v.Policy, true)
			if err != nil {
				logger.GetLogger().Warn("AddSrcPolicy error", logfields.Error, err, "src", src)
				continue
			}
			afterSubjs = append(afterSubjs, sRecords...)
		}
	}

	// A key that exists only in the before list can be deleted because
	// nothing is referencing that key anymore. And the after list can
	// be used to update existing rules to their new state.
	zombieSet := record.Diff(beforeSubjs, afterSubjs)
	return zombieSet, afterSubjs, nil
}

func (state *PolicyState) RemoveMatchLabelNetworkPolicy(policy *types.TetragonNetworkPolicy) error {
	zombieSet, updateSet, err := state.removeMatchLabelNetworkPolicy(policy)
	if err != nil {
		return err
	}
	// Necessary order to ensure any updates to records are in place before we
	// remove stale records.
	prog.AddRecords(updateSet, true)
	prog.RemoveRecords(zombieSet)
	return nil
}

func createSrcKey(namespace, wl, kind string) (*types.ProcessTreeKey, error) {
	var nsId policyfilter.StateID
	if namespace != "" {
		var ok bool

		workload := policyfilter.NSID{
			Namespace: namespace,
			Workload:  wl,
			Kind:      kind,
		}

		state, err := policyfilter.GetState()
		if err != nil {
			logger.GetLogger().Warn("Unable to get policyfilter", logfields.Error, err)
			return nil, err
		}
		// If the ID does not yet exist we need to wait for it to be added. This is
		// an imperfect solution. Ideally we would just modify the policyfilter state
		// to preallocate an ID.But, its in OSS and not obvious how to extend it to
		// support this.
		nsId, ok = state.GetIdNs(workload)
		if !ok {
			logger.GetLogger().Debug("workload info does not exist yet, queuing for workload updates.", "namespace", namespace, "workload", wl)
			return nil, nil
		}
	} else {
		nsId = policyfilter.StateID(0)
	}

	return &types.ProcessTreeKey{
		NSID:  uint64(nsId),
		Depth: 0,
		Self:  0,
		Path:  [8]uint64{0, 0, 0, 0, 0, 0, 0, 0},
	}, nil
}

func (state *PolicyState) policyDestRecords(src *types.ProcessTreeKey, action *record.DatapathAction, policy *types.TetragonNetworkPolicy, init bool) []*record.DatapathRecord {
	records := []*record.DatapathRecord{}

	if policy.Destination.CIDR != nil {
		r, err := addDestSrcCIDRRecords(policy.PolicyUID, &policy.Destination, src, action, init)
		if err != nil {
			logger.GetLogger().Warn("CIDR policy record error", logfields.Error, err, "CIDR", policy.Destination.CIDR)
		}
		records = append(records, r...)
	}

	if policy.Destination.FQDN != nil {
		for _, entry := range policy.Destination.FQDN.Names {
			if len(policy.Destination.Ports) == 0 {
				ep := &endpoint.Endpoint{
					Type: tetragon.EndpointType_ENDPOINT_TYPE_DNS,
					Dns:  entry,
				}
				endpoint := record.DatapathEndpoint{
					EP:   ep,
					Port: 0,
				}
				records = append(records, &record.DatapathRecord{
					PolicyUID: policy.PolicyUID,
					Src:       src,
					Endpoint:  endpoint,
					Action:    action,
					Init:      init,
				})
			}

			for _, port := range policy.Destination.Ports {
				ep := &endpoint.Endpoint{
					Type: tetragon.EndpointType_ENDPOINT_TYPE_DNS,
					Dns:  entry,
				}
				endpoint := record.DatapathEndpoint{
					EP:   ep,
					Port: port,
				}
				records = append(records, &record.DatapathRecord{
					PolicyUID: policy.PolicyUID,
					Src:       src,
					Endpoint:  endpoint,
					Action:    action,
					Init:      init,
				})
			}
		}
	}

	ls := state.Dst[policy.PolicyUID]
	if ls != nil {
		for _, ep := range ls.Endpoints {
			if len(ls.Policy.Destination.Ports) == 0 {
				endpoint := record.DatapathEndpoint{
					EP:   ep,
					Port: 0,
				}

				records = append(records, &record.DatapathRecord{
					PolicyUID: policy.PolicyUID,
					Src:       src,
					Endpoint:  endpoint,
					Action:    action,
					Init:      init,
				})
			}
			for _, port := range ls.Policy.Destination.Ports {
				endpoint := record.DatapathEndpoint{
					EP:   ep,
					Port: port,
				}

				records = append(records, &record.DatapathRecord{
					PolicyUID: policy.PolicyUID,
					Src:       src,
					Endpoint:  endpoint,
					Action:    action,
					Init:      init,
				})
			}
		}
	}
	return records
}

// Create DstMatchLAbelsPolicy to add new Network Policy
func (state *PolicyState) CreateDstMatchLabelsPolicy(policy *types.TetragonNetworkPolicy) {
	state.DstLock.Lock()
	defer state.DstLock.Unlock()

	if len(policy.Destination.Labels.Equal) < 1 {
		return
	}

	ls := &matchLabels.LabelSet{
		Labels: policy.Destination.Labels.Equal,
		Policy: policy,
		Ports:  policy.Destination.Ports,
	}

	state.Dst.Add(ls)
}

// Create SrcMatchLAbelsPolicy to add new Network Policy
func (state *PolicyState) CreateSrcMatchLabelsPolicy(policy *types.TetragonNetworkPolicy) {
	state.SrcLock.Lock()
	defer state.SrcLock.Unlock()

	ls := &matchLabels.LabelSet{
		Labels: policy.Subject.Labels.Equal,
		Policy: policy,
	}

	state.Src.Add(ls)
}

func (state *PolicyState) CreateMatchLabelsPolicy(policy *types.TetragonNetworkPolicy) error {
	if len(policy.Destination.Labels.Equal) > 0 {
		state.CreateDstMatchLabelsPolicy(policy)
	}

	// There are a few possibilities for possible scope.
	// 0. MatchLabels is set then we use this otherwise,
	// 1. fully specified namespace:workload:kind
	// 2. namespace scoped policy e.g. just namespace
	// 3. host scope, no namespace
	if len(policy.Subject.Labels.Equal) > 0 {
		state.CreateSrcMatchLabelsPolicy(policy)
	}

	return nil
}

func (state *PolicyState) getAllExistingPolicy() []*types.TetragonNetworkPolicy {
	uniquePolicyMap := make(map[types.TetragonPolicyUniqueID]*types.TetragonNetworkPolicy)
	allPolicy := make([]*types.TetragonNetworkPolicy, 0)

	for _, p := range state.Src {
		if _, ok := uniquePolicyMap[p.Policy.PolicyUID]; !ok {
			uniquePolicyMap[p.Policy.PolicyUID] = p.Policy
			allPolicy = append(allPolicy, p.Policy)
		}
	}
	for _, p := range state.Dst {
		if _, ok := uniquePolicyMap[p.Policy.PolicyUID]; !ok {
			uniquePolicyMap[p.Policy.PolicyUID] = p.Policy
			allPolicy = append(allPolicy, p.Policy)
		}
	}
	return allPolicy
}

func (state *PolicyState) GetRecords(currentPolicy []*types.TetragonNetworkPolicy) (*PolicyState, []*record.DatapathRecord, error) {
	calculatorRecords := []*record.DatapathRecord{}
	calculatorState := NewPolicyState()

	// Add Policy to calculator state
	for _, p := range currentPolicy {
		err := calculatorState.CreateMatchLabelsPolicy(p)
		if err != nil {
			return nil, nil, err
		}
	}

	// Calculate current records of before making state change
	for _, p := range state.localObjects {
		r, err := calculatorState.objectAdd(p)
		if err != nil {
			return nil, nil, err
		}
		calculatorRecords = append(calculatorRecords, r...)
	}

	for _, p := range state.remoteObjects {
		r, err := calculatorState.objectAdd(p)
		if err != nil {
			return nil, nil, err
		}
		calculatorRecords = append(calculatorRecords, r...)
	}

	return calculatorState, calculatorRecords, nil
}

// createMatchLabelsPolicySet computes the records generated from the current
// state and policies, then computes the records generated from a fresh state
// contaning the current and new policies. It then returns the new state, the
// records to add and the records to remove (which are the diff between the
// current computed records and the new ones).
//
// Todo, this has lots of low hanging fruit for optimizing duplicate calculations.
func createMatchLabelsPolicySet(policy []*types.TetragonNetworkPolicy) (*PolicyState, []*record.DatapathRecord, []*record.DatapathRecord, error) {
	// Entry point to Policy state create collect records for current
	// policy state.
	preState := GetRealizedState()
	currentPolicy := preState.getAllExistingPolicy()
	_, preRecords, err := preState.GetRecords(currentPolicy)
	if err != nil {
		return nil, nil, nil, err
	}

	// Building new policy set with additional policy
	newPolicy := append(currentPolicy, policy...)

	// Recalculate records using new state with new policy.
	postState := NewPolicyState()
	postState.localObjects = maps.Clone(preState.localObjects)
	postState.remoteObjects = maps.Clone(preState.remoteObjects)
	postState, postRecords, err := postState.GetRecords(newPolicy)
	if err != nil {
		return nil, nil, nil, err
	}

	// Find datapath record for new policy and the set of records
	// we need to remove.
	removeRecordsSet := record.Diff(preRecords, postRecords)
	return postState, postRecords, removeRecordsSet, nil
}

func CreateMatchLabelsPolicySet(policy []*types.TetragonNetworkPolicy) error {
	state := GetRealizedState()
	state.Reader.Lock()
	defer state.Reader.Unlock()

	newState, addSet, removeSet, err := createMatchLabelsPolicySet(policy)
	if err != nil {
		return err
	}

	// Order matters lets add the new set of recrods, notice this
	// might duplicate existing records its fine we just update
	// them regardless. Then second remove any old records that
	// are no longer valid.
	prog.AddRecords(addSet, false)
	prog.RemoveRecords(removeSet)

	// Setnew state
	SetRealizedState(newState)
	return nil
}

// Entry point to Policy state remove
func RemoveNetworkPolicySet(policy []*types.TetragonNetworkPolicy) error {
	s := GetRealizedState()

	for _, p := range policy {
		err := s.RemoveMatchLabelNetworkPolicy(p)
		if err != nil {
			return err
		}
	}
	return nil
}
