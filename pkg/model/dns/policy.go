package dns

import (
	"fmt"
	"maps"
	"strconv"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/policyfilter"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/matchLabels"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/netpol/library"
)

func (state *PolicyState) removeMatchLabelNetworkPolicy(uid string, policy *types.TetragonNetworkPolicy) ([]*record.DatapathRecord, []*record.DatapathRecord, error) {
	state.SrcLock.Lock()
	defer state.SrcLock.Unlock()

	subject := state.Src[uid]

	l3id := ""
	if policy.Subject.LogicalNetwork.VRF != "" {
		l3id = policy.Subject.LogicalNetwork.VRF
	} else if policy.Subject.LogicalNetwork.VLAN != 0 {
		l3id = policy.Subject.LogicalNetwork.VRF
	}
	l3 := state.L3[uid]

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

	if l3 != nil {
		records, err := state.l3Add(l3id)
		if err != nil {
			logger.GetLogger().Warn("Remove policy failure: ", "policyName", l3.Name)
		} else {
			beforeSubjs = append(beforeSubjs, records...)
		}
	}

	state.Src.Remove(uid)
	state.Dst.Remove(uid)
	state.L3.Remove(uid)

	for _, v := range state.Src {
		if v == nil {
			continue
		}
		for _, src := range v.Subjects {
			sRecords, err := state.AddSrcPolicy(v.Name, src, v.Policy, true)
			if err != nil {
				logger.GetLogger().Warn("AddSrcPolicy error", logfields.Error, err, "src", src)
				continue
			}
			afterSubjs = append(afterSubjs, sRecords...)
		}
	}

	if l3 != nil {
		records, err := state.l3Add(l3id)
		if err != nil {
			logger.GetLogger().Warn("Error on policy remove, failed to build new state:", "logicalNetwork", l3id)
		} else {
			afterSubjs = append(afterSubjs, records...)
		}
	}

	// A key that exists only in the before list can be deleted because
	// nothing is referencing that key anymore. And the after list can
	// be used to update existing rules to their new state.
	zombieSet := record.Diff(beforeSubjs, afterSubjs)
	return zombieSet, afterSubjs, nil
}

func (state *PolicyState) RemoveMatchLabelNetworkPolicy(uid string, policy *types.TetragonNetworkPolicy) error {
	zombieSet, updateSet, err := state.removeMatchLabelNetworkPolicy(uid, policy)
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

func (state *PolicyState) policyDestRecords(uid string, src *types.ProcessTreeKey, action *record.DatapathAction, policy *types.TetragonNetworkPolicy, init bool) []*record.DatapathRecord {
	records := []*record.DatapathRecord{}
	recordPolicy := record.Policy{
		Name: uid,
		Rule: policy.Rule,
	}

	if policy.Destination.CIDR != nil {
		r, err := addDestSrcCIDRRecords(&recordPolicy, &policy.Destination, src, action, init)
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
					Policy:   recordPolicy,
					Src:      src,
					Endpoint: endpoint,
					Action:   action,
					Init:     init,
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
					Policy:   recordPolicy,
					Src:      src,
					Endpoint: endpoint,
					Action:   action,
					Init:     init,
				})
			}
		}
	}

	ls := state.Dst[uid]
	if ls != nil {
		for _, ep := range ls.Endpoints {
			if len(ls.Policy.Destination.Ports) == 0 {
				endpoint := record.DatapathEndpoint{
					EP:   ep,
					Port: 0,
				}

				records = append(records, &record.DatapathRecord{
					Policy:   recordPolicy,
					Src:      src,
					Endpoint: endpoint,
					Action:   action,
					Init:     init,
				})
			}
			for _, port := range ls.Policy.Destination.Ports {
				endpoint := record.DatapathEndpoint{
					EP:   ep,
					Port: port,
				}

				records = append(records, &record.DatapathRecord{
					Policy:   recordPolicy,
					Src:      src,
					Endpoint: endpoint,
					Action:   action,
					Init:     init,
				})
			}
		}
	}
	return records
}

// Create DstMatchLAbelsPolicy to add new Network Policy
func (state *PolicyState) CreateDstMatchLabelsPolicy(uid string, policy *types.TetragonNetworkPolicy) {
	state.DstLock.Lock()
	defer state.DstLock.Unlock()

	if len(policy.Destination.Labels.Equal) < 1 {
		return
	}

	ls := &matchLabels.LabelSet{
		Name:   uid,
		Labels: policy.Destination.Labels.Equal,
		Policy: policy,
		Ports:  policy.Destination.Ports,
	}

	state.Dst.Add(ls)
}

// Create SrcMatchLAbelsPolicy to add new Network Policy
func (state *PolicyState) CreateSrcMatchLabelsPolicy(uid string, policy *types.TetragonNetworkPolicy) {
	state.SrcLock.Lock()
	defer state.SrcLock.Unlock()

	ls := &matchLabels.LabelSet{
		Name:   uid,
		Labels: policy.Subject.Labels.Equal,
		Policy: policy,
	}

	state.Src.Add(ls)
}

// Create L3NetworkPolicy to add a new logical network policy
func (state *PolicyState) CreateNetworkPolicy(uid string, policy *types.TetragonNetworkPolicy) error {
	state.L3Lock.Lock()
	defer state.L3Lock.Unlock()

	labels := make(map[string]string)
	if policy.Subject.LogicalNetwork.VLAN != 0 {
		s := strconv.FormatUint(uint64(policy.Subject.LogicalNetwork.VLAN), 10)
		labels["vlan"] = s
	} else {
		labels["vrf"] = policy.Subject.LogicalNetwork.VRF
	}

	ls := &matchLabels.LabelSet{
		Name:   uid,
		Labels: labels,
		Policy: policy,
	}

	if policy.Subject.LogicalNetwork.VLAN != 0 {
		return fmt.Errorf("l2 not implemented") //state.L2.Add(uid, ls)
	}

	state.L3.Add(ls)
	return nil
}

func (state *PolicyState) CreateMatchLabelsPolicy(uid string, policy *types.TetragonNetworkPolicy) error {
	// This is a L3 or L2 network firewall policy. For now we handle
	// it here as a special case.
	if policy.Source != nil {
		state.CreateNetworkPolicy(uid, policy)
	}

	if len(policy.Destination.Labels.Equal) > 0 {
		state.CreateDstMatchLabelsPolicy(uid, policy)
	}

	// There are a few possibilities for possible scope.
	// 0. MatchLabels is set then we use this otherwise,
	// 1. fully specified namespace:workload:kind
	// 2. namespace scoped policy e.g. just namespace
	// 3. host scope, no namespace
	if len(policy.Subject.Labels.Equal) > 0 {
		state.CreateSrcMatchLabelsPolicy(uid, policy)
	}

	return nil
}

func (state *PolicyState) getAllExistingPolicy() []*types.TetragonNetworkPolicy {
	uniquePolicyMap := make(map[string]*types.TetragonNetworkPolicy)
	allPolicy := make([]*types.TetragonNetworkPolicy, 0)

	for _, p := range state.Src {
		if _, ok := uniquePolicyMap[p.Name]; !ok {
			uniquePolicyMap[p.Name] = p.Policy
			allPolicy = append(allPolicy, p.Policy)
		}
	}
	for _, p := range state.Dst {
		if _, ok := uniquePolicyMap[p.Name]; !ok {
			uniquePolicyMap[p.Name] = p.Policy
			allPolicy = append(allPolicy, p.Policy)
		}
	}
	for _, p := range state.L3 {
		if _, ok := uniquePolicyMap[p.Name]; !ok {
			uniquePolicyMap[p.Name] = p.Policy
			allPolicy = append(allPolicy, p.Policy)
		}
	}
	return allPolicy
}

func (state *PolicyState) GetRecords(currentPolicy []*types.TetragonNetworkPolicy) (*PolicyState, []*record.DatapathRecord, error) {
	calculatorRecords := []*record.DatapathRecord{}
	calculatorState := NewPolicyState()

	uidGenerator := make(map[string]int, len(currentPolicy))

	// Add Policy to calculator state
	for _, p := range currentPolicy {
		id, ok := uidGenerator[p.Name]
		if !ok {
			id = 0
			uidGenerator[p.Name] = 0
		} else {
			id++
			uidGenerator[p.Name] = id
		}

		uid := fmt.Sprintf("%s_%d", p.Name, id)
		library.GetRepository().Link(p.Name, uid)
		err := calculatorState.CreateMatchLabelsPolicy(uid, p)
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

	for k, uid := range state.networkL3Objects {
		calculatorState.networkL3Objects[k] = uid
		r, err := calculatorState.l3Add(k)
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
	postState.networkL3Objects = maps.Clone(preState.networkL3Objects)
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
func RemoveNetworkPolicySet(name string, policy []*types.TetragonNetworkPolicy) error {
	s := GetRealizedState()

	for i, p := range policy {
		uid := fmt.Sprintf("%s_%d", name, i)
		err := s.RemoveMatchLabelNetworkPolicy(uid, p)
		if err != nil {
			return err
		}
		library.GetRepository().DelLink(uid)
	}
	return nil
}
