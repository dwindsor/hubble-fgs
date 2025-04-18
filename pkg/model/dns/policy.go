package dns

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/matchLabels"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/sirupsen/logrus"
)

// Legacy workload add for FQDN quota policy soon to be removed
func AddNetworkPolicy(policy *types.TetragonNetworkPolicy, init bool) error {
	// The matchLabels case and wl="",kind="" case will fall throuh to queueWorkloadQuotaPolicy
	src, err := createSrcPolicy(policy)
	if err != nil {
		return err
	}
	if src == nil {
		return nil
	}

	records, err := GetRealizedState().AddSrcPolicy(policy.Name, src, policy, init)
	if err != nil {
		return err
	}
	if err := prog.AddRecords(records, false); err != nil {
		return err
	}

	return nil
}

func queueWorkloadNetworkPolicy(policy *types.TetragonNetworkPolicy) {
	queueWl[policy.Subject.Workload] = policy
}

func QueueWorkloadNetworkPolicy(policy *types.TetragonNetworkPolicy) {
	queueWlLock.Lock()
	queueWorkloadNetworkPolicy(policy)
	queueWlLock.Unlock()
}

func (state *PolicyState) progRemoveNetworkPolicy(name string, src *types.ProcessTreeKey, d *types.TetragonNetworkDestination) error {
	var err error

	if d.FQDN != nil {
		for _, entry := range d.FQDN.Names {
			ep := &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_DNS,
				Dns:  entry,
			}
			endpoint := record.DatapathEndpoint{
				EP:   ep,
				Port: 0,
			}
			record := &record.DatapathRecord{
				Src:      src,
				Endpoint: endpoint,
			}
			if err := prog.RemoveSingleRecord(record); err != nil {
				logger.GetLogger().WithFields(logrus.Fields{
					"cgid": src.CgroupId,
					"self": src.Self,
					"dest": entry,
				}).WithError(err).Error("TCP quota remove Failed")
			}
		}
		logger.GetLogger().WithFields(logrus.Fields{
			"cgid": src.CgroupId,
			"self": src.Self,
			"dest": strings.Join(d.FQDN.Names, " "),
		}).Debug("TCP quota removed")
	}

	ls, ok := state.Dst[name]
	if !ok {
		return nil
	}

	for _, ep := range ls.Endpoints {
		endpoint := record.DatapathEndpoint{
			EP:   ep,
			Port: 0,
		}
		record := &record.DatapathRecord{
			Src:      src,
			Endpoint: endpoint,
		}
		if prog.RemoveSingleRecord(record); err != nil {
			logger.GetLogger().WithFields(logrus.Fields{
				"cgid": src.CgroupId,
				"self": src.Self,
			}).WithError(err).Error("TCP quota labels endpoint remove Failed")
			continue
		}
		logger.GetLogger().WithFields(logrus.Fields{
			"cgid": src.CgroupId,
			"self": src.Self,
		}).Debug("TCP DNS labels endpoint quota removed")
	}

	return nil
}

func (state *PolicyState) RemoveNetworkPolicy(name string, policy *types.TetragonNetworkPolicy) error {
	queueWlLock.Lock()
	defer queueWlLock.Unlock()

	s := &policy.Subject.Workload
	d := &policy.Destination

	delete(queueWl, policy.Subject.Workload)

	src, err := createSrcKey(s.Namespace, s.Name, s.Kind)
	if err != nil {
		// Remove should not throw an error if the policy doesn't exist
		return nil
	}
	if src == nil {
		return nil
	}

	return state.progRemoveNetworkPolicy(name, src, d)
}

func (state *PolicyState) removeMatchLabelNetworkPolicy(uid string, policy *types.TetragonNetworkPolicy) ([]*record.DatapathRecord, []*record.DatapathRecord, error) {
	state.SrcLock.Lock()
	defer state.SrcLock.Unlock()

	subject := state.Src[uid]

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

	state.Src.Remove(uid)
	state.Dst.Remove(uid)

	for _, v := range state.Src {
		if v == nil {
			continue
		}
		for _, src := range v.Subjects {
			sRecords, err := state.AddSrcPolicy(v.Name, src, v.Policy, true)
			if err != nil {
				logger.GetLogger().WithField("src", src).WithError(err).Warn("AddSrcPolicy error")
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

func createSrcPolicy(policy *types.TetragonNetworkPolicy) (*types.ProcessTreeKey, error) {
	queueWlLock.Lock()
	defer queueWlLock.Unlock()

	s := &policy.Subject.Workload

	src, err := createSrcKey(s.Namespace, s.Name, s.Kind)
	if err != nil {
		return nil, err
	}

	// If the src does not yet exist we watch for it and create the policy
	// once an ID has been generated.
	if src == nil {
		queueWorkloadNetworkPolicy(policy)
		return nil, nil
	}
	return src, nil
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
			logger.GetLogger().WithError(err).Warn("Unable to get policyfilter")
			return nil, err
		}
		// If the ID does not yet exist we need to wait for it to be added. This is
		// an imperfect solution. Ideally we would just modify the policyfilter state
		// to preallocate an ID.But, its in OSS and not obvious how to extend it to
		// support this.
		nsId, ok = state.GetIdNs(workload)
		if !ok {
			logger.GetLogger().WithField("namespace", namespace).WithField("workload", wl).Debug("workload info does not exist yet, queuing for workload updates.")
			return nil, nil
		}
	} else {
		nsId = policyfilter.StateID(0)
	}

	return &types.ProcessTreeKey{
		CgroupId: uint64(nsId),
		Depth:    0,
		Self:     0,
		Path:     [8]uint64{0, 0, 0, 0, 0, 0, 0, 0},
	}, nil
}

func (state *PolicyState) policyDestRecords(uid string, src *types.ProcessTreeKey, action *record.DatapathAction, policy *types.TetragonNetworkPolicy, init bool) []*record.DatapathRecord {
	records := []*record.DatapathRecord{}

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

func (state *PolicyState) AddSrcPolicy(uid string, src *types.ProcessTreeKey, policy *types.TetragonNetworkPolicy, init bool) ([]*record.DatapathRecord, error) {
	records := []*record.DatapathRecord{}

	dfltAction, err := calculateAction(&policy.Default)
	if err != nil {
		logger.GetLogger().WithFields(logrus.Fields{
			"uid":    uid,
			"name":   policy.Name,
			"action": policy.Action,
		}).WithError(err).Error("policy has unsupported or invalid default action")
		return records, err
	}

	action, err := calculateAction(&policy.Action)
	if err != nil {
		logger.GetLogger().WithFields(logrus.Fields{
			"uid":    uid,
			"name":   policy.Name,
			"action": policy.Action,
		}).WithError(err).Error("policy has unsupported or invalid action")
		return records, err
	}

	// Records are mapped to the datapath. We need a distinct record
	// for each process or lack of processSelector simply apply to
	// the entire pod.
	if len(policy.Subject.InProcessName) > 0 {
		for _, process := range policy.Subject.InProcessName {
			self, err := prog.GetBinaryId(process)
			if err != nil {
				logger.GetLogger().WithFields(logrus.Fields{
					"uid":     uid,
					"process": process,
				}).WithError(err).Warn("Failed to create record")
				return records, err
			}

			processSrc := &types.ProcessTreeKey{
				CgroupId: src.CgroupId,
				Depth:    0,
				Self:     self,
				Path:     [8]uint64{0, 0, 0, 0, 0, 0, 0, 0},
			}

			r := state.policyDestRecords(uid, processSrc, action, policy, init)
			records = append(records, r...)
		}
	} else {
		r := state.policyDestRecords(uid, src, action, policy, init)
		records = append(records, r...)
	}

	// Append the default record for the Pod layer
	endpoint := record.DatapathEndpoint{
		EP:   nil,
		Port: 0,
	}
	dfltRecord := &record.DatapathRecord{
		Src:      src,
		Endpoint: endpoint,
		Action:   dfltAction,
		Init:     init,
	}
	records = append(records, dfltRecord)

	return records, nil
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

	state.Dst.Add(uid, ls)
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

	state.Src.Add(uid, ls)
}

func (state *PolicyState) CreateMatchLabelsPolicy(uid string, policy *types.TetragonNetworkPolicy) error {
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
	return allPolicy
}

// createMatchLabelsPolicySet computes the records generated from the current
// state and policies, then computes the records generated from a fresh state
// contaning the current and new policies. It then returns the new state, the
// records to add and the records to remove (which are the diff between the
// current computed records and the new ones).
func createMatchLabelsPolicySet(policy []*types.TetragonNetworkPolicy) (*PolicyState, []*record.DatapathRecord, []*record.DatapathRecord, error) {
	// Entry point to Policy state create
	// Collect existing policy set
	currentState := GetRealizedState()
	currentPolicy := currentState.getAllExistingPolicy()

	calculatorRecords := []*record.DatapathRecord{}
	calculatorState := NewPolicyState()

	for _, p := range currentState.localObjects {
		r, err := calculatorState.objectAdd(p)
		if err != nil {
			return nil, nil, nil, err
		}
		calculatorRecords = append(calculatorRecords, r...)
	}

	for _, p := range currentState.remoteObjects {
		r, err := calculatorState.objectAdd(p)
		if err != nil {
			return nil, nil, nil, err
		}
		calculatorRecords = append(calculatorRecords, r...)
	}

	// Building new state with extended policy set
	newState := NewPolicyState()
	allPolicy := append(currentPolicy, policy...)
	uidGenerator := make(map[string]int, len(allPolicy))

	for _, p := range allPolicy {
		id, ok := uidGenerator[p.Name]
		if !ok {
			id = 0
			uidGenerator[p.Name] = 0
		} else {
			id++
			uidGenerator[p.Name] = id
		}

		uid := fmt.Sprintf("%s_%d", p.Name, id)
		err := newState.CreateMatchLabelsPolicy(uid, p)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	// Walk existing pods and create new []record from new policy
	addRecordsSet := []*record.DatapathRecord{}
	for _, p := range currentState.localObjects {
		r, err := newState.objectAdd(p)
		if err != nil {
			return nil, nil, nil, err
		}
		addRecordsSet = append(addRecordsSet, r...)
	}
	for _, p := range currentState.remoteObjects {
		r, err := newState.objectAdd(p)
		if err != nil {
			return nil, nil, nil, err
		}
		addRecordsSet = append(addRecordsSet, r...)
	}

	// If the record no longer exists remove it.
	removeRecordsSet := record.Diff(calculatorRecords, addRecordsSet)
	return newState, addRecordsSet, removeRecordsSet, nil
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
		err := s.RemoveNetworkPolicy(uid, p)
		if err != nil {
			return err
		}
		err = s.RemoveMatchLabelNetworkPolicy(uid, p)
		if err != nil {
			return err
		}
	}
	return nil
}
