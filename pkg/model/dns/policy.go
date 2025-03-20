package dns

import (
	"fmt"
	"strings"

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
	if err := prog.AddRecords(records); err != nil {
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
				Type: endpoint.DnsType,
				Dns:  entry,
			}
			record := &record.DatapathRecord{
				Src: src,
				EP:  ep,
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
		}).Info("TCP quota removed")
	}

	ls, ok := state.Dst[name]
	if !ok {
		return nil
	}

	for _, ep := range ls.Endpoints {
		record := &record.DatapathRecord{
			Src: src,
			EP:  ep,
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
		}).Info("TCP DNS labels endpoint quota removed")
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

func (state *PolicyState) __RemoveMatchLabelNetworkPolicy(uid string, policy *types.TetragonNetworkPolicy) ([]*record.DatapathRecord, error) {
	state.SrcLock.Lock()
	defer state.SrcLock.Unlock()

	subject := state.Src[uid]
	dest := state.Dst[uid]

	var beforeSubjs []*record.DatapathRecord
	var beforeDests []*record.DatapathRecord
	var afterSubjs []*record.DatapathRecord
	var afterDests []*record.DatapathRecord

	dstLabels := &matchLabels.LabelSet{
		Label:  policy.Destination.Labels.Equal,
		Policy: policy,
	}

	subjectLabels := &matchLabels.LabelSet{
		Label:  policy.Subject.MatchLabelsEqual,
		Policy: policy,
	}

	if subject != nil {
		for _, s := range subject.Subjects {
			beforeSubjs = state.SrcAdd(s, subjectLabels)
		}
	}

	if dest != nil {
		for _, ep := range dest.Endpoints {
			beforeDests = state.EndpointAdd(ep, dstLabels)
		}
	}

	state.Src.Remove(uid)
	state.Dst.Remove(uid)

	if subject != nil {
		for _, s := range subject.Subjects {
			afterSubjs = state.SrcAdd(s, subjectLabels)
		}
	}

	if dest != nil {
		for _, ep := range dest.Endpoints {
			afterDests = state.EndpointAdd(ep, dstLabels)
		}
	}

	beforeJoin := append(beforeSubjs, beforeDests...)
	afterJoin := append(afterSubjs, afterDests...)

	// A key that exists only in the beforeJoin can be deleted because
	// nothing is referencing that key anymore. To unwind this we will
	// do the following: first find set of rules that can be deleted
	// called ZombieSet here, update the existing rules in afterJoin,
	// and finally remove the ZombieSet.
	zombieSet := record.Diff(beforeJoin, afterJoin)
	return zombieSet, nil
}

func (state *PolicyState) RemoveMatchLabelNetworkPolicy(uid string, policy *types.TetragonNetworkPolicy) error {
	zombieSet, err := state.__RemoveMatchLabelNetworkPolicy(uid, policy)
	if err != nil {
		return err
	}
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

	if policy.Destination.FQDN != nil {
		for _, entry := range policy.Destination.FQDN.Names {
			ep := &endpoint.Endpoint{
				Type: endpoint.DnsType,
				Dns:  entry,
			}
			records = append(records, &record.DatapathRecord{
				Src:    src,
				EP:     ep,
				Action: action,
				Init:   init,
			})
		}
	}

	ls := state.Dst[uid]
	if ls != nil {
		for _, ep := range ls.Endpoints {
			records = append(records, &record.DatapathRecord{
				Src:    src,
				EP:     ep,
				Action: action,
				Init:   init,
			})
		}
	}

	// Append the default record for the Pod layer
	dfltRecord := &record.DatapathRecord{
		Src:    src,
		EP:     nil,
		Action: dfltAction,
		Init:   init,
	}
	records = append(records, dfltRecord)

	return records, nil
}

// Create DstMatchLAbelsPolicy to add new Network Policy
func (state *PolicyState) CreateDstMatchLabelsPolicy(uid string, policy *types.TetragonNetworkPolicy) error {
	state.DstLock.Lock()
	defer state.DstLock.Unlock()

	if len(policy.Destination.Labels.Equal) < 1 {
		return nil
	}

	ls := &matchLabels.LabelSet{
		Name:   uid,
		Label:  policy.Destination.Labels.Equal,
		Policy: policy,
	}

	state.Dst.Add(uid, ls)
	return nil
}

// Create SrcMatchLAbelsPolicy to add new Network Policy
func (state *PolicyState) CreateSrcMatchLabelsPolicy(uid string, policy *types.TetragonNetworkPolicy) error {
	state.SrcLock.Lock()
	defer state.SrcLock.Unlock()

	ls := &matchLabels.LabelSet{
		Name:   uid,
		Label:  policy.Subject.MatchLabelsEqual,
		Policy: policy,
	}

	state.Src.Add(uid, ls)
	return nil
}

func (state *PolicyState) CreateMatchLabelsPolicy(uid string, policy *types.TetragonNetworkPolicy) error {
	if len(policy.Destination.Labels.Equal) > 0 {
		err := state.CreateDstMatchLabelsPolicy(uid, policy)
		if err != nil {
			return err
		}
	}

	// There are a few possibilities for possible scope.
	// 0. MatchLabels is set then we use this otherwise,
	// 1. fully specified namespace:workload:kind
	// 2. namespace scoped policy e.g. just namespace
	// 3. host scope, no namespace
	if len(policy.Subject.MatchLabelsEqual) > 0 {
		return state.CreateSrcMatchLabelsPolicy(uid, policy)
	}
	return nil
}

// Entry point to Policy state create
func CreateMatchLabelsPolicySet(name string, policy []*types.TetragonNetworkPolicy) error {
	s := GetRealizedState()

	for i, p := range policy {
		uid := fmt.Sprintf("%s_%d", name, i)
		err := s.CreateMatchLabelsPolicy(uid, p)
		if err != nil {
			return err
		}
	}
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
