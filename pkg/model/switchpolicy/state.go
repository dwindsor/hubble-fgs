// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package switchpolicy

import (
	"fmt"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

type SwitchPolicy struct {
	UID    UniqueID
	Policy *SmartSwitchNetworkPolicy
}

type diffToApply struct {
	toAdd        map[RuleID]*DPUPolicyRule
	toDel        map[RuleID]*DPUPolicyRule
	staleDeletes []*DPUPolicyRule // old-VRF-ID cleanups from GID changes
}

func newDiffToApply() diffToApply {
	return diffToApply{
		toAdd: make(map[RuleID]*DPUPolicyRule),
		toDel: make(map[RuleID]*DPUPolicyRule),
	}
}

func (d *diffToApply) getDiff() []*DPUPolicyRule {
	diff := make([]*DPUPolicyRule, 0, len(d.toAdd)+len(d.staleDeletes)+len(d.toDel))
	for _, rule := range d.toAdd {
		diff = append(diff, rule)
	}
	diff = append(diff, d.staleDeletes...)
	for _, rule := range d.toDel {
		diff = append(diff, rule)
	}
	return diff
}

func (d *diffToApply) Add(id RuleID, rule *DPUPolicyRule) {
	d.toAdd[id] = rule
	delete(d.toDel, id)
}

func (d *diffToApply) Del(id RuleID, rule *DPUPolicyRule) {
	d.toDel[id] = rule
	delete(d.toAdd, id)
}

type State struct {
	// Current state
	policyByRuleId  map[RuleID]*SwitchPolicy
	policyByVRFName map[VrfName]map[RuleID]*SwitchPolicy

	networkL3Objects *L3Networks

	// Delta to apply
	diff diffToApply
}

func NewState() *State {
	return &State{
		policyByRuleId:   make(map[RuleID]*SwitchPolicy),
		policyByVRFName:  make(map[VrfName]map[RuleID]*SwitchPolicy),
		diff:             newDiffToApply(),
		networkL3Objects: NewL3Networks(),
	}
}

func (s *State) RemoveRuleByID(id RuleID) error {
	existingPolicy, ok := s.policyByRuleId[id]
	if !ok {
		return fmt.Errorf("rule with id %d does not exist", id)
	}

	delete(s.policyByRuleId, id)
	if existingPolicy.Policy != nil {
		vrfNames := []VrfName{
			VrfName(existingPolicy.Policy.Source.Endpoint.VRF),
			VrfName(existingPolicy.Policy.Destination.Endpoint.VRF),
		}
		seen := make(map[VrfName]struct{}, len(vrfNames))
		for _, vrfName := range vrfNames {
			if _, ok := seen[vrfName]; ok {
				continue
			}
			seen[vrfName] = struct{}{}

			if vrfRules, ok := s.policyByVRFName[vrfName]; ok {
				delete(vrfRules, id)
				if len(vrfRules) == 0 {
					delete(s.policyByVRFName, vrfName)
				}
			}
		}
	} else {
		return fmt.Errorf("cannot remove rule with id %d: policy is nil", id)
	}
	converted := s.convertRuleToDPUPolicyRule(existingPolicy, false)
	if converted != nil {
		s.diff.Del(id, converted)
	}
	return nil
}

func (s *State) AddRule(id RuleID, policy *SwitchPolicy) error {
	if _, ok := s.policyByRuleId[id]; ok {
		return fmt.Errorf("rule with id %d already exists", id)
	}
	if policy.Policy == nil {
		return fmt.Errorf("cannot add rule with id %d: policy is nil", id)
	}
	s.policyByRuleId[id] = policy

	vrfNames := []VrfName{
		VrfName(policy.Policy.Source.Endpoint.VRF),
		VrfName(policy.Policy.Destination.Endpoint.VRF),
	}
	seen := make(map[VrfName]struct{}, len(vrfNames))
	for _, vrfName := range vrfNames {
		if _, ok := seen[vrfName]; ok {
			continue
		}
		seen[vrfName] = struct{}{}

		if _, ok := s.policyByVRFName[vrfName]; !ok {
			s.policyByVRFName[vrfName] = make(map[RuleID]*SwitchPolicy)
		}
		s.policyByVRFName[vrfName][id] = policy
	}
	converted := s.convertRuleToDPUPolicyRule(policy, true)
	if converted != nil {
		s.diff.Add(id, converted)
	}

	return nil
}

func (s *State) SetL3Networks(l3 *L3Networks) error {
	added, removed, changed := s.networkL3Objects.Diff(l3)

	// Phase 1: For changed GIDs, generate stale DELETEs using the current
	// (old) GID before the mapping is updated. This ensures the hardware
	// entry for the old VRF ID is cleaned up after the new one is installed.
	for vrfName := range changed {
		for _, rule := range s.policyByVRFName[vrfName] {
			oldDel := s.convertRuleToDPUPolicyRule(rule, false)
			if oldDel != nil {
				s.diff.staleDeletes = append(s.diff.staleDeletes, oldDel)
			}
		}
	}

	// Phase 2: Apply all L3Networks changes atomically.
	// Remove changed VRFs first to free their old GIDs (handles GID swaps).
	for vrfName := range changed {
		//nolint:errcheck // vrfName comes from Diff(), guaranteed to exist
		s.networkL3Objects.Remove(vrfName)
	}
	// Remove deleted VRFs and generate regular DELETEs.
	for vrfName := range removed {
		for ruleId, rule := range s.policyByVRFName[vrfName] {
			del := s.convertRuleToDPUPolicyRule(rule, false)
			if del != nil {
				s.diff.Del(ruleId, del)
			}
		}
		//nolint:errcheck // vrfName comes from Diff(), guaranteed to exist
		s.networkL3Objects.Remove(vrfName)
	}
	// Add changed VRFs with their new GIDs.
	for vrfName, change := range changed {
		//nolint:errcheck // newGID uniqueness guaranteed by incoming L3Networks
		s.networkL3Objects.Add(vrfName, change.NewGID)
	}
	// Add new VRFs.
	for vrfName, gid := range added {
		if err := s.networkL3Objects.Add(vrfName, gid); err != nil {
			return fmt.Errorf("failed to add L3 network %s: %w", vrfName, err)
		}
	}

	// Phase 3: Generate UPSERTs with new VrfIds (after mapping is updated).
	for vrfName := range changed {
		for ruleId, rule := range s.policyByVRFName[vrfName] {
			upsert := s.convertRuleToDPUPolicyRule(rule, true)
			if upsert != nil {
				s.diff.Add(ruleId, upsert)
			}
		}
	}
	for vrfName := range added {
		for ruleId, rule := range s.policyByVRFName[vrfName] {
			upsert := s.convertRuleToDPUPolicyRule(rule, true)
			if upsert != nil {
				s.diff.Add(ruleId, upsert)
			}
		}
	}

	return nil
}

func (s *State) GetDeltaToApply() []*DPUPolicyRule {
	delta := s.diff.getDiff()

	s.diff = newDiffToApply()
	return delta
}

// GetL3Networks returns a copy of the current L3 networks (safe to modify)
func (s *State) GetL3Networks() *L3Networks {
	return s.networkL3Objects.Copy()
}

func (s *State) convertRuleToDPUPolicyRule(rule *SwitchPolicy, upsert bool) *DPUPolicyRule {
	var operation v1alpha.PolicyOperation
	if upsert {
		operation = v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT
	} else {
		operation = v1alpha.PolicyOperation_POLICY_OPERATION_DELETE
	}

	var action v1alpha.PolicyAction
	if rule.Policy.Action.EnforceAction.Allow {
		action = v1alpha.PolicyAction_POLICY_ACTION_ALLOW
	} else if rule.Policy.Action.EnforceAction.Deny {
		action = v1alpha.PolicyAction_POLICY_ACTION_DENY
	} else {
		action = v1alpha.PolicyAction_POLICY_ACTION_UNSPECIFIED
	}
	sourceVRFId, ok := s.networkL3Objects.byName[VrfName(rule.Policy.Source.Endpoint.VRF)]
	if !ok {
		return nil
	}
	destinationVRFId, ok := s.networkL3Objects.byName[VrfName(rule.Policy.Destination.Endpoint.VRF)]
	if !ok {
		return nil
	}

	return &DPUPolicyRule{
		Oper: operation,
		Policy: &DPURule{
			K8SResourceVersion: rule.Policy.K8SResourceVersion,
			K8SUid:             rule.Policy.K8SUid,
			K8SIndex:           rule.Policy.K8SIndex,
			PolicyName:         rule.UID.PolicyName,
			RuleName:           rule.UID.RuleName,
			Action:             action,
			Source: DPUSubject{
				Cidr:  rule.Policy.Source.Endpoint.CIDR,
				Ports: nil,
				Vlan:  uint32(rule.Policy.Source.Endpoint.VLAN),
				Vrf:   rule.Policy.Source.Endpoint.VRF,
				VrfId: uint32(sourceVRFId),
			},
			// The current policy resolution does not include destination
			// Vlan and VRF this will be added soon.
			Destination: DPUSubject{
				Cidr:  rule.Policy.Destination.Endpoint.CIDR,
				Ports: rule.Policy.Destination.ProtoPorts,
				Vlan:  uint32(rule.Policy.Destination.Endpoint.VLAN),
				Vrf:   rule.Policy.Destination.Endpoint.VRF,
				VrfId: uint32(destinationVRFId),
			},
		},
	}
}
