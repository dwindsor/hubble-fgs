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
	"strings"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

type SwitchPolicy struct {
	UID    UniqueID
	Policy *SmartSwitchNetworkPolicy
}

type diffToApply struct {
	toAdd map[RuleID]*DPUPolicyRule
	toDel map[RuleID]*DPUPolicyRule
}

func newDiffToApply() diffToApply {
	return diffToApply{
		toAdd: make(map[RuleID]*DPUPolicyRule),
		toDel: make(map[RuleID]*DPUPolicyRule),
	}
}

func (d *diffToApply) getDiff() []*DPUPolicyRule {
	diff := make([]*DPUPolicyRule, 0, len(d.toAdd)+len(d.toDel))
	for _, rule := range d.toAdd {
		diff = append(diff, rule)
	}
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

	// nextID generates unique RuleIDs for replacement rules during VRF GID changes
	nextID func() RuleID
}

// uniqueVRFs returns [src] if src==dst, otherwise [src, dst].
func uniqueVRFs(src, dst VrfName) []VrfName {
	if src == dst {
		return []VrfName{src}
	}
	return []VrfName{src, dst}
}

func NewState(nextID func() RuleID) *State {
	return &State{
		policyByRuleId:   make(map[RuleID]*SwitchPolicy),
		policyByVRFName:  make(map[VrfName]map[RuleID]*SwitchPolicy),
		diff:             newDiffToApply(),
		networkL3Objects: NewL3Networks(),
		nextID:           nextID,
	}
}

func (s *State) RemoveRuleByID(id RuleID) error {
	existingPolicy, ok := s.policyByRuleId[id]
	if !ok {
		return fmt.Errorf("rule with id %d does not exist", id)
	}

	delete(s.policyByRuleId, id)
	if existingPolicy.Policy != nil {
		srcVRF := VrfName(existingPolicy.Policy.Source.Endpoint.VRF)
		dstVRF := VrfName(existingPolicy.Policy.Destination.Endpoint.VRF)
		for _, vrfName := range uniqueVRFs(srcVRF, dstVRF) {
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

	srcVRF := VrfName(policy.Policy.Source.Endpoint.VRF)
	dstVRF := VrfName(policy.Policy.Destination.Endpoint.VRF)
	for _, vrfName := range uniqueVRFs(srcVRF, dstVRF) {
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

func (s *State) SetL3Networks(l3 *L3Networks) (map[RuleID]RuleID, error) {
	// Detect VRF GID changes (same name, different GID)
	changed := make(map[VrfName]VrfGID)
	for vrfName, newGID := range l3.byName {
		if oldGID, ok := s.networkL3Objects.byName[vrfName]; ok && oldGID != newGID {
			changed[vrfName] = newGID
		}
	}

	// Check for GID conflicts with unchanged VRFs
	for vrfName, gid := range l3.byName {
		if _, isChanged := changed[vrfName]; isChanged {
			continue
		}
		if existingName, ok := s.networkL3Objects.byGID[gid]; ok {
			if existingName != vrfName {
				// Only error if the conflicting VRF is not also being changed
				if _, alsoChanged := changed[existingName]; !alsoChanged {
					return nil, fmt.Errorf("L3 network with GID %d already exists with different name %s (new name %s)", gid, existingName, vrfName)
				}
			}
		}
	}

	// Process VRF GID changes
	var idChanges map[RuleID]RuleID
	if len(changed) > 0 {
		// Collect affected rules per VRF before modifying anything.
		// A rule may reference multiple changed VRFs (src and dst), so
		// deduplicate by RuleID to avoid processing the same rule twice.
		affectedByID := make(map[RuleID]*SwitchPolicy)
		for vrfName := range changed {
			for ruleId, rule := range s.policyByVRFName[vrfName] {
				affectedByID[ruleId] = rule
			}
		}

		// Generate DELETE diffs using OLD GIDs (L3Networks still has old mapping)
		for ruleId, rule := range affectedByID {
			oldConverted := s.convertRuleToDPUPolicyRule(rule, false)
			if oldConverted != nil {
				s.diff.Del(ruleId, oldConverted)
			}
		}

		// Update L3Networks mapping: remove all changed first, then re-add (handles swaps)
		for vrfName := range changed {
			s.networkL3Objects.Remove(vrfName)
		}
		for vrfName, newGID := range changed {
			if err := s.networkL3Objects.Add(vrfName, newGID); err != nil {
				return nil, fmt.Errorf("failed to update L3 network %s to GID %d: %w", vrfName, newGID, err)
			}
		}

		// Generate ADD diffs using NEW GIDs with new RuleIDs
		idChanges = make(map[RuleID]RuleID)
		for oldRuleId, rule := range affectedByID {
			newRuleId := s.nextID()

			// Update policyByRuleId
			delete(s.policyByRuleId, oldRuleId)
			s.policyByRuleId[newRuleId] = rule

			// Update policyByVRFName references
			srcVRF := VrfName(rule.Policy.Source.Endpoint.VRF)
			dstVRF := VrfName(rule.Policy.Destination.Endpoint.VRF)
			for _, vrfName := range uniqueVRFs(srcVRF, dstVRF) {
				if vrfRules, ok := s.policyByVRFName[vrfName]; ok {
					delete(vrfRules, oldRuleId)
					vrfRules[newRuleId] = rule
				}
			}

			// Update the UID's RuleName to reflect the new RuleID.
			// The DELETE diff was already generated with the old RuleName.
			// RuleName format is "baseName/ruleId" — replace the suffix.
			if idx := strings.LastIndex(rule.UID.RuleName, "/"); idx >= 0 {
				rule.UID.RuleName = fmt.Sprintf("%s/%d", rule.UID.RuleName[:idx], newRuleId)
			}

			newConverted := s.convertRuleToDPUPolicyRule(rule, true)
			if newConverted != nil {
				s.diff.Add(newRuleId, newConverted)
			}

			idChanges[oldRuleId] = newRuleId
		}
	}

	// Handle new VRFs (not already in networkL3Objects)
	for vrfName, gid := range l3.byName {
		if _, ok := s.networkL3Objects.byName[vrfName]; !ok {
			if err := s.networkL3Objects.Add(vrfName, gid); err != nil {
				return nil, fmt.Errorf("failed to add L3 network %s: %w", vrfName, err)
			}
			for ruleId, rule := range s.policyByVRFName[vrfName] {
				converted := s.convertRuleToDPUPolicyRule(rule, true)
				if converted != nil {
					s.diff.Add(ruleId, converted)
				}
			}
		}
	}

	// Handle removed VRFs (in current but not in incoming)
	for vrfName := range s.networkL3Objects.byName {
		if _, ok := l3.byName[vrfName]; !ok {
			for ruleId, rule := range s.policyByVRFName[vrfName] {
				converted := s.convertRuleToDPUPolicyRule(rule, false)
				if converted != nil {
					s.diff.Del(ruleId, converted)
				}
			}
			if err := s.networkL3Objects.Remove(vrfName); err != nil {
				return nil, fmt.Errorf("failed to remove L3 network %s: %w", vrfName, err)
			}
		}
	}

	return idChanges, nil
}

func (s *State) AddL3Network(name VrfName, gid VrfGID) (map[RuleID]RuleID, error) {
	err := s.networkL3Objects.Add(name, gid)
	if err != nil {
		return nil, err
	}
	return s.SetL3Networks(s.networkL3Objects)
}

func (s *State) RemoveL3Network(name VrfName) (map[RuleID]RuleID, error) {
	err := s.networkL3Objects.Remove(name)
	if err != nil {
		return nil, err
	}
	return s.SetL3Networks(s.networkL3Objects)
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
