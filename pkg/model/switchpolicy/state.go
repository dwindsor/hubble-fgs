package switchpolicy

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
)

type SwitchPolicy struct {
	UID    UniqueID
	Policy *SmartSwitchNetworkPolicy
}

type diffToApply struct {
	toAdd map[ruleID]*dpu.DPUPolicyRule
	toDel map[ruleID]*dpu.DPUPolicyRule
}

func newDiffToApply() diffToApply {
	return diffToApply{
		toAdd: make(map[ruleID]*dpu.DPUPolicyRule),
		toDel: make(map[ruleID]*dpu.DPUPolicyRule),
	}
}

func (d *diffToApply) getDiff() []*dpu.DPUPolicyRule {
	diff := make([]*dpu.DPUPolicyRule, 0, len(d.toAdd)+len(d.toDel))
	for _, rule := range d.toAdd {
		diff = append(diff, rule)
	}
	for _, rule := range d.toDel {
		diff = append(diff, rule)
	}
	return diff
}

func (d *diffToApply) Add(id ruleID, rule *dpu.DPUPolicyRule) {
	d.toAdd[id] = rule
	delete(d.toDel, id)
}

func (d *diffToApply) Del(id ruleID, rule *dpu.DPUPolicyRule) {
	d.toDel[id] = rule
	delete(d.toAdd, id)
}

type State struct {
	// Current state
	policyByRuleId  map[ruleID]*SwitchPolicy
	policyByVRFName map[VrfName]map[ruleID]*SwitchPolicy

	networkL3Objects *L3Networks

	// Delta to apply
	diff diffToApply
}

func NewState() *State {
	return &State{
		policyByRuleId:   make(map[ruleID]*SwitchPolicy),
		policyByVRFName:  make(map[VrfName]map[ruleID]*SwitchPolicy),
		diff:             newDiffToApply(),
		networkL3Objects: NewL3Networks(),
	}
}

func (s *State) RemoveRuleByID(id ruleID) error {
	existingPolicy, ok := s.policyByRuleId[id]
	if !ok {
		return fmt.Errorf("rule with id %d does not exist", id)
	}

	delete(s.policyByRuleId, id)
	if existingPolicy.Policy != nil {
		vrfName := VrfName(existingPolicy.Policy.Source.Endpoint.VRF)

		if vrfRules, ok := s.policyByVRFName[vrfName]; ok {
			delete(vrfRules, id)
			if len(vrfRules) == 0 {
				delete(s.policyByVRFName, vrfName)
			}
		} else {
			return fmt.Errorf("inconsistent state: rule with id %d exists but VRF mapping not found", id)
		}
	} else {
		return fmt.Errorf("cannot remove rule with id %d: policy is nil", id)
	}
	s.diff.Del(id, s.convertRuleToDPUPolicyRule(existingPolicy, false))

	return nil
}

func (s *State) AddRule(id ruleID, policy *SwitchPolicy) error {
	logger.GetLogger().Info("Adding rule to state", "id", id, "policy", policy)
	if _, ok := s.policyByRuleId[id]; ok {
		return fmt.Errorf("rule with id %d already exists", id)
	}
	if policy.Policy == nil {
		return fmt.Errorf("cannot add rule with id %d: policy is nil", id)
	}
	s.policyByRuleId[id] = policy

	vrfName := VrfName(policy.Policy.Source.Endpoint.VRF)
	if vrfName == "" {
		return fmt.Errorf("cannot add rule with id %d: VRF name is empty", id)
	}
	if _, ok := s.policyByVRFName[vrfName]; !ok {
		s.policyByVRFName[vrfName] = make(map[ruleID]*SwitchPolicy)
	}
	s.policyByVRFName[vrfName][id] = policy
	s.diff.Add(id, s.convertRuleToDPUPolicyRule(policy, true))

	return nil
}

func (s *State) SetL3Networks(l3 *L3Networks) error {
	for vrfName, gid := range l3.byName {
		if existingGid, ok := s.networkL3Objects.byName[vrfName]; ok {
			if existingGid != gid {
				return fmt.Errorf("L3 network with name %s already exists with different GID %d (new GID %d)", vrfName, existingGid, gid)
			}
		}
		if existingName, ok := s.networkL3Objects.byGID[gid]; ok {
			if existingName != vrfName {
				return fmt.Errorf("L3 network with GID %d already exists with different name %s (new name %s)", gid, existingName, vrfName)
			}
		}
	}

	for vrfName, gid := range l3.byName {
		if _, ok := s.networkL3Objects.byName[vrfName]; !ok {
			// New L3 network, add it
			if err := s.networkL3Objects.Add(vrfName, gid); err != nil {
				return fmt.Errorf("failed to add L3 network %s: %w", vrfName, err)
			}
			// Mark all rules for this VRF to be added
			for ruleId, rule := range s.policyByVRFName[vrfName] {
				s.diff.Add(ruleId, s.convertRuleToDPUPolicyRule(rule, true))
			}
		}
	}

	for vrfName := range s.networkL3Objects.byName {
		if _, ok := l3.byName[vrfName]; !ok {
			// L3 network was removed, delete it
			// First we need to prepare DPU rules
			for ruleId, rule := range s.policyByVRFName[vrfName] {
				s.diff.Del(ruleId, s.convertRuleToDPUPolicyRule(rule, false))
			}
			if err := s.networkL3Objects.Remove(vrfName); err != nil {
				return fmt.Errorf("failed to remove L3 network %s: %w", vrfName, err)
			}
		}
	}
	return nil
}

func (s *State) AddL3Network(name VrfName, gid VrfGID) error {
	err := s.networkL3Objects.Add(name, gid)
	if err != nil {
		return err
	}
	err = s.SetL3Networks(s.networkL3Objects)
	if err != nil {
		return err
	}
	return nil
}

func (s *State) RemoveL3Network(name VrfName) error {
	err := s.networkL3Objects.Remove(name)
	if err != nil {
		return err
	}
	err = s.SetL3Networks(s.networkL3Objects)
	if err != nil {
		return err
	}
	return nil
}

func (s *State) GetDeltaToApply() []*dpu.DPUPolicyRule {
	delta := s.diff.getDiff()

	s.diff = newDiffToApply()
	return delta
}

func (s *State) convertRuleToDPUPolicyRule(rule *SwitchPolicy, upsert bool) *dpu.DPUPolicyRule {
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
	sourceVRFId := s.networkL3Objects.byName[VrfName(rule.Policy.Source.Endpoint.VRF)]
	destinationVRFId := s.networkL3Objects.byName[VrfName(rule.Policy.Destination.Endpoint.VRF)]

	dstProto := v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED
	dstMinPort := uint32(0)
	dstMaxPort := uint32(65535)
	if rule.Policy.Destination.ProtoPorts != nil {
		switch strings.ToLower(rule.Policy.Destination.ProtoPorts.Protocol) {
		case "tcp":
			dstProto = v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP
		case "udp":
			dstProto = v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP
		case "icmp":
			dstProto = v1alpha.PolicyProtocol_POLICY_PROTOCOL_ICMP
		}
		dstMinPort = rule.Policy.Destination.ProtoPorts.Port
		dstMaxPort = rule.Policy.Destination.ProtoPorts.EndPort
	}

	return &dpu.DPUPolicyRule{
		Oper: operation,
		Policy: &dpu.DPURule{
			PolicyName: rule.UID.PolicyName,
			RuleName:   rule.UID.RuleName,
			Action:     action,
			Source: dpu.DPUSubject{
				Cidr:     rule.Policy.Source.Endpoint.CIDR,
				MinPort:  0,
				MaxPort:  65535,
				Vlan:     rule.Policy.Source.Endpoint.VLAN,
				Vrf:      rule.Policy.Source.Endpoint.VRF,
				VrfId:    uint32(sourceVRFId),
				Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
			},
			// The current policy resolution does not include destination
			// Vlan and VRF this will be added soon.
			Destination: dpu.DPUSubject{
				Cidr:     rule.Policy.Destination.Endpoint.CIDR,
				MinPort:  dstMinPort,
				MaxPort:  dstMaxPort,
				Vlan:     rule.Policy.Destination.Endpoint.VLAN,
				Vrf:      rule.Policy.Destination.Endpoint.VRF,
				VrfId:    uint32(destinationVRFId),
				Protocol: dstProto,
			},
		},
	}
}
