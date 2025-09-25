package policy

import (
	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
)

const (
	ALLOW = "permit"
	DENY  = "forbid"
)

func ruleToJSON(rule *dpu.DPURule) FwPolicyV2 {
	name := rule.PolicyName + rule.RuleName
	uid := rule.K8SResourceVersion + ":" + rule.K8SUid + ":" + rule.PolicyName + ":" + rule.RuleName

	effect := "permit"
	if rule.Action == v1alpha.PolicyAction_POLICY_ACTION_DENY {
		effect = "deny"
	}

	proto := []string{"tcp"}

	source := EndpointV2{
		Ip:       rule.Source.Cidr,
		Vlan:     int(rule.Source.Vlan),
		Vrf:      int(rule.Source.VrfId),
		PortHigh: uint16(rule.Source.MaxPort),
		PortLow:  uint16(rule.Source.MinPort),
	}

	destination := EndpointV2{
		Ip:       rule.Destination.Cidr,
		PortHigh: uint16(rule.Destination.MaxPort),
		PortLow:  uint16(rule.Destination.MinPort),
		Vlan:     int(rule.Destination.Vlan),
		Vrf:      0, // Currently destination VRFs are wildcards
	}

	return FwPolicyV2{
		Id:          uid,
		Name:        name,
		Effect:      effect,
		Protocol:    proto,
		Source:      source,
		Destination: destination,
	}
}

func DPURuleToJSON(policySet []*dpu.DPUPolicyRule) []FwPolicyV2 {
	fwSet := []FwPolicyV2{}

	for _, p := range policySet {
		json := ruleToJSON(p.Policy)
		fwSet = append(fwSet, json)
	}

	return fwSet
}
