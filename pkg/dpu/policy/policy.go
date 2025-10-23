package policy

import (
	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
)

const (
	ALLOW = "permit"
	DENY  = "forbid"
)

func ruleToJSON(op v1alpha.PolicyOperation, rule *dpu.DPURule) FwPolicyV2 {
	var fwop uint16

	name := rule.PolicyName + rule.RuleName
	uid := rule.K8SResourceVersion + ":" + rule.K8SUid + ":" + rule.PolicyName + ":" + rule.RuleName

	effect := "permit"
	if rule.Action == v1alpha.PolicyAction_POLICY_ACTION_DENY {
		effect = "deny"
	}

	// Protocol is only being picked up from the destination
	proto := []string{}
	switch rule.Destination.Protocol {
	case v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP:
		proto = append(proto, "tcp")
	case v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP:
		proto = append(proto, "udp")
	case v1alpha.PolicyProtocol_POLICY_PROTOCOL_ICMP:
		proto = append(proto, "icmp")
	}

	switch op {
	case v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT:
		fwop = 0
	case v1alpha.PolicyOperation_POLICY_OPERATION_DELETE:
		fwop = 1
	default:
		fwop = 0
	}

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
		Operation:   fwop,
		Effect:      effect,
		Protocol:    proto,
		Source:      source,
		Destination: destination,
	}
}

func DPURuleToJSON(op v1alpha.PolicyOperation, policySet []*dpu.DPUPolicyRule) []FwPolicyV2 {
	fwSet := []FwPolicyV2{}

	for _, p := range policySet {
		json := ruleToJSON(op, p.Policy)
		fwSet = append(fwSet, json)
	}

	return fwSet
}
