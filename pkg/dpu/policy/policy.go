package policy

import (
	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
)

const (
	ALLOW = "permit"
	DENY  = "deny"
)

func ruleToJSON(op v1alpha.PolicyOperation, rule *dpu.DPURule) FwPolicyV2 {
	var fwop uint16

	name := rule.PolicyName + "/" + rule.RuleName
	uid := rule.K8SResourceVersion + ":" + rule.K8SUid + ":" + rule.PolicyName + ":" + rule.RuleName

	effect := ALLOW
	if rule.Action == v1alpha.PolicyAction_POLICY_ACTION_DENY {
		effect = DENY
	}

	switch op {
	case v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT:
		fwop = 0
	case v1alpha.PolicyOperation_POLICY_OPERATION_DELETE:
		fwop = 1
	default:
		fwop = 0
	}

	srcPorts := []PortV2{}
	dstPorts := []PortV2{}

	for _, p := range rule.Destination.Ports {
		// Protocol is only being picked up from the destination
		proto := []string{}
		switch p.Protocol {
		case v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP:
			proto = append(proto, "tcp")
		case v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP:
			proto = append(proto, "udp")
		case v1alpha.PolicyProtocol_POLICY_PROTOCOL_ICMP:
			proto = append(proto, "icmp")
		}
		dstPorts = append(dstPorts, PortV2{
			PortHigh: uint16(p.MaxPort),
			PortLow:  uint16(p.MinPort),
			Protocol: proto,
		})
	}

	for _, p := range rule.Source.Ports {
		// Protocol is only being picked up from the destination
		proto := []string{}
		switch p.Protocol {
		case v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP:
			proto = append(proto, "tcp")
		case v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP:
			proto = append(proto, "udp")
		case v1alpha.PolicyProtocol_POLICY_PROTOCOL_ICMP:
			proto = append(proto, "icmp")
		}
		srcPorts = append(srcPorts, PortV2{
			PortHigh: uint16(p.MaxPort),
			PortLow:  uint16(p.MinPort),
			Protocol: proto,
		})
	}

	source := EndpointV2{
		Ip:    rule.Source.Cidr,
		Vlan:  int(rule.Source.Vlan),
		Vrf:   int(rule.Source.VrfId),
		Ports: srcPorts,
	}

	destination := EndpointV2{
		Ip:    rule.Destination.Cidr,
		Ports: dstPorts,
		Vlan:  int(rule.Destination.Vlan),
		Vrf:   0, // Currently destination VRFs are wildcards
	}

	return FwPolicyV2{
		Id:          uid,
		Name:        name,
		Operation:   fwop,
		Effect:      effect,
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
