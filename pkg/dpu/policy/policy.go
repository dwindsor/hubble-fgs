package policy

import (
	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

const (
	ALLOW = "permit"
	DENY  = "deny"
)

// protocolToString converts a PolicyProtocol to its string representation
func protocolToString(p v1alpha.PolicyProtocol) string {
	switch p {
	case v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP:
		return "tcp"
	case v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP:
		return "udp"
	case v1alpha.PolicyProtocol_POLICY_PROTOCOL_ICMP:
		return "icmp"
	default:
		return "any"
	}
}

// portRangeKey uniquely identifies a port range for deduplication
type portRangeKey struct {
	portLow  uint16
	portHigh uint16
}

func mergePorts(x PortV2, y PortV2) PortV2 {
	seen := make(map[string]struct{})

	for _, s := range y.Protocol {
		seen[s] = struct{}{}
	}
	for _, s := range x.Protocol {
		seen[s] = struct{}{}
	}

	proto := make([]string, 0, len(seen))
	for k := range seen {
		proto = append(proto, k)
	}

	return PortV2{
		PortLow:  x.PortLow,
		PortHigh: x.PortHigh,
		Protocol: proto,
	}
}

func ruleToJSON(op v1alpha.PolicyOperation, rule *switchpolicy.DPURule) *FwPolicyV2 {
	var fwop uint16

	name := rule.PolicyName + "/" + rule.RuleName
	ruleUID := rule.K8SResourceVersion + ":" + rule.K8SUid + ":" + rule.PolicyName + ":" + rule.RuleName

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

	dstPorts := []PortV2{}
	srcPorts := []PortV2{} // For now we ignore source ports

	mergedPorts := make(map[portRangeKey]PortV2)

	if rule.Destination.Ports != nil {
		for _, p := range *rule.Destination.Ports {
			end := p.EndPort
			if end < p.Port {
				end = p.Port
			}

			key := portRangeKey{
				portLow:  uint16(p.Port),
				portHigh: uint16(end),
			}

			v := PortV2{
				PortLow:  uint16(p.Port),
				PortHigh: uint16(end),
				Protocol: []string{protocolToString(p.Protocol)},
			}

			if portv2, ok := mergedPorts[key]; ok {
				v = mergePorts(v, portv2)
			}

			mergedPorts[key] = v
		}

		for _, v := range mergedPorts {
			dstPorts = append(dstPorts, v)
		}
	}

	return &FwPolicyV2{
		Id:        ruleUID,
		Name:      name,
		Operation: fwop,
		Effect:    effect,
		Source: EndpointV2{
			Ip:    rule.Source.Cidr,
			Vlan:  int(rule.Source.Vlan),
			Vrf:   int(rule.Source.VrfId),
			Ports: srcPorts,
		},
		Destination: EndpointV2{
			Ip:    rule.Destination.Cidr,
			Ports: dstPorts,
			Vlan:  int(rule.Destination.Vlan),
			Vrf:   0, // Currently destination VRFs are wildcards
		},
	}
}

func DPURuleToJSON(op v1alpha.PolicyOperation, policySet []*switchpolicy.DPUPolicyRule) []FwPolicyV2 {
	fwSet := make([]FwPolicyV2, 0, len(policySet))

	for _, p := range policySet {
		policy := ruleToJSON(op, p.Policy)
		fwSet = append(fwSet, *policy)
	}

	return fwSet
}
