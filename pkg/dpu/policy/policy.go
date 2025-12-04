package policy

import (
	"fmt"

	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

const (
	ALLOW = "permit"
	DENY  = "deny"
)

// portRangeKey uniquely identifies a port range for deduplication
type portRangeKey struct {
	portLow  uint16
	portHigh uint16
}

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

func ruleToJSON(op v1alpha.PolicyOperation, rule *switchpolicy.DPURule) []FwPolicyV2 {
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

	// Group destination ports by port range, collecting all protocols for each range
	dstProtosByRange := make(map[portRangeKey]map[string]struct{})
	if rule.Destination.Ports != nil {
		for _, p := range *rule.Destination.Ports {
			key := portRangeKey{portLow: uint16(p.Port), portHigh: uint16(p.EndPort)}
			if dstProtosByRange[key] == nil {
				dstProtosByRange[key] = make(map[string]struct{})
			}
			proto := protocolToString(p.Protocol)
			dstProtosByRange[key][proto] = struct{}{}
		}
	}

	// Group source ports by port range, collecting all protocols for each range
	srcProtosByRange := make(map[portRangeKey]map[string]struct{})
	if rule.Source.Ports != nil {
		for _, p := range *rule.Source.Ports {
			key := portRangeKey{portLow: uint16(p.Port), portHigh: uint16(p.EndPort)}
			if srcProtosByRange[key] == nil {
				srcProtosByRange[key] = make(map[string]struct{})
			}
			proto := protocolToString(p.Protocol)
			srcProtosByRange[key][proto] = struct{}{}
		}
	}

	// If no port ranges found, create a single policy with empty ports
	if len(dstProtosByRange) == 0 && len(srcProtosByRange) == 0 {
		return []FwPolicyV2{{
			Id:        uid,
			Name:      name,
			Operation: fwop,
			Effect:    effect,
			Source: EndpointV2{
				Ip:    rule.Source.Cidr,
				Vlan:  int(rule.Source.Vlan),
				Vrf:   int(rule.Source.VrfId),
				Ports: []PortV2{},
			},
			Destination: EndpointV2{
				Ip:    rule.Destination.Cidr,
				Ports: []PortV2{},
				Vlan:  int(rule.Destination.Vlan),
				Vrf:   0, // Currently destination VRFs are wildcards
			},
		}}
	}

	// Create a separate policy for each destination port range
	policies := make([]FwPolicyV2, 0, len(dstProtosByRange))
	for portRange, protoSet := range dstProtosByRange {
		// Convert protocol set to sorted slice
		protocols := make([]string, 0, len(protoSet))
		for proto := range protoSet {
			protocols = append(protocols, proto)
		}

		dstPort := PortV2{
			PortLow:  portRange.portLow,
			PortHigh: portRange.portHigh,
			Protocol: protocols,
		}

		// Build source ports (include all source port ranges with their protocols)
		srcPorts := []PortV2{}
		for srcRange, srcProtoSet := range srcProtosByRange {
			srcProtocols := make([]string, 0, len(srcProtoSet))
			for proto := range srcProtoSet {
				srcProtocols = append(srcProtocols, proto)
			}
			srcPorts = append(srcPorts, PortV2{
				PortLow:  srcRange.portLow,
				PortHigh: srcRange.portHigh,
				Protocol: srcProtocols,
			})
		}

		// Create unique ID for this port-range-specific policy
		policyUID := fmt.Sprintf("%s:%d-%d", uid, portRange.portLow, portRange.portHigh)

		policies = append(policies, FwPolicyV2{
			Id:        policyUID,
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
				Ports: []PortV2{dstPort},
				Vlan:  int(rule.Destination.Vlan),
				Vrf:   0, // Currently destination VRFs are wildcards
			},
		})
	}

	return policies
}

func DPURuleToJSON(op v1alpha.PolicyOperation, policySet []*switchpolicy.DPUPolicyRule) []FwPolicyV2 {
	fwSet := []FwPolicyV2{}

	for _, p := range policySet {
		policies := ruleToJSON(op, p.Policy)
		fwSet = append(fwSet, policies...)
	}

	return fwSet
}
