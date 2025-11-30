package switchpolicy

import (
	"strings"

	isovalentv1 "github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

func toSmartSwitchDefaultAction(_ *isovalentv1.SmartSwitchNetworkPolicy) SmartSwitchNetworkAction {
	// SmartSwitch is default deny for all policies at this point
	return SmartSwitchNetworkAction{
		EnforceAction: SmartSwitchEnforceAction{
			Deny: true,
		},
	}
}

func toSmartSwitchAction(r *isovalentv1.SmartSwitchNetworkPolicyRule) SmartSwitchNetworkAction {
	enforce := SmartSwitchEnforceAction{}
	if strings.Compare(r.Action, "deny") == 0 {
		enforce.Deny = true
	}
	if strings.Compare(r.Action, "allow") == 0 {
		enforce.Allow = true
	}
	return SmartSwitchNetworkAction{
		EnforceAction: enforce,
	}
}

func parseSmartSwitchPolicy(np *isovalentv1.SmartSwitchNetworkPolicy, r *isovalentv1.SmartSwitchNetworkPolicyRule) ([]*SmartSwitchNetworkPolicy, error) {
	policy := []*SmartSwitchNetworkPolicy{}

	dfltAction := toSmartSwitchDefaultAction(np)
	act := toSmartSwitchAction(r)

	protoports := make([]SmartSwitchNetworkProtocolPorts, len(r.Destination.ProtoPorts), len(r.Destination.ProtoPorts))
	for _, p := range r.Destination.ProtoPorts {
		if p.EndPort == 0 {
			p.EndPort = p.Port
		}

		proto := v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED

		switch p.Protocol {
		case "TCP":
			proto = v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP
		case "UDP":
			proto = v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP
		case "ICMP":
			proto = v1alpha.PolicyProtocol_POLICY_PROTOCOL_ICMP
		}

		protoports = append(protoports,
			SmartSwitchNetworkProtocolPorts{
				Port:     uint32(p.Port),
				EndPort:  uint32(p.EndPort),
				Protocol: proto,
			})
	}

	for _, s := range r.Source.IPBlock {
		source := SmartSwitchNetworkSource{
			Endpoint: SmartSwitchNetworkEndpoint{
				CIDR: s.CIDR,
				VRF:  s.VRF,
				VLAN: s.VLAN,
			},
		}

		for _, d := range r.Destination.IPBlock {
			dest := SmartSwitchNetworkDestination{
				Endpoint: SmartSwitchNetworkEndpoint{
					CIDR: d.CIDR,
					VRF:  d.VRF,
					VLAN: d.VLAN,
				},
				ProtoPorts: &protoports,
			}

			policy = append(policy, &SmartSwitchNetworkPolicy{
				K8SResourceVersion: np.ResourceVersion,
				K8SUid:             string(np.UID),
				Source:             source,
				Destination:        dest,
				Action:             act,
				Default:            dfltAction,
			})
		}
	}

	return policy, nil
}

func ToSmartSwitchNetworkPolicies(np *isovalentv1.SmartSwitchNetworkPolicy) ([]*SmartSwitchNetworkPolicy, error) {
	result := []*SmartSwitchNetworkPolicy{}
	for _, r := range np.Spec.Rules {
		rulePolicy, err := parseSmartSwitchPolicy(np, &r)
		if err != nil {
			return nil, err
		}
		result = append(result, rulePolicy...)
	}
	return result, nil
}
