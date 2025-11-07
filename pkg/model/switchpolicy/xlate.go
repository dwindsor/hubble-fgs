package switchpolicy

import (
	"strings"

	isovalentv1 "github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
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
	for _, s := range r.Source.IPBlock {
		source := SmartSwitchNetworkSource{
			Endpoint: SmartSwitchNetworkEndpoint{
				CIDR: s.CIDR,
				VRF:  s.VRF,
				VLAN: s.VLAN,
			},
		}
		for _, d := range r.Destination.IPBlock {
			protoports := []SmartSwitchNetworkProtocolPorts{}
			for _, p := range r.Destination.ProtoPorts {
				if p.EndPort == 0 {
					p.EndPort = p.Port
				}
				protoports = append(protoports,
					SmartSwitchNetworkProtocolPorts{
						Port:     p.Port,
						EndPort:  p.EndPort,
						Protocol: p.Protocol,
					})
			}
			dest := SmartSwitchNetworkDestination{
				Endpoint: SmartSwitchNetworkEndpoint{
					CIDR: d.CIDR,
					VRF:  d.VRF,
					VLAN: d.VLAN,
				},
				ProtoPorts: protoports,
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
