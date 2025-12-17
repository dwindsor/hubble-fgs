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
	"net/netip"
	"strings"

	isovalentv1 "github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

func cidrIPFamily(cidr string) (int, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return 0, err
	}

	addr := prefix.Addr()
	if addr.Is4() {
		return 4, nil
	}
	if addr.Is6() {
		return 6, nil
	}

	return 0, fmt.Errorf("unsupported CIDR address family: %s", cidr)
}

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

	dprotoports := make([]SmartSwitchNetworkProtocolPorts, 0, len(r.Destination.ProtoPorts))

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

		dprotoports = append(dprotoports,
			SmartSwitchNetworkProtocolPorts{
				Port:     uint32(p.Port),
				EndPort:  uint32(p.EndPort),
				Protocol: proto,
			})
	}

	for _, s := range r.Source.IPBlock {
		sFamily, err := cidrIPFamily(s.CIDR)
		if err != nil {
			return nil, fmt.Errorf("invalid source CIDR %q: %w", s.CIDR, err)
		}

		source := SmartSwitchNetworkSource{
			Endpoint: SmartSwitchNetworkEndpoint{
				CIDR: s.CIDR,
				VRF:  s.VRF,
				VLAN: s.VLAN,
			},
		}

		for _, d := range r.Destination.IPBlock {
			dFamily, err := cidrIPFamily(d.CIDR)
			if err != nil {
				return nil, fmt.Errorf("invalid destination CIDR %q: %w", d.CIDR, err)
			}
			if sFamily != dFamily {
				continue
			}

			dest := SmartSwitchNetworkDestination{
				Endpoint: SmartSwitchNetworkEndpoint{
					CIDR: d.CIDR,
					VRF:  d.VRF,
					VLAN: d.VLAN,
				},
				ProtoPorts: &dprotoports,
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
