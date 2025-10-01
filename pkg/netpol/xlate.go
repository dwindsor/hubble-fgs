package netpol

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/model/dns"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

func toFirewallSubject(np *v1alpha1.TetragonNetworkPolicy) (types.TetragonNetworkSubject, error) {
	subj := types.TetragonNetworkSubject{
		Workload: types.TetragonWorkloadNetworkSubject{},
	}

	if np.Spec.LogicalNetworkSelector == nil {
		return subj, fmt.Errorf("firewall policy requires logical network specifier")
	}

	if np.Spec.LogicalNetworkSelector.VRF != "" && np.Spec.LogicalNetworkSelector.VLAN != 0 {
		return subj, fmt.Errorf("firewall policy can not support both VRF and VLAN set, %v", np.Spec.LogicalNetworkSelector.VRF)
	}

	if np.Spec.LogicalNetworkSelector.VRF != "" {
		ln := types.TetragonLogicalNetworkSubject{
			VRF: np.Spec.LogicalNetworkSelector.VRF,
		}
		return types.TetragonNetworkSubject{
			LogicalNetwork: ln,
		}, nil
	}

	ln := types.TetragonLogicalNetworkSubject{
		VLAN: np.Spec.LogicalNetworkSelector.VLAN,
	}
	return types.TetragonNetworkSubject{
		LogicalNetwork: ln,
	}, nil
}

func toSubject(np *v1alpha1.TetragonNetworkPolicy) (types.TetragonNetworkSubject, error) {
	subj := types.TetragonNetworkSubject{
		Workload: types.TetragonWorkloadNetworkSubject{},
	}

	// Note: Network Policy does not support MatchExpressions as of now, if
	// we do we need to update how we check that selectors are empty above
	if (np.Spec.PodSelector == nil || np.Spec.PodSelector.MatchLabels == nil) &&
		(np.Spec.NamespaceSelector == nil || np.Spec.NamespaceSelector.MatchLabels == nil) {
		// If there's no PodSelector and no NamespaceSelector in a policy,
		// assume the user intended to target the host of the agent itself
		subj.Labels = types.TetragonNetworkLabels{
			Equal: map[string]string{dns.InternalLabelKey: dns.InternalHostName},
		}
	} else if np.Spec.PodSelector != nil && np.Spec.PodSelector.MatchLabels != nil {
		subj.Labels = types.TetragonNetworkLabels{
			Equal: np.Spec.PodSelector.MatchLabels,
		}
	} else {
		subj.Labels = types.TetragonNetworkLabels{
			Equal: map[string]string{},
		}
	}

	if np.Spec.NamespaceSelector != nil {
		nsSet := np.Spec.NamespaceSelector.MatchLabels

		for k, v := range nsSet {
			tnpKey := fmt.Sprintf("_tnp_%s", k)
			subj.Labels.Equal[tnpKey] = v
		}
	}

	if np.Spec.ProcessSelector != nil {
		sel := np.Spec.ProcessSelector

		if sel.Operator != "In" {
			return subj, fmt.Errorf("unsupported process selector op, only 'In' is currently supported")
		}
		subj.InProcessName = append(subj.InProcessName, sel.Values...)
	}

	return subj, nil
}

func toDefaultAction(np *v1alpha1.TetragonNetworkPolicy) types.TetragonNetworkAction {
	dfltEnforce := &types.TetragonEnforceAction{}
	if strings.Compare(np.Spec.DefaultAction, "deny") == 0 {
		dfltEnforce.Deny = true
	}
	if strings.Compare(np.Spec.DefaultAction, "allow") == 0 {
		dfltEnforce.Allow = true
	}
	return types.TetragonNetworkAction{
		EnforceAction: dfltEnforce,
	}
}

func toAction(r *v1alpha1.NetworkPolicyRule) types.TetragonNetworkAction {
	enforce := &types.TetragonEnforceAction{}
	if strings.Compare(r.Action, "deny") == 0 {
		enforce.Deny = true
	}
	if strings.Compare(r.Action, "allow") == 0 {
		enforce.Allow = true
	}
	return types.TetragonNetworkAction{
		EnforceAction: enforce,
	}
}

func toDestination(d *v1alpha1.NetworkDestination) types.TetragonNetworkDestination {
	var f *types.TetragonNetworkFQDN
	var ip *types.TetragonNetworkCIDR

	if len(d.FQDN) > 0 {
		f = &types.TetragonNetworkFQDN{
			Names: d.FQDN,
		}
	} else {
		f = nil
	}

	if d.IPBlock != nil {
		ip = &types.TetragonNetworkCIDR{
			CIDR: d.IPBlock.CIDR,
		}
	}

	labels := types.TetragonNetworkLabels{}
	if d.PodSelector != nil {
		labels.Equal = d.PodSelector.MatchLabels
	}

	ports := make([]uint32, 0, len(d.Ports.Ports))
	ports = append(ports, d.Ports.Ports...)

	return types.TetragonNetworkDestination{
		FQDN:   f,
		Labels: labels,
		CIDR:   ip,
		Ports:  ports,
	}
}

func toFirewallDestination(d *v1alpha1.NetworkDestination) (*types.TetragonNetworkDestination, error) {
	var f *types.TetragonNetworkFQDN
	labels := types.TetragonNetworkLabels{}

	if len(d.FQDN) > 0 {
		return nil, fmt.Errorf("firewall does not have FQDN support")
	}
	if d.PodSelector != nil {
		return nil, fmt.Errorf("firewall does not have pod label support")
	}
	if d.IPBlock == nil {
		return nil, fmt.Errorf("firewall wildcard destination rules not supported")
	}

	ip := &types.TetragonNetworkCIDR{
		CIDR: d.IPBlock.CIDR,
	}

	ports := make([]uint32, 0, len(d.Ports.Ports))
	ports = append(ports, d.Ports.Ports...)

	return &types.TetragonNetworkDestination{
		FQDN:   f,
		Labels: labels,
		CIDR:   ip,
		Ports:  ports,
	}, nil
}

func toFirewallSource(d *v1alpha1.NetworkSource) (*types.TetragonNetworkSource, error) {

	if d.IPBlock == nil {
		return nil, fmt.Errorf("firewall wildcard source rulees not supported")
	}

	ip := &types.TetragonNetworkCIDR{
		CIDR: d.IPBlock.CIDR,
	}

	ports := make([]uint32, 0, len(d.Ports.Ports))
	ports = append(ports, d.Ports.Ports...)

	return &types.TetragonNetworkSource{
		CIDR:  ip,
		Ports: ports,
	}, nil
}

func parseConnectPolicy(np *v1alpha1.TetragonNetworkPolicy, r *v1alpha1.NetworkPolicyRule) ([]*types.TetragonNetworkPolicy, error) {
	policy := []*types.TetragonNetworkPolicy{}

	subj, err := toSubject(np)
	if err != nil {
		return nil, err
	}
	dfltAction := toDefaultAction(np)
	act := toAction(r)
	for _, d := range r.Destination {
		dest := toDestination(&d)
		policy = append(policy, &types.TetragonNetworkPolicy{
			RuleDescription: r.Description,
			Subject:         subj,
			Destination:     dest,
			Action:          act,
			Default:         dfltAction,
		})
	}

	return policy, nil
}

func parseFirewallPolicy(np *v1alpha1.TetragonNetworkPolicy, r *v1alpha1.NetworkPolicyRule) ([]*types.TetragonNetworkPolicy, error) {
	policy := []*types.TetragonNetworkPolicy{}

	subj, err := toFirewallSubject(np)
	if err != nil {
		return nil, err
	}
	dfltAction := toDefaultAction(np)
	act := toAction(r)
	for _, s := range r.Source {
		source, err := toFirewallSource(&s)
		if err != nil {
			return nil, err
		}
		for _, d := range r.Destination {
			dest, err := toFirewallDestination(&d)
			if err != nil {
				return nil, err
			}

			policy = append(policy, &types.TetragonNetworkPolicy{
				RuleDescription: r.Description,
				Subject:         subj,
				Source:          source,
				Destination:     *dest,
				Action:          act,
				Default:         dfltAction,
			})
		}
	}

	return policy, nil
}

// Normalize K8s Tetragon Network Policy into internal representation
func ToTetragonNetworkPolicies(np *v1alpha1.TetragonNetworkPolicy) ([]*types.TetragonNetworkPolicy, error) {
	result := []*types.TetragonNetworkPolicy{}
	for _, r := range np.Spec.Rules {
		switch r.Hook {
		case "connect":
			rulePolicy, err := parseConnectPolicy(np, &r)
			if err != nil {
				return nil, err
			}
			result = append(result, rulePolicy...)
		case "firewall":
			rulePolicy, err := parseFirewallPolicy(np, &r)
			if err != nil {
				return nil, err
			}
			result = append(result, rulePolicy...)
		default:
			return nil, fmt.Errorf("unsupported hook type (%s)", r.Hook)
		}
	}
	return result, nil
}

func ToTetragonNetworkPolicyNamespaced(_ *v1alpha1.TetragonNetworkPolicyNamespaced) ([]*types.TetragonNetworkPolicy, error) {
	var policy []*types.TetragonNetworkPolicy
	return policy, nil
}
