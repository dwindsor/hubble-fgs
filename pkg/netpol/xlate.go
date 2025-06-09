package netpol

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/model/dns"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

// Normalize K8s Tetragon Network Policy into internal representation
func ToTetragonNetworkPolicies(np *v1alpha1.TetragonNetworkPolicy) ([]*types.TetragonNetworkPolicy, error) {
	policy := []*types.TetragonNetworkPolicy{}
	name := np.Name

	subj := types.TetragonNetworkSubject{
		Workload: types.TetragonWorkloadNetworkSubject{},
	}

	if np.Spec.PodSelector != nil {
		subj.Labels = types.TetragonNetworkLabels{
			Equal: np.Spec.PodSelector.MatchLabels,
		}
	} else {
		// If there's no PodSelector in a policy, assume the user
		// intended to target the host of the agent itself
		subj.Labels = types.TetragonNetworkLabels{
			Equal: map[string]string{dns.InternalLabelKey: dns.InternalHostName},
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
			return nil, fmt.Errorf("unsupported process selector op, only 'In' is currently supported")
		}
		subj.InProcessName = append(subj.InProcessName, sel.Values...)
	}

	dfltEnforce := &types.TetragonEnforceAction{}
	if strings.Compare(np.Spec.DefaultAction, "deny") == 0 {
		dfltEnforce.Deny = true
	}
	if strings.Compare(np.Spec.DefaultAction, "allow") == 0 {
		dfltEnforce.Allow = true
	}
	dfltAction := types.TetragonNetworkAction{
		EnforceAction: dfltEnforce,
	}

	for _, r := range np.Spec.Rules {
		if r.Hook != "connect" {
			return nil, fmt.Errorf("unsupported hook type (%s)", r.Hook)
		}

		enforce := &types.TetragonEnforceAction{}
		if strings.Compare(r.Action, "deny") == 0 {
			enforce.Deny = true
		}
		if strings.Compare(r.Action, "allow") == 0 {
			enforce.Allow = true
		}
		act := types.TetragonNetworkAction{
			EnforceAction: enforce,
		}

		for _, d := range r.Destination {
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
			} else {
				// As for the top level PodSelector, assume no
				// PodSelector means to target the agent host
				// itself
				labels.Equal = map[string]string{dns.InternalLabelKey: dns.InternalHostName}
			}

			ports := make([]uint32, 0, len(d.Ports.Ports))
			ports = append(ports, d.Ports.Ports...)

			dest := types.TetragonNetworkDestination{
				FQDN:   f,
				Labels: labels,
				CIDR:   ip,
				Ports:  ports,
			}

			policy = append(policy, &types.TetragonNetworkPolicy{
				Name:        name,
				Rule:        r.Description,
				Subject:     subj,
				Destination: dest,
				Action:      act,
				Default:     dfltAction,
			})
		}
	}
	return policy, nil
}

func ToTetragonNetworkPolicyNamespaced(_ *v1alpha1.TetragonNetworkPolicyNamespaced) ([]*types.TetragonNetworkPolicy, error) {
	var policy []*types.TetragonNetworkPolicy
	return policy, nil
}
