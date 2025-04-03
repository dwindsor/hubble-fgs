package netpol

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

// Normalize K8s Tetragon Network Policy into internal representation
func ToTetragonNetworkPolicy(np *v1alpha1.TetragonNetworkPolicy) ([]*types.TetragonNetworkPolicy, error) {
	policy := []*types.TetragonNetworkPolicy{}
	subjEqual := np.Spec.PodSelector.MatchLabels
	name := np.ObjectMeta.Name

	subj := types.TetragonNetworkSubject{
		MatchLabelsEqual: subjEqual,
		Workload:         types.TetragonWorkloadNetworkSubject{},
	}

	if np.Spec.ProcessSelector != nil {
		sel := np.Spec.ProcessSelector

		if sel.Operator != "In" {
			return nil, fmt.Errorf("unsupported process selector op, only 'In' is currently supported")
		}
		for _, v := range sel.Values {
			subj.InProcessName = append(subj.InProcessName, v)
		}
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
			return nil, fmt.Errorf("unsupporte hook type (%s)", r.Hook)
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

			if len(d.FQDN) > 0 {
				f = &types.TetragonNetworkFQDN{
					Names: d.FQDN,
				}
			} else {
				f = nil
			}

			labels := types.TetragonNetworkLabels{
				Equal: d.PodSelector.MatchLabels,
			}

			ports := make([]uint32, 0, len(d.Ports.Ports))
			for _, p := range d.Ports.Ports {
				ports = append(ports, p)
			}

			dest := types.TetragonNetworkDestination{
				FQDN:   f,
				Labels: labels,
				Ports:  ports,
			}

			policy = append(policy, &types.TetragonNetworkPolicy{
				Name:        name,
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
