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
			destEqual := make(map[string]string)

			var f *types.TetragonNetworkFQDN

			if len(d.FQDN.Fqdn) > 0 {
				f = &types.TetragonNetworkFQDN{
					Names: d.FQDN.Fqdn,
				}
			} else {
				f = nil
			}

			if len(d.Labels.MatchLabels) > 0 {
				for _, l := range d.Labels.MatchLabels {
					kv := strings.Split(l, "=")
					if len(kv) < 2 {
						return policy, fmt.Errorf("Invalidor unsupported match labels %s", l)
					}
					destEqual[kv[0]] = kv[1]
				}
			}

			labels := types.TetragonNetworkLabels{
				Equal: destEqual,
			}

			dest := types.TetragonNetworkDestination{
				FQDN:   f,
				Labels: labels,
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
