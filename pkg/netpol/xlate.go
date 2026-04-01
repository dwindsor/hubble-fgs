// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package netpol

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/isovalent/ipa/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/netpolstate"
)

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
			Equal: map[string]string{netpolstate.InternalLabelKey: netpolstate.InternalHostName},
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

func ensureCIDR(ipBlock string) string {
	if strings.Contains(ipBlock, "/") {
		return ipBlock
	}

	ip, err := netip.ParseAddr(ipBlock)
	if err != nil {
		// Invalid IP address, return as-is
		return ipBlock
	}

	if ip.Is4() {
		return ipBlock + "/32"
	}
	return ipBlock + "/128"
}

func toDestination(d *v1alpha1.NetworkDestination) (types.TetragonNetworkDestination, error) {
	var f *types.TetragonNetworkFQDN
	var cidr netip.Prefix
	var svcRef *types.TetragonServiceRef

	if len(d.FQDN) > 0 {
		// Normalize FQDN: ensure trailing dot to match BPF DNS parser
		// output. The DNS parsers (BPF and userspace) produces domain
		// names with trailing dots (e.g., "google.com."), so policy
		// FQDNs must also have trailing dots for endpoint cache
		// matching to work correctly.
		fqdns := make([]string, 0, len(d.FQDN))
		for _, entry := range d.FQDN {
			fqdn := entry
			if !strings.HasSuffix(fqdn, ".") {
				fqdn = fqdn + "."
			}
			fqdns = append(fqdns, fqdn)
		}

		f = &types.TetragonNetworkFQDN{
			Names: fqdns,
		}
	} else {
		f = nil
	}

	if d.IPBlock != nil {
		var err error
		cidr, err = netip.ParsePrefix(ensureCIDR(d.IPBlock.CIDR))
		if err != nil {
			return types.TetragonNetworkDestination{}, fmt.Errorf("failed to parse CIDR %s: %w", d.IPBlock.CIDR, err)
		}
	}

	if d.ServiceSelector != nil {
		namespace := d.ServiceSelector.Namespace
		if namespace == "" {
			namespace = "default"
		}
		svcRef = &types.TetragonServiceRef{
			Name:      d.ServiceSelector.Name,
			Namespace: namespace,
		}
	}

	labels := types.TetragonNetworkLabels{}
	if d.PodSelector != nil {
		labels.Equal = d.PodSelector.MatchLabels
	}

	ports := make([]uint32, 0, len(d.Ports.Ports))
	ports = append(ports, d.Ports.Ports...)

	return types.TetragonNetworkDestination{
		FQDN:       f,
		Labels:     labels,
		CIDR:       cidr,
		ServiceRef: svcRef,
		Ports:      ports,
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
		dest, err := toDestination(&d)
		if err != nil {
			return nil, fmt.Errorf("failed to translate destination %v: %w", d, err)
		}

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
