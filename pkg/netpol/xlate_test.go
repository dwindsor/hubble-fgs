package netpol

import (
	"encoding/json"
	"reflect"
	"testing"

	v1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/isovalent/ipa/k8s/apis/cilium.io/v1alpha1"
	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/model/dns"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

func TestToTetragonNetworkPolicies(t *testing.T) {
	rule := v1alpha1.NetworkPolicyRule{
		Hook:        "connect",
		Description: "Allows HTTPS connection to 8.8.8.8",
		Destination: []v1alpha1.NetworkDestination{
			{
				IPBlock: &v1alpha1.NetworkDestinationCIDR{CIDR: "8.8.8.8/32"},
				Ports:   v1alpha1.NetworkDestinationPorts{Protocol: "TCP", Ports: []uint32{443}},
			},
		},
	}
	rule2 := v1alpha1.NetworkPolicyRule{
		Hook:        "connect",
		Description: "Allows HTTP connection to 8.8.4.4",
		Destination: []v1alpha1.NetworkDestination{
			{
				IPBlock: &v1alpha1.NetworkDestinationCIDR{CIDR: "8.8.4.4/32"},
				Ports:   v1alpha1.NetworkDestinationPorts{Protocol: "TCP", Ports: []uint32{80}},
			},
		},
	}

	tests := []struct {
		name    string
		policy  v1alpha1.TetragonNetworkPolicy
		want    []*types.TetragonNetworkPolicy
		wantErr bool
	}{
		{
			name: "Empty PodSelector with NamespaceSelector",
			policy: v1alpha1.TetragonNetworkPolicy{
				Spec: v1alpha1.NetworkPolicySpec{
					PodSelector: &v1.LabelSelector{},
					NamespaceSelector: &v1.LabelSelector{
						MatchLabels: map[string]v1.MatchLabelsValue{"kubernetes.io/metadata.name": "default"},
					},
					ProcessSelector: &v1alpha1.BinarySelector{
						Operator: "In",
						Values:   []string{"/usr/bin/curl"},
					},
					DefaultAction: "deny",
					Rules:         []v1alpha1.NetworkPolicyRule{rule},
				},
			},
			want: []*types.TetragonNetworkPolicy{
				{
					RuleDescription: rule.Description,
					Subject: types.TetragonNetworkSubject{
						Labels:        types.TetragonNetworkLabels{Equal: map[string]string{"_tnp_kubernetes.io/metadata.name": "default"}},
						InProcessName: []string{"/usr/bin/curl"},
					},
					Destination: types.TetragonNetworkDestination{
						CIDR:  &types.TetragonNetworkCIDR{CIDR: rule.Destination[0].IPBlock.CIDR},
						Ports: []uint32{rule.Destination[0].Ports.Ports[0]},
					},
					Default: types.TetragonNetworkAction{EnforceAction: &types.TetragonEnforceAction{Deny: true}},
					Action:  types.TetragonNetworkAction{EnforceAction: &types.TetragonEnforceAction{}},
				},
			},
		},
		{
			name: "Empty NamespaceSelector",
			policy: v1alpha1.TetragonNetworkPolicy{
				Spec: v1alpha1.NetworkPolicySpec{
					PodSelector:       &v1.LabelSelector{MatchLabels: map[string]v1.MatchLabelsValue{"app": "frontend"}},
					NamespaceSelector: nil,
					ProcessSelector: &v1alpha1.BinarySelector{
						Operator: "In",
						Values:   []string{"/usr/bin/curl"},
					},
					DefaultAction: "deny",
					Rules:         []v1alpha1.NetworkPolicyRule{rule},
				},
			},
			want: []*types.TetragonNetworkPolicy{
				{
					RuleDescription: rule.Description,
					Subject: types.TetragonNetworkSubject{
						Labels:        types.TetragonNetworkLabels{Equal: map[string]string{"app": "frontend"}},
						InProcessName: []string{"/usr/bin/curl"},
					},
					Destination: types.TetragonNetworkDestination{
						CIDR:  &types.TetragonNetworkCIDR{CIDR: rule.Destination[0].IPBlock.CIDR},
						Ports: []uint32{rule.Destination[0].Ports.Ports[0]},
					},
					Default: types.TetragonNetworkAction{EnforceAction: &types.TetragonEnforceAction{Deny: true}},
					Action:  types.TetragonNetworkAction{EnforceAction: &types.TetragonEnforceAction{}},
				},
			},
		},
		{
			name: "Implicit subject is host",
			policy: v1alpha1.TetragonNetworkPolicy{
				Spec: v1alpha1.NetworkPolicySpec{
					ProcessSelector: &v1alpha1.BinarySelector{
						Operator: "In",
						Values:   []string{"/usr/bin/curl"},
					},
					DefaultAction: "deny",
					Rules:         []v1alpha1.NetworkPolicyRule{rule},
				},
			},
			want: []*types.TetragonNetworkPolicy{
				{
					RuleDescription: rule.Description,
					Subject: types.TetragonNetworkSubject{
						Labels:        types.TetragonNetworkLabels{Equal: map[string]string{dns.InternalLabelKey: dns.InternalHostName}},
						InProcessName: []string{"/usr/bin/curl"},
					},
					Destination: types.TetragonNetworkDestination{
						CIDR:  &types.TetragonNetworkCIDR{CIDR: rule.Destination[0].IPBlock.CIDR},
						Ports: []uint32{rule.Destination[0].Ports.Ports[0]},
					},
					Default: types.TetragonNetworkAction{EnforceAction: &types.TetragonEnforceAction{Deny: true}},
					Action:  types.TetragonNetworkAction{EnforceAction: &types.TetragonEnforceAction{}},
				},
			},
		},
		{
			name: "Two rules result in two policies",
			policy: v1alpha1.TetragonNetworkPolicy{
				Spec: v1alpha1.NetworkPolicySpec{
					PodSelector: &v1.LabelSelector{},
					NamespaceSelector: &v1.LabelSelector{
						MatchLabels: map[string]v1.MatchLabelsValue{"kubernetes.io/metadata.name": "default"},
					},
					ProcessSelector: &v1alpha1.BinarySelector{
						Operator: "In",
						Values:   []string{"/usr/bin/curl"},
					},
					DefaultAction: "deny",
					Rules:         []v1alpha1.NetworkPolicyRule{rule, rule2},
				},
			},
			want: []*types.TetragonNetworkPolicy{
				{
					RuleDescription: rule.Description,
					Subject: types.TetragonNetworkSubject{
						Labels:        types.TetragonNetworkLabels{Equal: map[string]string{"_tnp_kubernetes.io/metadata.name": "default"}},
						InProcessName: []string{"/usr/bin/curl"},
					},
					Destination: types.TetragonNetworkDestination{
						CIDR:  &types.TetragonNetworkCIDR{CIDR: rule.Destination[0].IPBlock.CIDR},
						Ports: []uint32{rule.Destination[0].Ports.Ports[0]},
					},
					Default: types.TetragonNetworkAction{EnforceAction: &types.TetragonEnforceAction{Deny: true}},
					Action:  types.TetragonNetworkAction{EnforceAction: &types.TetragonEnforceAction{}},
				},
				{
					RuleDescription: rule2.Description,
					Subject: types.TetragonNetworkSubject{
						Labels:        types.TetragonNetworkLabels{Equal: map[string]string{"_tnp_kubernetes.io/metadata.name": "default"}},
						InProcessName: []string{"/usr/bin/curl"},
					},
					Destination: types.TetragonNetworkDestination{
						CIDR:  &types.TetragonNetworkCIDR{CIDR: rule2.Destination[0].IPBlock.CIDR},
						Ports: []uint32{rule2.Destination[0].Ports.Ports[0]},
					},
					Default: types.TetragonNetworkAction{EnforceAction: &types.TetragonEnforceAction{Deny: true}},
					Action:  types.TetragonNetworkAction{EnforceAction: &types.TetragonEnforceAction{}},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToTetragonNetworkPolicies(&tt.policy)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToTetragonNetworkPolicies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				jsonGot, err := json.Marshal(got)
				require.NoError(t, err)
				jsonWant, err := json.Marshal(tt.want)
				require.NoError(t, err)
				t.Errorf("got: %v,\nwant: %v", string(jsonGot), string(jsonWant))
			}
		})
	}
}
