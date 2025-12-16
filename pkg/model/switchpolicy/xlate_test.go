package switchpolicy

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	isovalentv1 "github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

func TestToSmartSwitchNetworkPolicies(t *testing.T) {
	tests := []struct {
		name    string
		policy  isovalentv1.SmartSwitchNetworkPolicy
		want    []*SmartSwitchNetworkPolicy
		wantErr bool
	}{
		{
			name: "Single rule with VRF source and destination",
			policy: isovalentv1.SmartSwitchNetworkPolicy{
				Spec: isovalentv1.SmartSwitchNetworkPolicySpec{
					Rules: []isovalentv1.SmartSwitchNetworkPolicyRule{
						{
							Description: "Allow traffic from internal VRF to external VRF",
							Action:      "allow",
							Source: isovalentv1.SmartSwitchNetworkSource{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "10.0.0.0/8",
										VRF:  "internal",
									},
								},
							},
							Destination: isovalentv1.SmartSwitchNetworkDestination{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "8.8.8.8/32",
										VRF:  "external",
									},
								},
								ProtoPorts: []isovalentv1.SmartSwitchProtocolPort{
									{
										Port:     443,
										Protocol: "TCP",
									},
								},
							},
						},
					},
				},
			},
			want: []*SmartSwitchNetworkPolicy{
				{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.0.0.0/8",
							VRF:  "internal",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "8.8.8.8/32",
							VRF:  "external",
						},
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{
								Port:     443,
								EndPort:  443,
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
							},
						},
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Allow: true},
					},
					Default: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Deny: true},
					},
				},
			},
		},
		{
			name: "Single rule with VLAN source and destination",
			policy: isovalentv1.SmartSwitchNetworkPolicy{
				Spec: isovalentv1.SmartSwitchNetworkPolicySpec{
					Rules: []isovalentv1.SmartSwitchNetworkPolicyRule{
						{
							Description: "Deny traffic between VLANs",
							Action:      "deny",
							Source: isovalentv1.SmartSwitchNetworkSource{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "192.168.1.0/24",
										VLAN: 100,
									},
								},
							},
							Destination: isovalentv1.SmartSwitchNetworkDestination{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "192.168.2.0/24",
										VLAN: 200,
									},
								},
								ProtoPorts: []isovalentv1.SmartSwitchProtocolPort{
									{
										Port:     80,
										Protocol: "TCP",
									},
								},
							},
						},
					},
				},
			},
			want: []*SmartSwitchNetworkPolicy{
				{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "192.168.1.0/24",
							VLAN: 100,
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "192.168.2.0/24",
							VLAN: 200,
						},
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{
								Port:     80,
								EndPort:  80,
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
							},
						},
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Deny: true},
					},
					Default: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Deny: true},
					},
				},
			},
		},
		{
			name: "Multiple sources and destinations create cross product",
			policy: isovalentv1.SmartSwitchNetworkPolicy{
				Spec: isovalentv1.SmartSwitchNetworkPolicySpec{
					Rules: []isovalentv1.SmartSwitchNetworkPolicyRule{
						{
							Description: "Allow HTTP and HTTPS from multiple sources",
							Action:      "allow",
							Source: isovalentv1.SmartSwitchNetworkSource{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "10.0.1.0/24",
										VRF:  "vrf-1",
									},
									{
										CIDR: "10.0.2.0/24",
										VRF:  "vrf-1",
									},
								},
							},
							Destination: isovalentv1.SmartSwitchNetworkDestination{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "192.168.1.100/32",
										VRF:  "vrf-2",
									},
									{
										CIDR: "192.168.1.101/32",
										VRF:  "vrf-2",
									},
								},
								ProtoPorts: []isovalentv1.SmartSwitchProtocolPort{
									{
										Port:     80,
										Protocol: "TCP",
									},
									{
										Port:     443,
										Protocol: "TCP",
									},
								},
							},
						},
					},
				},
			},
			want: []*SmartSwitchNetworkPolicy{
				// Source 1, Dest 1, Port 80
				{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.0.1.0/24",
							VRF:  "vrf-1",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "192.168.1.100/32",
							VRF:  "vrf-2",
						},
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{
								Port:     80,
								EndPort:  80,
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
							},
							SmartSwitchNetworkProtocolPorts{
								Port:     443,
								EndPort:  443,
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
							},
						},
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Allow: true},
					},
					Default: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Deny: true},
					},
				},
				// Source 1, Dest 2, Port 80
				{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.0.1.0/24",
							VRF:  "vrf-1",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "192.168.1.101/32",
							VRF:  "vrf-2",
						},
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{
								Port:     80,
								EndPort:  80,
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
							},
							SmartSwitchNetworkProtocolPorts{
								Port:     443,
								EndPort:  443,
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
							},
						},
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Allow: true},
					},
					Default: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Deny: true},
					},
				},
				// Source 2, Dest 1, Port 80
				{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.0.2.0/24",
							VRF:  "vrf-1",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "192.168.1.100/32",
							VRF:  "vrf-2",
						},
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{
								Port:     80,
								EndPort:  80,
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
							},
							SmartSwitchNetworkProtocolPorts{
								Port:     443,
								EndPort:  443,
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
							},
						},
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Allow: true},
					},
					Default: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Deny: true},
					},
				},
				// Source 2, Dest 2, Port 80
				{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.0.2.0/24",
							VRF:  "vrf-1",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "192.168.1.101/32",
							VRF:  "vrf-2",
						},
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{
								Port:     80,
								EndPort:  80,
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
							},
							SmartSwitchNetworkProtocolPorts{
								Port:     443,
								EndPort:  443,
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
							},
						},
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Allow: true},
					},
					Default: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Deny: true},
					},
				},
			},
		},
		{
			name: "Multiple rules result in multiple policies",
			policy: isovalentv1.SmartSwitchNetworkPolicy{
				Spec: isovalentv1.SmartSwitchNetworkPolicySpec{
					Rules: []isovalentv1.SmartSwitchNetworkPolicyRule{
						{
							Description: "Allow HTTPS",
							Action:      "allow",
							Source: isovalentv1.SmartSwitchNetworkSource{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "10.0.0.0/8",
									},
								},
							},
							Destination: isovalentv1.SmartSwitchNetworkDestination{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "8.8.8.8/32",
									},
								},
								ProtoPorts: []isovalentv1.SmartSwitchProtocolPort{
									{
										Port:     443,
										Protocol: "TCP",
									},
									{
										Port:     53,
										Protocol: "UDP",
									},
								},
							},
						},
					},
				},
			},
			want: []*SmartSwitchNetworkPolicy{
				{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.0.0.0/8",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "8.8.8.8/32",
						},
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{
								Port:     443,
								EndPort:  443,
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
							},
							SmartSwitchNetworkProtocolPorts{
								Port:     53,
								EndPort:  53,
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP,
							},
						},
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Allow: true},
					},
					Default: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Deny: true},
					},
				},
			},
		},
		{
			name: "Port range support",
			policy: isovalentv1.SmartSwitchNetworkPolicy{
				Spec: isovalentv1.SmartSwitchNetworkPolicySpec{
					Rules: []isovalentv1.SmartSwitchNetworkPolicyRule{
						{
							Description: "Allow port range 8000-8080",
							Action:      "allow",
							Source: isovalentv1.SmartSwitchNetworkSource{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "10.0.0.0/8",
										VLAN: 100,
									},
								},
							},
							Destination: isovalentv1.SmartSwitchNetworkDestination{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "192.168.1.0/24",
										VLAN: 200,
									},
								},
								ProtoPorts: []isovalentv1.SmartSwitchProtocolPort{
									{
										Port:     8000,
										EndPort:  8080,
										Protocol: "TCP",
									},
								},
							},
						},
					},
				},
			},
			want: []*SmartSwitchNetworkPolicy{
				{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.0.0.0/8",
							VLAN: 100,
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "192.168.1.0/24",
							VLAN: 200,
						},
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{
								Port:     8000,
								EndPort:  8080,
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
							},
						},
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Allow: true},
					},
					Default: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Deny: true},
					},
				},
			},
		},
		{
			name: "Empty rules list",
			policy: isovalentv1.SmartSwitchNetworkPolicy{
				Spec: isovalentv1.SmartSwitchNetworkPolicySpec{
					Rules: []isovalentv1.SmartSwitchNetworkPolicyRule{},
				},
			},
			want: []*SmartSwitchNetworkPolicy{},
		},
		{
			name: "Protocol only without port - match all ports for protocol",
			policy: isovalentv1.SmartSwitchNetworkPolicy{
				Spec: isovalentv1.SmartSwitchNetworkPolicySpec{
					Rules: []isovalentv1.SmartSwitchNetworkPolicyRule{
						{
							Description: "Allow all TCP traffic",
							Action:      "allow",
							Source: isovalentv1.SmartSwitchNetworkSource{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "10.0.0.0/8",
									},
								},
							},
							Destination: isovalentv1.SmartSwitchNetworkDestination{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "192.168.1.0/24",
									},
								},
								ProtoPorts: []isovalentv1.SmartSwitchProtocolPort{
									{
										Protocol: "TCP",
									},
								},
							},
						},
					},
				},
			},
			want: []*SmartSwitchNetworkPolicy{
				{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.0.0.0/8",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "192.168.1.0/24",
						},
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
							},
						},
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Allow: true},
					},
					Default: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Deny: true},
					},
				},
			},
		},
		{
			name: "Multiple protocols without ports",
			policy: isovalentv1.SmartSwitchNetworkPolicy{
				Spec: isovalentv1.SmartSwitchNetworkPolicySpec{
					Rules: []isovalentv1.SmartSwitchNetworkPolicyRule{
						{
							Description: "Allow TCP and UDP traffic",
							Action:      "allow",
							Source: isovalentv1.SmartSwitchNetworkSource{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "10.0.0.0/8",
										VRF:  "internal",
									},
								},
							},
							Destination: isovalentv1.SmartSwitchNetworkDestination{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "192.168.1.0/24",
										VRF:  "external",
									},
								},
								ProtoPorts: []isovalentv1.SmartSwitchProtocolPort{
									{
										Protocol: "TCP",
									},
									{
										Protocol: "UDP",
									},
								},
							},
						},
					},
				},
			},
			want: []*SmartSwitchNetworkPolicy{
				{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.0.0.0/8",
							VRF:  "internal",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "192.168.1.0/24",
							VRF:  "external",
						},
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
							},
							SmartSwitchNetworkProtocolPorts{
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP,
							},
						},
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Allow: true},
					},
					Default: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Deny: true},
					},
				},
			},
		},
		{
			name: "Port without protocol",
			policy: isovalentv1.SmartSwitchNetworkPolicy{
				Spec: isovalentv1.SmartSwitchNetworkPolicySpec{
					Rules: []isovalentv1.SmartSwitchNetworkPolicyRule{
						{
							Description: "Allow port 443 any protocol",
							Action:      "allow",
							Source: isovalentv1.SmartSwitchNetworkSource{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "10.0.0.0/8",
									},
								},
							},
							Destination: isovalentv1.SmartSwitchNetworkDestination{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "192.168.1.0/24",
									},
								},
								ProtoPorts: []isovalentv1.SmartSwitchProtocolPort{
									{
										Port: 443,
									},
								},
							},
						},
					},
				},
			},
			want: []*SmartSwitchNetworkPolicy{
				{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.0.0.0/8",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "192.168.1.0/24",
						},
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{
								Port:    443,
								EndPort: 443,
							},
						},
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Allow: true},
					},
					Default: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Deny: true},
					},
				},
			},
		},
		{
			name: "Empty source IPBlock array",
			policy: isovalentv1.SmartSwitchNetworkPolicy{
				Spec: isovalentv1.SmartSwitchNetworkPolicySpec{
					Rules: []isovalentv1.SmartSwitchNetworkPolicyRule{
						{
							Description: "Rule with no sources",
							Action:      "allow",
							Source: isovalentv1.SmartSwitchNetworkSource{
								IPBlock: []isovalentv1.SmartSwitchNetwork{},
							},
							Destination: isovalentv1.SmartSwitchNetworkDestination{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "192.168.1.0/24",
									},
								},
								ProtoPorts: []isovalentv1.SmartSwitchProtocolPort{
									{
										Port:     443,
										Protocol: "TCP",
									},
								},
							},
						},
					},
				},
			},
			want: []*SmartSwitchNetworkPolicy{},
		},
		{
			name: "Empty destination IPBlock array",
			policy: isovalentv1.SmartSwitchNetworkPolicy{
				Spec: isovalentv1.SmartSwitchNetworkPolicySpec{
					Rules: []isovalentv1.SmartSwitchNetworkPolicyRule{
						{
							Description: "Rule with no destinations",
							Action:      "allow",
							Source: isovalentv1.SmartSwitchNetworkSource{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "10.0.0.0/8",
									},
								},
							},
							Destination: isovalentv1.SmartSwitchNetworkDestination{
								IPBlock: []isovalentv1.SmartSwitchNetwork{},
								ProtoPorts: []isovalentv1.SmartSwitchProtocolPort{
									{
										Port:     443,
										Protocol: "TCP",
									},
								},
							},
						},
					},
				},
			},
			want: []*SmartSwitchNetworkPolicy{},
		},
		{
			name: "Mixed protocol specifications - some with ports, some without",
			policy: isovalentv1.SmartSwitchNetworkPolicy{
				Spec: isovalentv1.SmartSwitchNetworkPolicySpec{
					Rules: []isovalentv1.SmartSwitchNetworkPolicyRule{
						{
							Description: "Allow specific TCP port and all UDP",
							Action:      "allow",
							Source: isovalentv1.SmartSwitchNetworkSource{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "10.0.0.0/8",
									},
								},
							},
							Destination: isovalentv1.SmartSwitchNetworkDestination{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "192.168.1.0/24",
									},
								},
								ProtoPorts: []isovalentv1.SmartSwitchProtocolPort{
									{
										Port:     443,
										Protocol: "TCP",
									},
									{
										Protocol: "UDP",
									},
								},
							},
						},
					},
				},
			},
			want: []*SmartSwitchNetworkPolicy{
				{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.0.0.0/8",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "192.168.1.0/24",
						},
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{
								Port:     443,
								EndPort:  443,
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
							},
							SmartSwitchNetworkProtocolPorts{
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP,
							},
						},
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Allow: true},
					},
					Default: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Deny: true},
					},
				},
			},
		},
		{
			name: "Zero port value",
			policy: isovalentv1.SmartSwitchNetworkPolicy{
				Spec: isovalentv1.SmartSwitchNetworkPolicySpec{
					Rules: []isovalentv1.SmartSwitchNetworkPolicyRule{
						{
							Description: "Rule with zero port",
							Action:      "allow",
							Source: isovalentv1.SmartSwitchNetworkSource{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "10.0.0.0/8",
									},
								},
							},
							Destination: isovalentv1.SmartSwitchNetworkDestination{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "192.168.1.0/24",
									},
								},
								ProtoPorts: []isovalentv1.SmartSwitchProtocolPort{
									{
										Port:     0,
										Protocol: "TCP",
									},
								},
							},
						},
					},
				},
			},
			want: []*SmartSwitchNetworkPolicy{
				{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.0.0.0/8",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "192.168.1.0/24",
						},
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{
								Port:     0,
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
							},
						},
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Allow: true},
					},
					Default: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Deny: true},
					},
				},
			},
		},
		{
			name: "ICMP protocol without port",
			policy: isovalentv1.SmartSwitchNetworkPolicy{
				Spec: isovalentv1.SmartSwitchNetworkPolicySpec{
					Rules: []isovalentv1.SmartSwitchNetworkPolicyRule{
						{
							Description: "Allow ICMP",
							Action:      "allow",
							Source: isovalentv1.SmartSwitchNetworkSource{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "10.0.0.0/8",
										VRF:  "internal",
									},
								},
							},
							Destination: isovalentv1.SmartSwitchNetworkDestination{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{
										CIDR: "192.168.1.0/24",
										VRF:  "external",
									},
								},
								ProtoPorts: []isovalentv1.SmartSwitchProtocolPort{
									{
										Protocol: "ICMP",
									},
								},
							},
						},
					},
				},
			},
			want: []*SmartSwitchNetworkPolicy{
				{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.0.0.0/8",
							VRF:  "internal",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "192.168.1.0/24",
							VRF:  "external",
						},
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_ICMP,
							},
						},
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Allow: true},
					},
					Default: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{Deny: true},
					},
				},
			},
		},
		{
			name: "Mixed IPv4/IPv6 CIDRs only map same-family",
			policy: isovalentv1.SmartSwitchNetworkPolicy{
				Spec: isovalentv1.SmartSwitchNetworkPolicySpec{
					Rules: []isovalentv1.SmartSwitchNetworkPolicyRule{
						{
							Description: "Allow mixed v4/v6",
							Action:      "allow",
							Source: isovalentv1.SmartSwitchNetworkSource{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{CIDR: "10.0.0.0/8"},
									{CIDR: "2001:db8::/32"},
								},
							},
							Destination: isovalentv1.SmartSwitchNetworkDestination{
								IPBlock: []isovalentv1.SmartSwitchNetwork{
									{CIDR: "192.168.1.0/24"},
									{CIDR: "2001:db8:1::/48"},
								},
								ProtoPorts: []isovalentv1.SmartSwitchProtocolPort{
									{Protocol: "TCP"},
								},
							},
						},
					},
				},
			},
			want: []*SmartSwitchNetworkPolicy{
				{
					Source: SmartSwitchNetworkSource{Endpoint: SmartSwitchNetworkEndpoint{CIDR: "10.0.0.0/8"}},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{CIDR: "192.168.1.0/24"},
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP},
						},
					},
					Action:  SmartSwitchNetworkAction{EnforceAction: SmartSwitchEnforceAction{Allow: true}},
					Default: SmartSwitchNetworkAction{EnforceAction: SmartSwitchEnforceAction{Deny: true}},
				},
				{
					Source: SmartSwitchNetworkSource{Endpoint: SmartSwitchNetworkEndpoint{CIDR: "2001:db8::/32"}},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{CIDR: "2001:db8:1::/48"},
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP},
						},
					},
					Action:  SmartSwitchNetworkAction{EnforceAction: SmartSwitchEnforceAction{Allow: true}},
					Default: SmartSwitchNetworkAction{EnforceAction: SmartSwitchEnforceAction{Deny: true}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToSmartSwitchNetworkPolicies(&tt.policy)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToSmartSwitchNetworkPolicies() error = %v, wantErr %v", err, tt.wantErr)
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
