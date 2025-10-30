package switchpolicy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
)

func TestConvertRuleToDPUPolicyRule(t *testing.T) {
	tests := []struct {
		name           string
		setupState     func() *State
		rule           *SwitchPolicy
		upsert         bool
		expectedOper   v1alpha.PolicyOperation
		expectedAction v1alpha.PolicyAction
		expectedSrc    dpu.DPUSubject
		expectedDst    dpu.DPUSubject
	}{
		{
			name: "Upsert operation with allow action and TCP",
			setupState: func() *State {
				s := NewState()
				s.networkL3Objects.Add("internal", 100)
				s.networkL3Objects.Add("external", 200)
				return s
			},
			rule: &SwitchPolicy{
				UID: UniqueID{
					PolicyName: "test-policy",
					RuleName:   "rule-1",
				},
				Policy: &SmartSwitchNetworkPolicy{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.0.0.0/8",
							VRF:  "internal",
							VLAN: 100,
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "192.168.1.0/24",
							VRF:  "external",
							VLAN: 200,
						},
						ProtoPorts: &SmartSwitchNetworkProtocolPorts{
							Protocol: "tcp",
							Port:     443,
							EndPort:  443,
						},
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{
							Allow: true,
						},
					},
				},
			},
			upsert:         true,
			expectedOper:   v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
			expectedAction: v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
			expectedSrc: dpu.DPUSubject{
				Cidr:     "10.0.0.0/8",
				MinPort:  0,
				MaxPort:  65535,
				Vlan:     100,
				Vrf:      "internal",
				VrfId:    100,
				Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
			},
			expectedDst: dpu.DPUSubject{
				Cidr:     "192.168.1.0/24",
				MinPort:  443,
				MaxPort:  443,
				Vlan:     200,
				Vrf:      "external",
				VrfId:    200,
				Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
			},
		},
		{
			name: "Delete operation with deny action and UDP",
			setupState: func() *State {
				s := NewState()
				s.networkL3Objects.Add("dmz", 50)
				return s
			},
			rule: &SwitchPolicy{
				UID: UniqueID{
					PolicyName: "deny-policy",
					RuleName:   "rule-2",
				},
				Policy: &SmartSwitchNetworkPolicy{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "172.16.0.0/12",
							VRF:  "dmz",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.0.0.0/8",
							VRF:  "",
						},
						ProtoPorts: &SmartSwitchNetworkProtocolPorts{
							Protocol: "udp",
							Port:     53,
							EndPort:  53,
						},
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{
							Deny: true,
						},
					},
				},
			},
			upsert:         false,
			expectedOper:   v1alpha.PolicyOperation_POLICY_OPERATION_DELETE,
			expectedAction: v1alpha.PolicyAction_POLICY_ACTION_DENY,
			expectedSrc: dpu.DPUSubject{
				Cidr:     "172.16.0.0/12",
				MinPort:  0,
				MaxPort:  65535,
				Vlan:     0,
				Vrf:      "dmz",
				VrfId:    50,
				Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
			},
			expectedDst: dpu.DPUSubject{
				Cidr:     "10.0.0.0/8",
				MinPort:  53,
				MaxPort:  53,
				Vlan:     0,
				Vrf:      "",
				VrfId:    0,
				Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP,
			},
		},
		{
			name: "ICMP protocol",
			setupState: func() *State {
				return NewState()
			},
			rule: &SwitchPolicy{
				UID: UniqueID{
					PolicyName: "icmp-policy",
					RuleName:   "rule-3",
				},
				Policy: &SmartSwitchNetworkPolicy{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.1.0.0/16",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.2.0.0/16",
						},
						ProtoPorts: &SmartSwitchNetworkProtocolPorts{
							Protocol: "icmp",
							Port:     0,
							EndPort:  0,
						},
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{
							Allow: true,
						},
					},
				},
			},
			upsert:         true,
			expectedOper:   v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
			expectedAction: v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
			expectedSrc: dpu.DPUSubject{
				Cidr:     "10.1.0.0/16",
				MinPort:  0,
				MaxPort:  65535,
				Vlan:     0,
				Vrf:      "",
				VrfId:    0,
				Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
			},
			expectedDst: dpu.DPUSubject{
				Cidr:     "10.2.0.0/16",
				MinPort:  0,
				MaxPort:  0,
				Vlan:     0,
				Vrf:      "",
				VrfId:    0,
				Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_ICMP,
			},
		},
		{
			name: "Nil ProtoPorts - defaults to all ports and unspecified protocol",
			setupState: func() *State {
				return NewState()
			},
			rule: &SwitchPolicy{
				UID: UniqueID{
					PolicyName: "no-ports-policy",
					RuleName:   "rule-4",
				},
				Policy: &SmartSwitchNetworkPolicy{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "192.168.0.0/16",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "172.20.0.0/16",
						},
						ProtoPorts: nil,
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{
							Allow: true,
						},
					},
				},
			},
			upsert:         true,
			expectedOper:   v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
			expectedAction: v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
			expectedSrc: dpu.DPUSubject{
				Cidr:     "192.168.0.0/16",
				MinPort:  0,
				MaxPort:  65535,
				Vlan:     0,
				Vrf:      "",
				VrfId:    0,
				Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
			},
			expectedDst: dpu.DPUSubject{
				Cidr:     "172.20.0.0/16",
				MinPort:  0,
				MaxPort:  65535,
				Vlan:     0,
				Vrf:      "",
				VrfId:    0,
				Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
			},
		},
		{
			name: "Port range with EndPort",
			setupState: func() *State {
				return NewState()
			},
			rule: &SwitchPolicy{
				UID: UniqueID{
					PolicyName: "range-policy",
					RuleName:   "rule-5",
				},
				Policy: &SmartSwitchNetworkPolicy{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.10.0.0/16",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.20.0.0/16",
						},
						ProtoPorts: &SmartSwitchNetworkProtocolPorts{
							Protocol: "TCP",
							Port:     8000,
							EndPort:  9000,
						},
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{
							Allow: true,
						},
					},
				},
			},
			upsert:         true,
			expectedOper:   v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
			expectedAction: v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
			expectedSrc: dpu.DPUSubject{
				Cidr:     "10.10.0.0/16",
				MinPort:  0,
				MaxPort:  65535,
				Vlan:     0,
				Vrf:      "",
				VrfId:    0,
				Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
			},
			expectedDst: dpu.DPUSubject{
				Cidr:     "10.20.0.0/16",
				MinPort:  8000,
				MaxPort:  9000,
				Vlan:     0,
				Vrf:      "",
				VrfId:    0,
				Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
			},
		},
		{
			name: "Unknown protocol defaults to unspecified",
			setupState: func() *State {
				return NewState()
			},
			rule: &SwitchPolicy{
				UID: UniqueID{
					PolicyName: "unknown-proto-policy",
					RuleName:   "rule-6",
				},
				Policy: &SmartSwitchNetworkPolicy{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.30.0.0/16",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.40.0.0/16",
						},
						ProtoPorts: &SmartSwitchNetworkProtocolPorts{
							Protocol: "sctp",
							Port:     5000,
							EndPort:  5000,
						},
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{
							Deny: true,
						},
					},
				},
			},
			upsert:         false,
			expectedOper:   v1alpha.PolicyOperation_POLICY_OPERATION_DELETE,
			expectedAction: v1alpha.PolicyAction_POLICY_ACTION_DENY,
			expectedSrc: dpu.DPUSubject{
				Cidr:     "10.30.0.0/16",
				MinPort:  0,
				MaxPort:  65535,
				Vlan:     0,
				Vrf:      "",
				VrfId:    0,
				Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
			},
			expectedDst: dpu.DPUSubject{
				Cidr:     "10.40.0.0/16",
				MinPort:  5000,
				MaxPort:  5000,
				Vlan:     0,
				Vrf:      "",
				VrfId:    0,
				Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
			},
		},
		{
			name: "No action specified - defaults to unspecified",
			setupState: func() *State {
				return NewState()
			},
			rule: &SwitchPolicy{
				UID: UniqueID{
					PolicyName: "no-action-policy",
					RuleName:   "rule-7",
				},
				Policy: &SmartSwitchNetworkPolicy{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.50.0.0/16",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.60.0.0/16",
						},
						ProtoPorts: &SmartSwitchNetworkProtocolPorts{
							Protocol: "tcp",
							Port:     80,
							EndPort:  80,
						},
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{
							Allow: false,
							Deny:  false,
						},
					},
				},
			},
			upsert:         true,
			expectedOper:   v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
			expectedAction: v1alpha.PolicyAction_POLICY_ACTION_UNSPECIFIED,
			expectedSrc: dpu.DPUSubject{
				Cidr:     "10.50.0.0/16",
				MinPort:  0,
				MaxPort:  65535,
				Vlan:     0,
				Vrf:      "",
				VrfId:    0,
				Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
			},
			expectedDst: dpu.DPUSubject{
				Cidr:     "10.60.0.0/16",
				MinPort:  80,
				MaxPort:  80,
				Vlan:     0,
				Vrf:      "",
				VrfId:    0,
				Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
			},
		},
		{
			name: "Empty VRF uses default VRF ID 0",
			setupState: func() *State {
				return NewState()
			},
			rule: &SwitchPolicy{
				UID: UniqueID{
					PolicyName: "default-vrf-policy",
					RuleName:   "rule-8",
				},
				Policy: &SmartSwitchNetworkPolicy{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "0.0.0.0/0",
							VRF:  "",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "0.0.0.0/0",
							VRF:  "",
						},
						ProtoPorts: &SmartSwitchNetworkProtocolPorts{
							Protocol: "tcp",
							Port:     443,
							EndPort:  443,
						},
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{
							Allow: true,
						},
					},
				},
			},
			upsert:         true,
			expectedOper:   v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
			expectedAction: v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
			expectedSrc: dpu.DPUSubject{
				Cidr:     "0.0.0.0/0",
				MinPort:  0,
				MaxPort:  65535,
				Vlan:     0,
				Vrf:      "",
				VrfId:    0,
				Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
			},
			expectedDst: dpu.DPUSubject{
				Cidr:     "0.0.0.0/0",
				MinPort:  443,
				MaxPort:  443,
				Vlan:     0,
				Vrf:      "",
				VrfId:    0,
				Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
			},
		},
		{
			name: "Case insensitive protocol - UDP uppercase",
			setupState: func() *State {
				return NewState()
			},
			rule: &SwitchPolicy{
				UID: UniqueID{
					PolicyName: "upper-proto-policy",
					RuleName:   "rule-9",
				},
				Policy: &SmartSwitchNetworkPolicy{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.70.0.0/16",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "10.80.0.0/16",
						},
						ProtoPorts: &SmartSwitchNetworkProtocolPorts{
							Protocol: "UDP",
							Port:     161,
							EndPort:  161,
						},
					},
					Action: SmartSwitchNetworkAction{
						EnforceAction: SmartSwitchEnforceAction{
							Allow: true,
						},
					},
				},
			},
			upsert:         true,
			expectedOper:   v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
			expectedAction: v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
			expectedSrc: dpu.DPUSubject{
				Cidr:     "10.70.0.0/16",
				MinPort:  0,
				MaxPort:  65535,
				Vlan:     0,
				Vrf:      "",
				VrfId:    0,
				Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
			},
			expectedDst: dpu.DPUSubject{
				Cidr:     "10.80.0.0/16",
				MinPort:  161,
				MaxPort:  161,
				Vlan:     0,
				Vrf:      "",
				VrfId:    0,
				Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := tt.setupState()
			result := state.convertRuleToDPUPolicyRule(tt.rule, tt.upsert)

			require.NotNil(t, result, "Result should not be nil")
			require.NotNil(t, result.Policy, "Result.Policy should not be nil")

			// Verify operation
			require.Equal(t, tt.expectedOper, result.Oper, "Operation mismatch")

			// Verify policy metadata
			require.Equal(t, tt.rule.UID.PolicyName, result.Policy.PolicyName, "PolicyName mismatch")
			require.Equal(t, tt.rule.UID.RuleName, result.Policy.RuleName, "RuleName mismatch")

			// Verify action
			require.Equal(t, tt.expectedAction, result.Policy.Action, "Action mismatch")

			// Verify source
			require.Equal(t, tt.expectedSrc.Cidr, result.Policy.Source.Cidr, "Source CIDR mismatch")
			require.Equal(t, tt.expectedSrc.MinPort, result.Policy.Source.MinPort, "Source MinPort mismatch")
			require.Equal(t, tt.expectedSrc.MaxPort, result.Policy.Source.MaxPort, "Source MaxPort mismatch")
			require.Equal(t, tt.expectedSrc.Vlan, result.Policy.Source.Vlan, "Source VLAN mismatch")
			require.Equal(t, tt.expectedSrc.Vrf, result.Policy.Source.Vrf, "Source VRF mismatch")
			require.Equal(t, tt.expectedSrc.VrfId, result.Policy.Source.VrfId, "Source VrfId mismatch")
			require.Equal(t, tt.expectedSrc.Protocol, result.Policy.Source.Protocol, "Source Protocol mismatch")

			// Verify destination
			require.Equal(t, tt.expectedDst.Cidr, result.Policy.Destination.Cidr, "Destination CIDR mismatch")
			require.Equal(t, tt.expectedDst.MinPort, result.Policy.Destination.MinPort, "Destination MinPort mismatch")
			require.Equal(t, tt.expectedDst.MaxPort, result.Policy.Destination.MaxPort, "Destination MaxPort mismatch")
			require.Equal(t, tt.expectedDst.Vlan, result.Policy.Destination.Vlan, "Destination VLAN mismatch")
			require.Equal(t, tt.expectedDst.Vrf, result.Policy.Destination.Vrf, "Destination VRF mismatch")
			require.Equal(t, tt.expectedDst.VrfId, result.Policy.Destination.VrfId, "Destination VrfId mismatch")
			require.Equal(t, tt.expectedDst.Protocol, result.Policy.Destination.Protocol, "Destination Protocol mismatch")
		})
	}
}
