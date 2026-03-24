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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

func TestConvertRuleToDPUPolicyRule(t *testing.T) {
	tests := []struct {
		name           string
		setupState     func() *State
		rule           *SwitchPolicy
		upsert         bool
		expectedOper   v1alpha.PolicyOperation
		expectedAction v1alpha.PolicyAction
		expectedSrc    DPUSubject
		expectedDst    DPUSubject
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
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
								Port:     443,
								EndPort:  443,
							},
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
			expectedSrc: DPUSubject{
				Cidr: "10.0.0.0/8",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     0,
						EndPort:  65535,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
					},
				},
				Vlan:  100,
				Vrf:   "internal",
				VrfId: 100,
			},
			expectedDst: DPUSubject{
				Cidr: "192.168.1.0/24",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     443,
						EndPort:  443,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
					},
				},
				Vlan:  200,
				Vrf:   "external",
				VrfId: 200,
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
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP,
								Port:     53,
								EndPort:  53,
							},
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
			expectedSrc: DPUSubject{
				Cidr: "172.16.0.0/12",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     0,
						EndPort:  65535,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
					},
				},
				Vlan:  0,
				Vrf:   "dmz",
				VrfId: 50,
			},
			expectedDst: DPUSubject{
				Cidr: "10.0.0.0/8",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     53,
						EndPort:  53,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP,
					},
				},
				Vlan:  0,
				Vrf:   "",
				VrfId: 0,
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
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_ICMP,
								Port:     0,
								EndPort:  0,
							},
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
			expectedSrc: DPUSubject{
				Cidr: "10.1.0.0/16",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     0,
						EndPort:  65535,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
					},
				},
				Vlan:  0,
				Vrf:   "",
				VrfId: 0,
			},
			expectedDst: DPUSubject{
				Cidr: "10.2.0.0/16",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     0,
						EndPort:  0,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_ICMP,
					},
				},
				Vlan:  0,
				Vrf:   "",
				VrfId: 0,
			},
		},
		{
			name: "Empty ProtoPorts - defaults to all ports and unspecified protocol",
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
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{},
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
			expectedSrc: DPUSubject{
				Cidr: "192.168.0.0/16",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     0,
						EndPort:  65535,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
					},
				},
				Vlan:  0,
				Vrf:   "",
				VrfId: 0,
			},
			expectedDst: DPUSubject{
				Cidr:  "172.20.0.0/16",
				Ports: &[]SmartSwitchNetworkProtocolPorts{},
				Vlan:  0,
				Vrf:   "",
				VrfId: 0,
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
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
								Port:     8000,
								EndPort:  9000,
							},
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
			expectedSrc: DPUSubject{
				Cidr: "10.10.0.0/16",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     0,
						EndPort:  65535,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
					},
				},
				Vlan:  0,
				Vrf:   "",
				VrfId: 0,
			},
			expectedDst: DPUSubject{
				Cidr: "10.20.0.0/16",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     8000,
						EndPort:  9000,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
					},
				},
				Vlan:  0,
				Vrf:   "",
				VrfId: 0,
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
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
								Port:     5000,
								EndPort:  5000,
							},
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
			expectedSrc: DPUSubject{
				Cidr: "10.30.0.0/16",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     0,
						EndPort:  65535,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
					},
				},
				Vlan:  0,
				Vrf:   "",
				VrfId: 0,
			},
			expectedDst: DPUSubject{
				Cidr: "10.40.0.0/16",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     5000,
						EndPort:  5000,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
					},
				},
				Vlan:  0,
				Vrf:   "",
				VrfId: 0,
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
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
								Port:     80,
								EndPort:  80,
							},
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
			expectedSrc: DPUSubject{
				Cidr: "10.50.0.0/16",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     0,
						EndPort:  65535,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
					},
				},
				Vlan:  0,
				Vrf:   "",
				VrfId: 0,
			},
			expectedDst: DPUSubject{
				Cidr: "10.60.0.0/16",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     80,
						EndPort:  80,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
					},
				},
				Vlan:  0,
				Vrf:   "",
				VrfId: 0,
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
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
								Port:     443,
								EndPort:  443,
							},
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
			expectedSrc: DPUSubject{
				Cidr: "0.0.0.0/0",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     0,
						EndPort:  65535,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
					},
				},
				Vlan:  0,
				Vrf:   "",
				VrfId: 0,
			},
			expectedDst: DPUSubject{
				Cidr: "0.0.0.0/0",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     443,
						EndPort:  443,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
					},
				},
				Vlan:  0,
				Vrf:   "",
				VrfId: 0,
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
						ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
							SmartSwitchNetworkProtocolPorts{
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP,
								Port:     161,
								EndPort:  161,
							},
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
			expectedSrc: DPUSubject{
				Cidr: "10.70.0.0/16",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     0,
						EndPort:  65535,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED,
					},
				},
				Vlan:  0,
				Vrf:   "",
				VrfId: 0,
			},
			expectedDst: DPUSubject{
				Cidr: "10.80.0.0/16",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     161,
						EndPort:  161,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP,
					},
				},
				Vlan:  0,
				Vrf:   "",
				VrfId: 0,
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
			require.Equal(t, tt.expectedSrc.Vlan, result.Policy.Source.Vlan, "Source VLAN mismatch")
			require.Equal(t, tt.expectedSrc.Vrf, result.Policy.Source.Vrf, "Source VRF mismatch")
			require.Equal(t, tt.expectedSrc.VrfId, result.Policy.Source.VrfId, "Source VrfId mismatch")

			// Verify destination
			require.Equal(t, tt.expectedDst.Cidr, result.Policy.Destination.Cidr, "Destination CIDR mismatch")
			require.Equal(t, tt.expectedDst.Vlan, result.Policy.Destination.Vlan, "Destination VLAN mismatch")
			require.Equal(t, tt.expectedDst.Vrf, result.Policy.Destination.Vrf, "Destination VRF mismatch")
			require.Equal(t, tt.expectedDst.VrfId, result.Policy.Destination.VrfId, "Destination VrfId mismatch")

			p := *tt.expectedDst.Ports
			r := *result.Policy.Destination.Ports
			if len(p) > 0 {
				require.Equal(t, p[0].Port, r[0].Port, "Destination MinPort mismatch")
				require.Equal(t, p[0].EndPort, r[0].EndPort, "Destination MaxPort mismatch")
				require.Equal(t, p[0].Protocol, r[0].Protocol, "Destination Protocol mismatch")
			} else {
				require.Equal(t, 0, len(r))
			}
		})
	}
}

func TestInterVRFPolicyAppliedWhenDestinationVRFAddedLater(t *testing.T) {
	s := NewState()

	// Only source VRF exists at first
	require.NoError(t, s.SetL3Networks(&L3Networks{byName: map[VrfName]VrfGID{"": 0, "internal": 100}, byGID: map[VrfGID]VrfName{0: "", 100: "internal"}}))

	rule := &SwitchPolicy{
		UID: UniqueID{PolicyName: "test-policy", RuleName: "rule-1"},
		Policy: &SmartSwitchNetworkPolicy{
			K8SResourceVersion: "1",
			K8SUid:             "uid",
			K8SIndex:           1,
			Source:             SmartSwitchNetworkSource{Endpoint: SmartSwitchNetworkEndpoint{CIDR: "10.0.0.0/8", VRF: "internal", VLAN: 0}},
			Destination:        SmartSwitchNetworkDestination{Endpoint: SmartSwitchNetworkEndpoint{CIDR: "192.168.0.0/16", VRF: "external", VLAN: 0}, ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{}},
			Action:             SmartSwitchNetworkAction{EnforceAction: SmartSwitchEnforceAction{Allow: true}},
			Default:            SmartSwitchNetworkAction{EnforceAction: SmartSwitchEnforceAction{Deny: true}},
		},
	}

	// Add policy before destination VRF exists: should not emit any delta
	require.NoError(t, s.AddRule(1, rule))
	delta := s.GetDeltaToApply()
	require.Len(t, delta, 0)

	// Add destination VRF: policy should now be emitted
	require.NoError(t, s.SetL3Networks(&L3Networks{byName: map[VrfName]VrfGID{"": 0, "internal": 100, "external": 200}, byGID: map[VrfGID]VrfName{0: "", 100: "internal", 200: "external"}}))
	delta = s.GetDeltaToApply()
	require.Len(t, delta, 1)
	require.Equal(t, v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT, delta[0].Oper)
	require.Equal(t, uint32(100), delta[0].Policy.Source.VrfId)
	require.Equal(t, uint32(200), delta[0].Policy.Destination.VrfId)
}

func TestAddRule_DuplicateVRFDoesNotRecreatePolicyByVRFNameEntry(t *testing.T) {
	s := NewState()

	vrfName := VrfName("internal")
	existing := make(map[RuleID]*SwitchPolicy)
	existing[RuleID(99)] = nil
	s.policyByVRFName[vrfName] = existing

	rule := &SwitchPolicy{
		UID: UniqueID{PolicyName: "test-policy", RuleName: "rule-1"},
		Policy: &SmartSwitchNetworkPolicy{
			K8SResourceVersion: "1",
			K8SUid:             "uid",
			K8SIndex:           1,
			Source:             SmartSwitchNetworkSource{Endpoint: SmartSwitchNetworkEndpoint{CIDR: "10.0.0.0/8", VRF: string(vrfName), VLAN: 100}},
			Destination:        SmartSwitchNetworkDestination{Endpoint: SmartSwitchNetworkEndpoint{CIDR: "192.168.0.0/16", VRF: string(vrfName), VLAN: 200}, ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{}},
			Action:             SmartSwitchNetworkAction{EnforceAction: SmartSwitchEnforceAction{Allow: true}},
			Default:            SmartSwitchNetworkAction{EnforceAction: SmartSwitchEnforceAction{Deny: true}},
		},
	}

	require.NoError(t, s.AddRule(1, rule))
	require.Len(t, s.policyByVRFName, 1)
	require.Contains(t, s.policyByVRFName[vrfName], RuleID(99))
	require.Contains(t, s.policyByVRFName[vrfName], RuleID(1))
}

func TestRemoveRuleByID_RemovingFromSourceDoesNotBreakDestinationCleanup(t *testing.T) {
	s := NewState()

	rule1 := &SwitchPolicy{
		UID: UniqueID{PolicyName: "test-policy", RuleName: "rule-1"},
		Policy: &SmartSwitchNetworkPolicy{
			K8SResourceVersion: "1",
			K8SUid:             "uid-1",
			K8SIndex:           1,
			Source:             SmartSwitchNetworkSource{Endpoint: SmartSwitchNetworkEndpoint{CIDR: "10.0.0.0/8", VRF: "src", VLAN: 100}},
			Destination:        SmartSwitchNetworkDestination{Endpoint: SmartSwitchNetworkEndpoint{CIDR: "192.168.0.0/16", VRF: "dst", VLAN: 200}, ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{}},
			Action:             SmartSwitchNetworkAction{EnforceAction: SmartSwitchEnforceAction{Allow: true}},
			Default:            SmartSwitchNetworkAction{EnforceAction: SmartSwitchEnforceAction{Deny: true}},
		},
	}

	rule2 := &SwitchPolicy{
		UID: UniqueID{PolicyName: "test-policy", RuleName: "rule-2"},
		Policy: &SmartSwitchNetworkPolicy{
			K8SResourceVersion: "1",
			K8SUid:             "uid-2",
			K8SIndex:           2,
			Source:             SmartSwitchNetworkSource{Endpoint: SmartSwitchNetworkEndpoint{CIDR: "10.0.0.0/8", VRF: "src", VLAN: 100}},
			Destination:        SmartSwitchNetworkDestination{Endpoint: SmartSwitchNetworkEndpoint{CIDR: "172.16.0.0/12", VRF: "other", VLAN: 300}, ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{}},
			Action:             SmartSwitchNetworkAction{EnforceAction: SmartSwitchEnforceAction{Allow: true}},
			Default:            SmartSwitchNetworkAction{EnforceAction: SmartSwitchEnforceAction{Deny: true}},
		},
	}

	require.NoError(t, s.AddRule(1, rule1))
	require.NoError(t, s.AddRule(2, rule2))

	require.Contains(t, s.policyByVRFName, VrfName("src"))
	require.Contains(t, s.policyByVRFName, VrfName("dst"))
	require.Contains(t, s.policyByVRFName, VrfName("other"))

	require.NoError(t, s.RemoveRuleByID(1))

	require.Contains(t, s.policyByVRFName, VrfName("src"))
	require.Contains(t, s.policyByVRFName, VrfName("other"))
	require.NotContains(t, s.policyByVRFName, VrfName("dst"))

	require.NotContains(t, s.policyByVRFName[VrfName("src")], RuleID(1))
	require.Contains(t, s.policyByVRFName[VrfName("src")], RuleID(2))
}

