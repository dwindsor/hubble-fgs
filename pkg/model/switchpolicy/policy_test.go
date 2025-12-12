package switchpolicy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

// TestYAMLPolicyToDPURuleConversion tests the full conversion pipeline from YAML policy
// definition to DPURule, verifying that the conversion is done correctly and the
// DPURules are formatted correctly.
func TestYAMLPolicyToDPURuleConversion(t *testing.T) {
	tests := []struct {
		name           string
		yaml           string
		l3Networks     *L3Networks
		expectedRules  []*DPURule
		expectedAction v1alpha.PolicyAction
		wantErr        bool
	}{
		{
			name: "Policy with multiple protocols",
			yaml: `
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: multi-protocol-policy
  namespace: default
spec:
  rules:
    - action: allow
      description: "Allow TCP and UDP"
      source:
        ipBlock:
          - cidr: 10.0.0.0/8
            vrf: internal
      destination:
        ipBlock:
          - cidr: 192.168.1.0/24
        protoPorts:
          - protocol: TCP
            port: 443
          - protocol: UDP
            port: 53
          - protocol: TCP
            port: 8000
            endPort: 8080
          - protocol: UDP
            port: 8000
            endPort: 8080
`,
			l3Networks: func() *L3Networks {
				l3 := NewL3Networks()
				l3.Add("internal", 1)
				return l3
			}(),
			expectedRules: []*DPURule{
				{
					PolicyName: "multi-protocol-policy",
					Action:     v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
					Source: DPUSubject{
						Cidr:  "10.0.0.0/8",
						Vrf:   "internal",
						VrfId: 1,
					},
					Destination: DPUSubject{
						Cidr: "192.168.1.0/24",
						Ports: &[]SmartSwitchNetworkProtocolPorts{
							{
								Port:     443,
								EndPort:  443,
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
							},
							{
								Port:     53,
								EndPort:  53,
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP,
							},
							{
								Port:     8000,
								EndPort:  8080,
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
							},
							{
								Port:     8000,
								EndPort:  8080,
								Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP,
							},
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Step 1: Parse YAML to SmartSwitchNetworkPolicy
			policies, err := FromYAML(tt.yaml)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, policies, 1, "Expected exactly one policy from YAML")

			policy := policies[0]

			// Step 2: Convert to SmartSwitchNetworkPolicy internal representation
			internalPolicies, err := ToSmartSwitchNetworkPolicies(policy)
			require.NoError(t, err)
			require.NotEmpty(t, internalPolicies, "Expected at least one internal policy")

			// Step 3: Create state and add L3 networks
			state := NewState()
			err = state.SetL3Networks(tt.l3Networks)
			require.NoError(t, err)

			// Step 4: Add rules to state and get DPU rules
			var dpuRules []*DPUPolicyRule
			for i, internalPolicy := range internalPolicies {
				ruleID := RuleID(i + 1)
				switchPolicy := &SwitchPolicy{
					UID: UniqueID{
						PolicyName: policy.Name,
						RuleName:   policy.Name,
					},
					Policy: internalPolicy,
				}
				err = state.AddRule(ruleID, switchPolicy)
				require.NoError(t, err)
			}

			// Get the delta (DPU rules to apply)
			dpuRules = state.GetDeltaToApply()
			require.Len(t, dpuRules, len(tt.expectedRules), "Expected %d DPU rules, got %d", len(tt.expectedRules), len(dpuRules))

			// Step 5: Verify DPU rules are correctly formatted
			for i, dpuRule := range dpuRules {
				require.NotNil(t, dpuRule.Policy, "DPU rule policy should not be nil")

				// Verify operation is UPSERT for new rules
				require.Equal(t, v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT, dpuRule.Oper,
					"Expected UPSERT operation for new rule")

				// Find matching expected rule
				found := false
				for _, expected := range tt.expectedRules {
					if dpuRule.Policy.Source.Cidr == expected.Source.Cidr &&
						dpuRule.Policy.Destination.Cidr == expected.Destination.Cidr {
						found = true

						// Verify policy name
						require.Equal(t, expected.PolicyName, dpuRule.Policy.PolicyName,
							"Rule %d: PolicyName mismatch", i)

						// Verify action
						require.Equal(t, expected.Action, dpuRule.Policy.Action,
							"Rule %d: Action mismatch", i)

						// Verify source
						require.Equal(t, expected.Source.Cidr, dpuRule.Policy.Source.Cidr,
							"Rule %d: Source CIDR mismatch", i)
						require.Equal(t, expected.Source.Vrf, dpuRule.Policy.Source.Vrf,
							"Rule %d: Source VRF mismatch", i)
						require.Equal(t, expected.Source.VrfId, dpuRule.Policy.Source.VrfId,
							"Rule %d: Source VrfId mismatch", i)
						require.Equal(t, expected.Source.Vlan, dpuRule.Policy.Source.Vlan,
							"Rule %d: Source VLAN mismatch", i)

						// Verify destination
						require.Equal(t, expected.Destination.Cidr, dpuRule.Policy.Destination.Cidr,
							"Rule %d: Destination CIDR mismatch", i)
						require.Equal(t, expected.Destination.Vrf, dpuRule.Policy.Destination.Vrf,
							"Rule %d: Destination VRF mismatch", i)
						require.Equal(t, expected.Destination.VrfId, dpuRule.Policy.Destination.VrfId,
							"Rule %d: Destination VrfId mismatch", i)
						require.Equal(t, expected.Destination.Vlan, dpuRule.Policy.Destination.Vlan,
							"Rule %d: Destination VLAN mismatch", i)

						// Verify ports
						if expected.Destination.Ports != nil {
							require.NotNil(t, dpuRule.Policy.Destination.Ports,
								"Rule %d: Expected destination ports but got nil", i)
							require.Equal(t, len(*expected.Destination.Ports), len(*dpuRule.Policy.Destination.Ports),
								"Rule %d: Destination ports count mismatch", i)

							for j, expectedPort := range *expected.Destination.Ports {
								actualPort := (*dpuRule.Policy.Destination.Ports)[j]
								require.Equal(t, expectedPort.Port, actualPort.Port,
									"Rule %d, Port %d: Port mismatch", i, j)
								require.Equal(t, expectedPort.EndPort, actualPort.EndPort,
									"Rule %d, Port %d: EndPort mismatch", i, j)
								require.Equal(t, expectedPort.Protocol, actualPort.Protocol,
									"Rule %d, Port %d: Protocol mismatch", i, j)
							}
						}
						break
					}
				}
				require.True(t, found, "Rule %d: No matching expected rule found for source=%s, dest=%s",
					i, dpuRule.Policy.Source.Cidr, dpuRule.Policy.Destination.Cidr)
			}
		})
	}
}
