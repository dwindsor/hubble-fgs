package switchpolicy

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
)

type FakeDPUProgrammer struct {
	rules []*dpu.DPUPolicyRule
}

func NewFakeDPUProgrammer() *FakeDPUProgrammer {
	return &FakeDPUProgrammer{
		rules: make([]*dpu.DPUPolicyRule, 0),
	}
}

func (f *FakeDPUProgrammer) SubmitDPURuleToDPU(rule *dpu.DPUPolicyRule) error {
	f.rules = append(f.rules, rule)
	return nil
}

func (f *FakeDPUProgrammer) Clear() {
	f.rules = make([]*dpu.DPUPolicyRule, 0)
}

func TestPolicyHandlerAddRemovePolicy(t *testing.T) {
	fakeDPU := NewFakeDPUProgrammer()
	newPolicyHandler := NewPolicyHandler(fakeDPU)

	l3Network := NewL3Networks()
	l3Network.Add("red", 1)
	l3Network.Add("blue", 2)

	err := newPolicyHandler.SetL3Networks(l3Network)
	require.NoError(t, err)

	resourceID := NewResourceID("ns", "default", "test-policy")
	err = newPolicyHandler.UpsertPolicy(
		resourceID,
		K8sRulesList{
			NewPolicyRule(
				"allow-red-to-blue",
				&SmartSwitchNetworkPolicy{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "172.1.0.0/24",
							VRF:  "red",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "172.2.0.0/24",
							VRF:  "blue",
						},
					},
				},
			),
		},
	)
	require.NoError(t, err)
	require.Len(t, fakeDPU.rules, 1)
	require.Equal(t, fakeDPU.rules[0].Oper, v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT)

	err = newPolicyHandler.DeletePolicy(resourceID)
	require.NoError(t, err)
	require.Len(t, fakeDPU.rules, 2)
	require.Equal(t, fakeDPU.rules[1].Oper, v1alpha.PolicyOperation_POLICY_OPERATION_DELETE)
}

func TestPolicyHandlerRemoveL3Network(t *testing.T) {
	fakeDPU := NewFakeDPUProgrammer()
	newPolicyHandler := NewPolicyHandler(fakeDPU)

	l3Network := NewL3Networks()
	l3Network.Add("red", 1)
	l3Network.Add("blue", 2)

	err := newPolicyHandler.SetL3Networks(l3Network)
	require.NoError(t, err)

	resourceID := NewResourceID("ns", "default", "test-policy")
	err = newPolicyHandler.UpsertPolicy(
		resourceID,
		K8sRulesList{
			NewPolicyRule(
				"allow-red-to-blue",
				&SmartSwitchNetworkPolicy{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "172.1.0.0/24",
							VRF:  "red",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "172.2.0.0/24",
							VRF:  "blue",
						},
					},
				},
			),
		},
	)
	require.NoError(t, err)
	require.Len(t, fakeDPU.rules, 1)
	require.Equal(t, fakeDPU.rules[0].Oper, v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT)

	// Let's update the L3 networks to remove "red"
	l3Network = NewL3Networks()
	l3Network.Add("blue", 2)
	err = newPolicyHandler.SetL3Networks(l3Network)
	require.NoError(t, err)

	// We should receive delete for the rule as "red" VRF was removed
	require.Len(t, fakeDPU.rules, 2)
	require.Equal(t, fakeDPU.rules[1].Oper, v1alpha.PolicyOperation_POLICY_OPERATION_DELETE)
	require.Equal(t, fakeDPU.rules[1].Policy.RuleName, "allow-red-to-blue/1")
	require.Equal(t, fakeDPU.rules[1].Policy.PolicyName, "ns/default/test-policy")

}

func TestPolicyUpdatePolicy(t *testing.T) {
	fakeDPU := NewFakeDPUProgrammer()
	newPolicyHandler := NewPolicyHandler(fakeDPU)

	l3Network := NewL3Networks()
	l3Network.Add("red", 1)
	newPolicyHandler.SetL3Networks(l3Network)
	resourceID := NewResourceID("ns", "default", "test-policy")
	err := newPolicyHandler.UpsertPolicy(
		resourceID,
		K8sRulesList{
			NewPolicyRule(
				"allow-red-to-red",
				&SmartSwitchNetworkPolicy{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "172.1.0.0/24",
							VRF:  "red",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "172.2.0.0/24",
							VRF:  "red",
						},
					},
				},
			),
		},
	)
	require.NoError(t, err)
	require.Len(t, fakeDPU.rules, 1)
	err = newPolicyHandler.UpsertPolicy(
		resourceID,
		K8sRulesList{
			NewPolicyRule(
				"allow-red-to-red",
				&SmartSwitchNetworkPolicy{
					Source: SmartSwitchNetworkSource{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "172.1.0.0/24",
							VRF:  "red",
						},
					},
					Destination: SmartSwitchNetworkDestination{
						Endpoint: SmartSwitchNetworkEndpoint{
							CIDR: "172.2.0.0/23",
							VRF:  "red",
						},
					},
				},
			),
		},
	)
	require.NoError(t, err)
	// We want to receive two updates in this order:
	// - one to add the new rule
	// - one to delete the previous rule
	require.Len(t, fakeDPU.rules, 3)
	require.Equal(t, fakeDPU.rules[1].Oper, v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT)
	require.Equal(t, fakeDPU.rules[1].Policy.RuleName, "allow-red-to-red/2")
	require.Equal(t, fakeDPU.rules[1].Policy.PolicyName, "ns/default/test-policy")
	require.Equal(t, fakeDPU.rules[2].Oper, v1alpha.PolicyOperation_POLICY_OPERATION_DELETE)
	require.Equal(t, fakeDPU.rules[2].Policy.RuleName, "allow-red-to-red/1")
	require.Equal(t, fakeDPU.rules[2].Policy.PolicyName, "ns/default/test-policy")

}

func createPolicyRule(ruleName, srcCIDR, dstCIDR, vrf string, port int32) *PolicyRule {
	return NewPolicyRule(
		ruleName,
		&SmartSwitchNetworkPolicy{
			Default: SmartSwitchNetworkAction{
				EnforceAction: SmartSwitchEnforceAction{Deny: true},
			},
			Action: SmartSwitchNetworkAction{
				EnforceAction: SmartSwitchEnforceAction{Allow: true},
			},
			Source: SmartSwitchNetworkSource{
				Endpoint: SmartSwitchNetworkEndpoint{CIDR: srcCIDR, VRF: vrf},
			},
			Destination: SmartSwitchNetworkDestination{
				Endpoint: SmartSwitchNetworkEndpoint{CIDR: dstCIDR, VRF: vrf},
				ProtoPorts: []SmartSwitchNetworkProtocolPorts{
					{Port: port, Protocol: "TCP"},
				},
			},
		},
	)
}

func checkRule(t *testing.T, rule *dpu.DPUPolicyRule, expectedRuleName, expectedPolicyName, srcCIDR, dstCIDR, vrf string, vrfId, port uint32) {
	require.Equal(t, v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT, rule.Oper)
	require.Equal(t, expectedRuleName, rule.Policy.RuleName)
	require.Equal(t, expectedPolicyName, rule.Policy.PolicyName)

	// Check source properties
	require.Equal(t, srcCIDR, rule.Policy.Source.Cidr)
	require.Equal(t, vrf, rule.Policy.Source.Vrf)
	require.Equal(t, vrfId, rule.Policy.Source.VrfId)
	require.Equal(t, uint32(0), rule.Policy.Source.Vlan)
	require.Len(t, rule.Policy.Source.Ports, 0)

	// Check destination properties
	require.Equal(t, dstCIDR, rule.Policy.Destination.Cidr)
	require.Equal(t, vrf, rule.Policy.Destination.Vrf)
	require.Equal(t, vrfId, rule.Policy.Destination.VrfId)
	require.Equal(t, uint32(0), rule.Policy.Destination.Vlan)
	require.Len(t, rule.Policy.Destination.Ports, 1)
	require.Equal(t, port, rule.Policy.Destination.Ports[0].MinPort)
	require.Equal(t, uint32(0), rule.Policy.Destination.Ports[0].MaxPort)
	require.Equal(t, v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP, rule.Policy.Destination.Ports[0].Protocol)
}

func findRuleByName(t *testing.T, fakeDPU *FakeDPUProgrammer, ruleName string) *dpu.DPUPolicyRule {
	for _, rule := range fakeDPU.rules {
		if rule.Policy.RuleName == ruleName {
			return rule
		}
	}
	require.Fail(t, "Rule not found", "Expected rule %s not found in fakeDPU.rules", ruleName)
	return nil
}

func TestBasicIntraVRFPolicy(t *testing.T) {
	fakeDPU := NewFakeDPUProgrammer()
	newPolicyHandler := NewPolicyHandler(fakeDPU)
	l3Network := NewL3Networks()
	l3Network.Add("red", 1)
	l3Network.Add("blue", 2)
	l3Network.Add("green", 3)
	newPolicyHandler.SetL3Networks(l3Network)

	// Helper function to test a policy with two rules
	testPolicy := func(policyName, srcCIDR, dstCIDR, vrf string, vrfId uint32, ruleIdOffset int) ResourceID {
		fakeDPU.Clear()
		resourceID := NewResourceID("ns", "default", policyName)

		err := newPolicyHandler.UpsertPolicy(
			resourceID,
			K8sRulesList{
				createPolicyRule(fmt.Sprintf("allow-%s-to-%s-80", vrf, vrf), srcCIDR, dstCIDR, vrf, 80),
				createPolicyRule(fmt.Sprintf("allow-%s-to-%s-443", vrf, vrf), srcCIDR, dstCIDR, vrf, 443),
			},
		)
		require.NoError(t, err)
		require.Len(t, fakeDPU.rules, 2)

		// Check both rules
		rule80 := findRuleByName(t, fakeDPU, fmt.Sprintf("allow-%s-to-%s-80/%d", vrf, vrf, ruleIdOffset+1))
		checkRule(t, rule80, fmt.Sprintf("allow-%s-to-%s-80/%d", vrf, vrf, ruleIdOffset+1),
			fmt.Sprintf("ns/default/%s", policyName), srcCIDR, dstCIDR, vrf, vrfId, 80)

		rule443 := findRuleByName(t, fakeDPU, fmt.Sprintf("allow-%s-to-%s-443/%d", vrf, vrf, ruleIdOffset+2))
		checkRule(t, rule443, fmt.Sprintf("allow-%s-to-%s-443/%d", vrf, vrf, ruleIdOffset+2),
			fmt.Sprintf("ns/default/%s", policyName), srcCIDR, dstCIDR, vrf, vrfId, 443)
		return resourceID
	}

	// Test red VRF policy
	resourceID1 := testPolicy("redPolicy", "10.1.0.0/16", "10.2.0.0/16", "red", 1, 0)

	// Test blue VRF policy with overlapping CIDRs
	resourceID2 := testPolicy("bluePolicy", "10.1.0.0/16", "10.2.0.0/16", "blue", 2, 2)

	// Test second red VRF policy with different source CIDR
	resourceID3 := testPolicy("redPolicy2", "10.3.0.0/16", "10.2.0.0/16", "red", 1, 4)

	// Helper function to test policy deletion
	testPolicyDeletion := func(resourceID ResourceID, policyName, vrf string, ruleIdOffset int) {
		fakeDPU.Clear()

		err := newPolicyHandler.DeletePolicy(resourceID)
		require.NoError(t, err)

		// Should have 2 additional delete operations
		require.Len(t, fakeDPU.rules, 2)

		// Check the delete operations for both rules (order-independent)
		deleteRule80 := findRuleByName(t, fakeDPU, fmt.Sprintf("allow-%s-to-%s-80/%d", vrf, vrf, ruleIdOffset+1))
		require.Equal(t, v1alpha.PolicyOperation_POLICY_OPERATION_DELETE, deleteRule80.Oper)
		require.Equal(t, fmt.Sprintf("allow-%s-to-%s-80/%d", vrf, vrf, ruleIdOffset+1), deleteRule80.Policy.RuleName)
		require.Equal(t, fmt.Sprintf("ns/default/%s", policyName), deleteRule80.Policy.PolicyName)

		deleteRule443 := findRuleByName(t, fakeDPU, fmt.Sprintf("allow-%s-to-%s-443/%d", vrf, vrf, ruleIdOffset+2))
		require.Equal(t, v1alpha.PolicyOperation_POLICY_OPERATION_DELETE, deleteRule443.Oper)
		require.Equal(t, fmt.Sprintf("allow-%s-to-%s-443/%d", vrf, vrf, ruleIdOffset+2), deleteRule443.Policy.RuleName)
		require.Equal(t, fmt.Sprintf("ns/default/%s", policyName), deleteRule443.Policy.PolicyName)
	}

	// Remove first redPolicy policy and check delete updates
	testPolicyDeletion(resourceID1, "redPolicy", "red", 0)

	// Remove bluePolicy and check delete updates
	testPolicyDeletion(resourceID2, "bluePolicy", "blue", 2)

	// Remove remaining redPolicy2 and check delete updates
	testPolicyDeletion(resourceID3, "redPolicy2", "red", 4)
}

func TestPolicyHandlerAddL3Network(t *testing.T) {
	fakeDPU := NewFakeDPUProgrammer()
	newPolicyHandler := NewPolicyHandler(fakeDPU)
	l3Network := NewL3Networks()
	newPolicyHandler.SetL3Networks(l3Network)

	resourceID := NewResourceID("ns", "default", "redPolicy")

	err := newPolicyHandler.UpsertPolicy(
		resourceID,
		K8sRulesList{
			createPolicyRule("allow-red-to-red-80", "10.1.0.0/16", "10.2.0.0/16", "red", 80),
		},
	)
	require.NoError(t, err)
	require.Len(t, fakeDPU.rules, 0)
	// Now add the "red" L3 network
	l3Network.Add("red", 7)
	err = newPolicyHandler.SetL3Networks(l3Network)
	require.NoError(t, err)
	require.Len(t, fakeDPU.rules, 1)
	rule80 := findRuleByName(t, fakeDPU, "allow-red-to-red-80/1")
	checkRule(t, rule80, "allow-red-to-red-80/1", "ns/default/redPolicy", "10.1.0.0/16", "10.2.0.0/16", "red", 7, 80)
}
