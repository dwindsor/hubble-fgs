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
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	isovalentv1 "github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

type FakeDPUProgrammer struct {
	rules []*DPUPolicyRule
}

func NewFakeDPUProgrammer() *FakeDPUProgrammer {
	return &FakeDPUProgrammer{
		rules: make([]*DPUPolicyRule, 0),
	}
}

func (f *FakeDPUProgrammer) SubmitDPURuleToDPU(rule *DPUPolicyRule) error {
	f.rules = append(f.rules, rule)
	return nil
}

func (f *FakeDPUProgrammer) Clear() {
	f.rules = make([]*DPUPolicyRule, 0)
}

// Helper function to create a minimal k8s policy object for testing
func makeTestK8sPolicy(name, namespace string) *isovalentv1.SmartSwitchNetworkPolicy {
	return &isovalentv1.SmartSwitchNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       isovalentv1.SNPKindDefinition,
			APIVersion: isovalentv1.SNPName,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: isovalentv1.SmartSwitchNetworkPolicySpec{
			Rules: []isovalentv1.SmartSwitchNetworkPolicyRule{
				{
					Description: "Test rule",
					Action:      "allow",
					Source: isovalentv1.SmartSwitchNetworkSource{
						IPBlock: []isovalentv1.NetworkObjectGroupSpec{
							{
								CIDR: "10.0.0.0/8",
							},
						},
					},
					Destination: isovalentv1.SmartSwitchNetworkDestination{
						IPBlock: []isovalentv1.NetworkObjectGroupSpec{
							{
								CIDR: "192.168.0.0/16",
							},
						},
						ProtoPorts: []isovalentv1.SmartSwitchProtocolPort{
							{
								Protocol: "TCP",
								Port:     80,
							},
						},
					},
				},
			},
		},
	}
}

func TestPolicyHandlerAddRemovePolicy(t *testing.T) {
	fakeDPU := NewFakeDPUProgrammer()
	newPolicyHandler := NewPolicyHandler(context.Background(), fakeDPU)

	l3Network := NewL3Networks()
	l3Network.Add("red", 1)
	l3Network.Add("blue", 2)

	err := newPolicyHandler.SetL3Networks(l3Network)
	require.NoError(t, err)

	resourceID := NewResourceID("SmartSwitchNetworkPolicy", "default", "test-policy")
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
		}, "",
	)
	require.NoError(t, err)
	require.Len(t, fakeDPU.rules, 1)
	require.Equal(t, fakeDPU.rules[0].Oper, v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT)

	err = newPolicyHandler.DeletePolicy(resourceID, "")
	require.NoError(t, err)
	require.Len(t, fakeDPU.rules, 2)
	require.Equal(t, fakeDPU.rules[1].Oper, v1alpha.PolicyOperation_POLICY_OPERATION_DELETE)
}

func TestPolicyHandlerRemoveL3Network(t *testing.T) {
	fakeDPU := NewFakeDPUProgrammer()
	newPolicyHandler := NewPolicyHandler(context.Background(), fakeDPU)

	l3Network := NewL3Networks()
	l3Network.Add("red", 1)
	l3Network.Add("blue", 2)

	err := newPolicyHandler.SetL3Networks(l3Network)
	require.NoError(t, err)

	resourceID := NewResourceID("SmartSwitchNetworkPolicy", "default", "test-policy")
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
		}, "",
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
	require.Equal(t, fakeDPU.rules[1].Policy.PolicyName, "SmartSwitchNetworkPolicy/default/test-policy")

}

func TestPolicyUpdatePolicy(t *testing.T) {
	fakeDPU := NewFakeDPUProgrammer()
	newPolicyHandler := NewPolicyHandler(context.Background(), fakeDPU)

	l3Network := NewL3Networks()
	l3Network.Add("red", 1)
	newPolicyHandler.SetL3Networks(l3Network)
	resourceID := NewResourceID("SmartSwitchNetworkPolicy", "default", "test-policy")
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
		}, "",
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
		}, "",
	)
	require.NoError(t, err)
	// We want to receive two updates in this order:
	// - one to add the new rule
	// - one to delete the previous rule
	require.Len(t, fakeDPU.rules, 3)
	require.Equal(t, fakeDPU.rules[1].Oper, v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT)
	require.Equal(t, fakeDPU.rules[1].Policy.RuleName, "allow-red-to-red/2")
	require.Equal(t, fakeDPU.rules[1].Policy.PolicyName, "SmartSwitchNetworkPolicy/default/test-policy")
	require.Equal(t, fakeDPU.rules[2].Oper, v1alpha.PolicyOperation_POLICY_OPERATION_DELETE)
	require.Equal(t, fakeDPU.rules[2].Policy.RuleName, "allow-red-to-red/1")
	require.Equal(t, fakeDPU.rules[2].Policy.PolicyName, "SmartSwitchNetworkPolicy/default/test-policy")

}

func createPolicyRule(ruleName, srcCIDR, dstCIDR, vrf string, port uint32) *PolicyRule {
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
				ProtoPorts: &[]SmartSwitchNetworkProtocolPorts{
					{Port: port, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP},
				},
			},
		},
	)
}

func checkRule(t *testing.T, rule *DPUPolicyRule, expectedRuleName, expectedPolicyName, srcCIDR, dstCIDR, vrf string, vrfId, port uint32) {
	require.Equal(t, v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT, rule.Oper)
	require.Equal(t, expectedRuleName, rule.Policy.RuleName)
	require.Equal(t, expectedPolicyName, rule.Policy.PolicyName)

	// Check source properties
	require.Equal(t, srcCIDR, rule.Policy.Source.Cidr)
	require.Equal(t, vrf, rule.Policy.Source.Vrf)
	require.Equal(t, vrfId, rule.Policy.Source.VrfId)
	require.Equal(t, uint32(0), rule.Policy.Source.Vlan)
	sports := rule.Policy.Source.Ports
	require.Nil(t, sports)

	// Check destination properties
	require.Equal(t, dstCIDR, rule.Policy.Destination.Cidr)
	require.Equal(t, vrf, rule.Policy.Destination.Vrf)
	require.Equal(t, vrfId, rule.Policy.Destination.VrfId)
	require.Equal(t, uint32(0), rule.Policy.Destination.Vlan)
	dports := *rule.Policy.Destination.Ports
	require.Len(t, dports, 1)
	require.Equal(t, port, dports[0].Port)
	require.Equal(t, uint32(0), dports[0].EndPort)
	require.Equal(t, v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP, dports[0].Protocol)
}

func findRuleByName(t *testing.T, fakeDPU *FakeDPUProgrammer, ruleName string) *DPUPolicyRule {
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
	newPolicyHandler := NewPolicyHandler(context.Background(), fakeDPU)
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
			}, "",
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

		err := newPolicyHandler.DeletePolicy(resourceID, "")
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
	newPolicyHandler := NewPolicyHandler(context.Background(), fakeDPU)
	l3Network := NewL3Networks()
	newPolicyHandler.SetL3Networks(l3Network)

	resourceID := NewResourceID("ns", "default", "redPolicy")

	err := newPolicyHandler.UpsertPolicy(
		resourceID,
		K8sRulesList{
			createPolicyRule("allow-red-to-red-80", "10.1.0.0/16", "10.2.0.0/16", "red", 80),
		}, "",
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

func TestPolicyHandlerResourceVersion(t *testing.T) {
	fakeDPU := NewFakeDPUProgrammer()
	handler := NewPolicyHandler(context.Background(), fakeDPU)

	l3Network := NewL3Networks()
	l3Network.Add("red", 1)
	err := handler.SetL3Networks(l3Network)
	require.NoError(t, err)

	// Initially, ResourceVersion should return error
	_, err = handler.ResourceVersion()
	require.Error(t, err, "Should error when no policy has been added")

	// Add policy with ResourceVersion
	resourceID := NewResourceID("SmartSwitchNetworkPolicy", "default", "test-policy")
	k8sPolicy := makeTestK8sPolicy("test-policy", "default")
	k8sPolicy.ResourceVersion = "12345"

	err = handler.UpsertPolicy(
		resourceID,
		K8sRulesList{
			NewPolicyRule(
				"allow-red",
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
		}, k8sPolicy.ResourceVersion,
	)
	require.NoError(t, err)

	// Now ResourceVersion should return the version
	version, err := handler.ResourceVersion()
	require.NoError(t, err)
	require.Equal(t, "12345", version)

	// Update with newer ResourceVersion
	k8sPolicy.ResourceVersion = "67890"
	err = handler.UpsertPolicy(resourceID, K8sRulesList{}, k8sPolicy.ResourceVersion)
	require.NoError(t, err)

	version, err = handler.ResourceVersion()
	require.NoError(t, err)
	require.Equal(t, "67890", version)
}

func TestPolicyHandlerVRFIDChange(t *testing.T) {
	fakeDPU := NewFakeDPUProgrammer()
	handler := NewPolicyHandler(context.Background(), fakeDPU)

	l3Network := NewL3Networks()
	l3Network.Add("red", 1)
	err := handler.SetL3Networks(l3Network)
	require.NoError(t, err)

	resourceID := NewResourceID("ns", "default", "test-policy")
	err = handler.UpsertPolicy(
		resourceID,
		K8sRulesList{
			createPolicyRule("allow-red-80", "10.1.0.0/16", "10.2.0.0/16", "red", 80),
		}, "",
	)
	require.NoError(t, err)
	require.Len(t, fakeDPU.rules, 1)
	require.Equal(t, uint32(1), fakeDPU.rules[0].Policy.Source.VrfId)
	require.Equal(t, uint32(1), fakeDPU.rules[0].Policy.Destination.VrfId)

	// Change VRF "red" GID from 1 to 5
	fakeDPU.Clear()
	l3Network = NewL3Networks()
	l3Network.Add("red", 5)
	err = handler.SetL3Networks(l3Network)
	require.NoError(t, err)

	// Should get 2 operations: UPSERT (new VRF ID) before DELETE (old VRF ID)
	require.Len(t, fakeDPU.rules, 2)
	require.Equal(t, v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT, fakeDPU.rules[0].Oper)
	require.Equal(t, uint32(5), fakeDPU.rules[0].Policy.Source.VrfId)
	require.Equal(t, uint32(5), fakeDPU.rules[0].Policy.Destination.VrfId)
	require.Equal(t, v1alpha.PolicyOperation_POLICY_OPERATION_DELETE, fakeDPU.rules[1].Oper)
	require.Equal(t, uint32(1), fakeDPU.rules[1].Policy.Source.VrfId)
	require.Equal(t, uint32(1), fakeDPU.rules[1].Policy.Destination.VrfId)

	// New rule should have different RuleName suffix than old
	require.NotEqual(t, fakeDPU.rules[0].Policy.RuleName, fakeDPU.rules[1].Policy.RuleName)
}

func TestPolicyHandlerVRFIDSwap(t *testing.T) {
	fakeDPU := NewFakeDPUProgrammer()
	handler := NewPolicyHandler(context.Background(), fakeDPU)

	l3Network := NewL3Networks()
	l3Network.Add("red", 1)
	l3Network.Add("blue", 2)
	err := handler.SetL3Networks(l3Network)
	require.NoError(t, err)

	// Add a policy in "red" VRF and one in "blue" VRF
	resourceID1 := NewResourceID("ns", "default", "red-policy")
	err = handler.UpsertPolicy(
		resourceID1,
		K8sRulesList{
			createPolicyRule("allow-red-80", "10.1.0.0/16", "10.2.0.0/16", "red", 80),
		}, "",
	)
	require.NoError(t, err)

	resourceID2 := NewResourceID("ns", "default", "blue-policy")
	err = handler.UpsertPolicy(
		resourceID2,
		K8sRulesList{
			createPolicyRule("allow-blue-80", "10.3.0.0/16", "10.4.0.0/16", "blue", 80),
		}, "",
	)
	require.NoError(t, err)

	// Swap GIDs: red:1→2, blue:2→1
	fakeDPU.Clear()
	l3Network = NewL3Networks()
	l3Network.Add("red", 2)
	l3Network.Add("blue", 1)
	err = handler.SetL3Networks(l3Network)
	require.NoError(t, err)

	// Should get 4 operations: 2 UPSERTs then 2 DELETEs
	require.Len(t, fakeDPU.rules, 4)

	// Count operations
	upserts := 0
	deletes := 0
	for _, rule := range fakeDPU.rules {
		switch rule.Oper {
		case v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT:
			upserts++
		case v1alpha.PolicyOperation_POLICY_OPERATION_DELETE:
			deletes++
		}
	}
	require.Equal(t, 2, upserts)
	require.Equal(t, 2, deletes)

	// All UPSERTs should come before all DELETEs
	for i := 0; i < 2; i++ {
		require.Equal(t, v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT, fakeDPU.rules[i].Oper)
	}
	for i := 2; i < 4; i++ {
		require.Equal(t, v1alpha.PolicyOperation_POLICY_OPERATION_DELETE, fakeDPU.rules[i].Oper)
	}
}

func TestPolicyHandlerVRFIDChangeMultipleRules(t *testing.T) {
	fakeDPU := NewFakeDPUProgrammer()
	handler := NewPolicyHandler(context.Background(), fakeDPU)

	l3Network := NewL3Networks()
	l3Network.Add("red", 1)
	err := handler.SetL3Networks(l3Network)
	require.NoError(t, err)

	resourceID := NewResourceID("ns", "default", "multi-policy")
	err = handler.UpsertPolicy(
		resourceID,
		K8sRulesList{
			createPolicyRule("allow-red-80", "10.1.0.0/16", "10.2.0.0/16", "red", 80),
			createPolicyRule("allow-red-443", "10.1.0.0/16", "10.2.0.0/16", "red", 443),
		}, "",
	)
	require.NoError(t, err)
	require.Len(t, fakeDPU.rules, 2)

	// Change VRF "red" GID from 1 to 10
	fakeDPU.Clear()
	l3Network = NewL3Networks()
	l3Network.Add("red", 10)
	err = handler.SetL3Networks(l3Network)
	require.NoError(t, err)

	// Should get 4 operations: 2 UPSERTs (new GID=10) then 2 DELETEs (old GID=1)
	require.Len(t, fakeDPU.rules, 4)

	for i := 0; i < 2; i++ {
		require.Equal(t, v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT, fakeDPU.rules[i].Oper)
		require.Equal(t, uint32(10), fakeDPU.rules[i].Policy.Source.VrfId)
	}
	for i := 2; i < 4; i++ {
		require.Equal(t, v1alpha.PolicyOperation_POLICY_OPERATION_DELETE, fakeDPU.rules[i].Oper)
		require.Equal(t, uint32(1), fakeDPU.rules[i].Policy.Source.VrfId)
	}
}

func TestPolicyHandlerVRFIDChangeUnaffected(t *testing.T) {
	fakeDPU := NewFakeDPUProgrammer()
	handler := NewPolicyHandler(context.Background(), fakeDPU)

	l3Network := NewL3Networks()
	l3Network.Add("red", 1)
	l3Network.Add("blue", 2)
	err := handler.SetL3Networks(l3Network)
	require.NoError(t, err)

	// Add policy in "blue" VRF (not affected by "red" change)
	resourceID := NewResourceID("ns", "default", "blue-policy")
	err = handler.UpsertPolicy(
		resourceID,
		K8sRulesList{
			createPolicyRule("allow-blue-80", "10.1.0.0/16", "10.2.0.0/16", "blue", 80),
		}, "",
	)
	require.NoError(t, err)

	// Change only "red" GID
	fakeDPU.Clear()
	l3Network = NewL3Networks()
	l3Network.Add("red", 5)
	l3Network.Add("blue", 2)
	err = handler.SetL3Networks(l3Network)
	require.NoError(t, err)

	// No operations should be emitted for "blue" policy
	require.Len(t, fakeDPU.rules, 0)
}

func TestPolicyHandlerVRFIDChangeThenUpsert(t *testing.T) {
	fakeDPU := NewFakeDPUProgrammer()
	handler := NewPolicyHandler(context.Background(), fakeDPU)

	l3Network := NewL3Networks()
	l3Network.Add("red", 1)
	err := handler.SetL3Networks(l3Network)
	require.NoError(t, err)

	resourceID := NewResourceID("ns", "default", "test-policy")
	err = handler.UpsertPolicy(
		resourceID,
		K8sRulesList{
			createPolicyRule("allow-red-80", "10.1.0.0/16", "10.2.0.0/16", "red", 80),
		}, "",
	)
	require.NoError(t, err)

	// Change VRF "red" GID from 1 to 5
	l3Network = NewL3Networks()
	l3Network.Add("red", 5)
	err = handler.SetL3Networks(l3Network)
	require.NoError(t, err)

	// Now do a normal UpsertPolicy on the same resource (verifies Repository sync)
	fakeDPU.Clear()
	err = handler.UpsertPolicy(
		resourceID,
		K8sRulesList{
			createPolicyRule("allow-red-443", "10.1.0.0/16", "10.2.0.0/16", "red", 443),
		}, "",
	)
	require.NoError(t, err)

	// Should get normal upsert+delete cycle (new rule added, old deleted)
	require.Len(t, fakeDPU.rules, 2)
	require.Equal(t, v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT, fakeDPU.rules[0].Oper)
	require.Equal(t, uint32(5), fakeDPU.rules[0].Policy.Source.VrfId)
	require.Equal(t, v1alpha.PolicyOperation_POLICY_OPERATION_DELETE, fakeDPU.rules[1].Oper)
	require.Equal(t, uint32(5), fakeDPU.rules[1].Policy.Source.VrfId)
}
