package switchpolicy

import (
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

func (f *FakeDPUProgrammer) SubmitDPURuleToDPU(rule *dpu.DPUPolicyRule) {
	f.rules = append(f.rules, rule)
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
	newPolicyHandler.UpsertPolicy(
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
	newPolicyHandler.UpsertPolicy(
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
