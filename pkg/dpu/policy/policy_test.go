package policy

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"
)

// expectedPolicy defines the expected output for a single FwPolicyV2
type expectedPolicy struct {
	Name       string
	Effect     string
	Operation  uint16
	SourceIp   string
	SourceVlan int
	SourceVrf  int
	DestIp     string
	DestVlan   int
	PortLow    uint16
	PortHigh   uint16
	Protocols  []string // expected protocols for this port range
}

func TestRuleToJSON(t *testing.T) {
	tests := []struct {
		name     string
		op       v1alpha.PolicyOperation
		rule     *switchpolicy.DPURule
		expected []expectedPolicy
	}{
		{
			name: "Single TCP port",
			op:   v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
			rule: &switchpolicy.DPURule{
				K8SResourceVersion: "v1",
				K8SUid:             "uid-123",
				PolicyName:         "test-policy",
				RuleName:           "rule-1",
				Action:             v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
				Source: switchpolicy.DPUSubject{
					Cidr:  "10.0.0.0/8",
					Vlan:  100,
					VrfId: 1,
				},
				Destination: switchpolicy.DPUSubject{
					Cidr: "192.168.1.0/24",
					Vlan: 200,
					Ports: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
						{Port: 80, EndPort: 80, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP},
					},
				},
			},
			expected: []expectedPolicy{
				{
					Name:       "test-policy/rule-1",
					Effect:     ALLOW,
					Operation:  0,
					SourceIp:   "10.0.0.0/8",
					SourceVlan: 100,
					SourceVrf:  1,
					DestIp:     "192.168.1.0/24",
					DestVlan:   200,
					PortLow:    80,
					PortHigh:   80,
					Protocols:  []string{"tcp"},
				},
			},
		},
		{
			name: "Multiple protocols same port range creates single policy",
			op:   v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
			rule: &switchpolicy.DPURule{
				K8SResourceVersion: "v1",
				K8SUid:             "uid-456",
				PolicyName:         "multi-proto-policy",
				RuleName:           "rule-1",
				Action:             v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
				Source: switchpolicy.DPUSubject{
					Cidr: "10.0.0.0/8",
				},
				Destination: switchpolicy.DPUSubject{
					Cidr: "192.168.1.0/24",
					Ports: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
						{Port: 80, EndPort: 80, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP},
						{Port: 80, EndPort: 80, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP},
					},
				},
			},
			expected: []expectedPolicy{
				{
					Name:      "multi-proto-policy/rule-1",
					Effect:    ALLOW,
					Operation: 0,
					SourceIp:  "10.0.0.0/8",
					DestIp:    "192.168.1.0/24",
					PortLow:   80,
					PortHigh:  80,
					Protocols: []string{"tcp", "udp"},
				},
			},
		},
		{
			name: "Different port ranges create separate policies",
			op:   v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
			rule: &switchpolicy.DPURule{
				K8SResourceVersion: "v1",
				K8SUid:             "uid-789",
				PolicyName:         "multi-port-policy",
				RuleName:           "rule-1",
				Action:             v1alpha.PolicyAction_POLICY_ACTION_DENY,
				Source: switchpolicy.DPUSubject{
					Cidr: "10.0.0.0/8",
				},
				Destination: switchpolicy.DPUSubject{
					Cidr: "192.168.1.0/24",
					Ports: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
						{Port: 80, EndPort: 80, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP},
						{Port: 443, EndPort: 443, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP},
					},
				},
			},
			expected: []expectedPolicy{
				{
					Name:      "multi-port-policy/rule-1",
					Effect:    DENY,
					Operation: 0,
					SourceIp:  "10.0.0.0/8",
					DestIp:    "192.168.1.0/24",
					PortLow:   80,
					PortHigh:  80,
					Protocols: []string{"tcp"},
				},
				{
					Name:      "multi-port-policy/rule-1",
					Effect:    DENY,
					Operation: 0,
					SourceIp:  "10.0.0.0/8",
					DestIp:    "192.168.1.0/24",
					PortLow:   443,
					PortHigh:  443,
					Protocols: []string{"tcp"},
				},
			},
		},
		{
			name: "Port range with multiple protocols",
			op:   v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
			rule: &switchpolicy.DPURule{
				K8SResourceVersion: "v1",
				K8SUid:             "uid-range",
				PolicyName:         "port-range-policy",
				RuleName:           "rule-1",
				Action:             v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
				Source: switchpolicy.DPUSubject{
					Cidr: "10.0.0.0/8",
				},
				Destination: switchpolicy.DPUSubject{
					Cidr: "192.168.1.0/24",
					Ports: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
						{Port: 8000, EndPort: 8080, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP},
						{Port: 8000, EndPort: 8080, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP},
					},
				},
			},
			expected: []expectedPolicy{
				{
					Name:      "port-range-policy/rule-1",
					Effect:    ALLOW,
					Operation: 0,
					SourceIp:  "10.0.0.0/8",
					DestIp:    "192.168.1.0/24",
					PortLow:   8000,
					PortHigh:  8080,
					Protocols: []string{"tcp", "udp"},
				},
			},
		},
		{
			name: "Delete operation",
			op:   v1alpha.PolicyOperation_POLICY_OPERATION_DELETE,
			rule: &switchpolicy.DPURule{
				K8SResourceVersion: "v1",
				K8SUid:             "uid-del",
				PolicyName:         "delete-policy",
				RuleName:           "rule-1",
				Action:             v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
				Source: switchpolicy.DPUSubject{
					Cidr: "10.0.0.0/8",
				},
				Destination: switchpolicy.DPUSubject{
					Cidr: "192.168.1.0/24",
					Ports: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
						{Port: 80, EndPort: 80, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP},
					},
				},
			},
			expected: []expectedPolicy{
				{
					Name:      "delete-policy/rule-1",
					Effect:    ALLOW,
					Operation: 1, // DELETE
					SourceIp:  "10.0.0.0/8",
					DestIp:    "192.168.1.0/24",
					PortLow:   80,
					PortHigh:  80,
					Protocols: []string{"tcp"},
				},
			},
		},
		{
			name: "No ports creates single policy with empty ports",
			op:   v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
			rule: &switchpolicy.DPURule{
				K8SResourceVersion: "v1",
				K8SUid:             "uid-noports",
				PolicyName:         "no-ports-policy",
				RuleName:           "rule-1",
				Action:             v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
				Source: switchpolicy.DPUSubject{
					Cidr: "10.0.0.0/8",
				},
				Destination: switchpolicy.DPUSubject{
					Cidr:  "192.168.1.0/24",
					Ports: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{},
				},
			},
			expected: []expectedPolicy{
				{
					Name:      "no-ports-policy/rule-1",
					Effect:    ALLOW,
					Operation: 0,
					SourceIp:  "10.0.0.0/8",
					DestIp:    "192.168.1.0/24",
					Protocols: nil, // empty ports
				},
			},
		},
		{
			name: "ICMP protocol",
			op:   v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
			rule: &switchpolicy.DPURule{
				K8SResourceVersion: "v1",
				K8SUid:             "uid-icmp",
				PolicyName:         "icmp-policy",
				RuleName:           "rule-1",
				Action:             v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
				Source: switchpolicy.DPUSubject{
					Cidr: "10.0.0.0/8",
				},
				Destination: switchpolicy.DPUSubject{
					Cidr: "192.168.1.0/24",
					Ports: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
						{Port: 0, EndPort: 0, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_ICMP},
					},
				},
			},
			expected: []expectedPolicy{
				{
					Name:      "icmp-policy/rule-1",
					Effect:    ALLOW,
					Operation: 0,
					SourceIp:  "10.0.0.0/8",
					DestIp:    "192.168.1.0/24",
					PortLow:   0,
					PortHigh:  0,
					Protocols: []string{"icmp"},
				},
			},
		},
		{
			name: "Unspecified protocol defaults to any",
			op:   v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
			rule: &switchpolicy.DPURule{
				K8SResourceVersion: "v1",
				K8SUid:             "uid-any",
				PolicyName:         "any-proto-policy",
				RuleName:           "rule-1",
				Action:             v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
				Source: switchpolicy.DPUSubject{
					Cidr: "10.0.0.0/8",
				},
				Destination: switchpolicy.DPUSubject{
					Cidr: "192.168.1.0/24",
					Ports: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
						{Port: 80, EndPort: 80, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED},
					},
				},
			},
			expected: []expectedPolicy{
				{
					Name:      "any-proto-policy/rule-1",
					Effect:    ALLOW,
					Operation: 0,
					SourceIp:  "10.0.0.0/8",
					DestIp:    "192.168.1.0/24",
					PortLow:   80,
					PortHigh:  80,
					Protocols: []string{"any"},
				},
			},
		},
		{
			name: "Duplicate protocols are deduplicated",
			op:   v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
			rule: &switchpolicy.DPURule{
				K8SResourceVersion: "v1",
				K8SUid:             "uid-dup",
				PolicyName:         "dup-policy",
				RuleName:           "rule-1",
				Action:             v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
				Source: switchpolicy.DPUSubject{
					Cidr: "10.0.0.0/8",
				},
				Destination: switchpolicy.DPUSubject{
					Cidr: "192.168.1.0/24",
					Ports: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
						{Port: 80, EndPort: 80, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP},
						{Port: 80, EndPort: 80, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP}, // duplicate
						{Port: 80, EndPort: 80, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP},
					},
				},
			},
			expected: []expectedPolicy{
				{
					Name:      "dup-policy/rule-1",
					Effect:    ALLOW,
					Operation: 0,
					SourceIp:  "10.0.0.0/8",
					DestIp:    "192.168.1.0/24",
					PortLow:   80,
					PortHigh:  80,
					Protocols: []string{"tcp", "udp"}, // tcp only once
				},
			},
		},
		{
			name: "Complex rule with multiple port ranges and protocols",
			op:   v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
			rule: &switchpolicy.DPURule{
				K8SResourceVersion: "v1",
				K8SUid:             "uid-complex",
				PolicyName:         "complex-policy",
				RuleName:           "rule-1",
				Action:             v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
				Source: switchpolicy.DPUSubject{
					Cidr:  "10.0.0.0/8",
					Vlan:  100,
					VrfId: 1,
				},
				Destination: switchpolicy.DPUSubject{
					Cidr: "192.168.1.0/24",
					Vlan: 200,
					Ports: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
						{Port: 80, EndPort: 80, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP},
						{Port: 80, EndPort: 80, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP},
						{Port: 443, EndPort: 443, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP},
						{Port: 8000, EndPort: 9000, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP},
					},
				},
			},
			expected: []expectedPolicy{
				{
					Name:       "complex-policy/rule-1",
					Effect:     ALLOW,
					Operation:  0,
					SourceIp:   "10.0.0.0/8",
					SourceVlan: 100,
					SourceVrf:  1,
					DestIp:     "192.168.1.0/24",
					DestVlan:   200,
					PortLow:    80,
					PortHigh:   80,
					Protocols:  []string{"tcp", "udp"},
				},
				{
					Name:       "complex-policy/rule-1",
					Effect:     ALLOW,
					Operation:  0,
					SourceIp:   "10.0.0.0/8",
					SourceVlan: 100,
					SourceVrf:  1,
					DestIp:     "192.168.1.0/24",
					DestVlan:   200,
					PortLow:    443,
					PortHigh:   443,
					Protocols:  []string{"tcp"},
				},
				{
					Name:       "complex-policy/rule-1",
					Effect:     ALLOW,
					Operation:  0,
					SourceIp:   "10.0.0.0/8",
					SourceVlan: 100,
					SourceVrf:  1,
					DestIp:     "192.168.1.0/24",
					DestVlan:   200,
					PortLow:    8000,
					PortHigh:   9000,
					Protocols:  []string{"tcp"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policies := ruleToJSON(tt.op, tt.rule)

			require.Len(t, policies, len(tt.expected), "policy count mismatch")

			// Build a map of actual policies by port range for easier matching
			// Keying the port range as low port and high port bits concatenated together
			actualByPort := make(map[uint32]FwPolicyV2)
			for _, p := range policies {
				if len(p.Destination.Ports) > 0 {
					key := uint32(p.Destination.Ports[0].PortLow)<<16 | uint32(p.Destination.Ports[0].PortHigh)
					actualByPort[key] = p
				} else {
					actualByPort[0] = p // no ports case
				}
			}

			// Validate each expected policy
			for _, exp := range tt.expected {
				key := uint32(exp.PortLow)<<16 | uint32(exp.PortHigh)
				actual, found := actualByPort[key]
				require.True(t, found, "expected policy with port range %d-%d not found", exp.PortLow, exp.PortHigh)

				require.Equal(t, exp.Name, actual.Name, "Name mismatch")
				require.Equal(t, exp.Effect, actual.Effect, "Effect mismatch")
				require.Equal(t, exp.Operation, actual.Operation, "Operation mismatch")
				require.Equal(t, exp.SourceIp, actual.Source.Ip, "Source IP mismatch")
				require.Equal(t, exp.SourceVlan, actual.Source.Vlan, "Source VLAN mismatch")
				require.Equal(t, exp.SourceVrf, actual.Source.Vrf, "Source VRF mismatch")
				require.Equal(t, exp.DestIp, actual.Destination.Ip, "Destination IP mismatch")
				require.Equal(t, exp.DestVlan, actual.Destination.Vlan, "Destination VLAN mismatch")

				if exp.Protocols == nil {
					require.Empty(t, actual.Destination.Ports, "expected empty ports")
				} else {
					require.Len(t, actual.Destination.Ports, 1, "expected single port entry")
					require.Equal(t, exp.PortLow, actual.Destination.Ports[0].PortLow, "PortLow mismatch")
					require.Equal(t, exp.PortHigh, actual.Destination.Ports[0].PortHigh, "PortHigh mismatch")

					// Sort both protocol slices for comparison
					actualProtos := make([]string, len(actual.Destination.Ports[0].Protocol))
					copy(actualProtos, actual.Destination.Ports[0].Protocol)
					sort.Strings(actualProtos)
					expectedProtos := make([]string, len(exp.Protocols))
					copy(expectedProtos, exp.Protocols)
					sort.Strings(expectedProtos)
					require.Equal(t, expectedProtos, actualProtos, "Protocols mismatch")
				}

				// Verify ID is not empty and contains port range
				require.NotEmpty(t, actual.Id, "ID should not be empty")
			}

			// Verify all IDs are unique
			ids := make(map[string]bool)
			for _, p := range policies {
				require.False(t, ids[p.Id], "Duplicate ID found: %s", p.Id)
				ids[p.Id] = true
			}
		})
	}
}

func TestProtocolToString(t *testing.T) {
	tests := []struct {
		protocol v1alpha.PolicyProtocol
		expected string
	}{
		{v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP, "tcp"},
		{v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP, "udp"},
		{v1alpha.PolicyProtocol_POLICY_PROTOCOL_ICMP, "icmp"},
		{v1alpha.PolicyProtocol_POLICY_PROTOCOL_UNSPECIFIED, "any"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := protocolToString(tt.protocol)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestDPURuleToJSON(t *testing.T) {
	tests := []struct {
		name      string
		op        v1alpha.PolicyOperation
		policySet []*switchpolicy.DPUPolicyRule
		expected  []expectedPolicy
	}{
		{
			name: "Multiple DPU rules with different port ranges",
			op:   v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
			policySet: []*switchpolicy.DPUPolicyRule{
				{
					Oper: v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
					Policy: &switchpolicy.DPURule{
						K8SResourceVersion: "v1",
						K8SUid:             "uid-1",
						PolicyName:         "policy-1",
						RuleName:           "rule-1",
						Action:             v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
						Source: switchpolicy.DPUSubject{
							Cidr:  "10.0.0.0/8",
							Vlan:  100,
							VrfId: 1,
						},
						Destination: switchpolicy.DPUSubject{
							Cidr: "192.168.1.0/24",
							Vlan: 200,
							Ports: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
								{Port: 80, EndPort: 80, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP},
								{Port: 443, EndPort: 443, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP},
							},
						},
					},
				},
				{
					Oper: v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
					Policy: &switchpolicy.DPURule{
						K8SResourceVersion: "v2",
						K8SUid:             "uid-2",
						PolicyName:         "policy-2",
						RuleName:           "rule-1",
						Action:             v1alpha.PolicyAction_POLICY_ACTION_DENY,
						Source: switchpolicy.DPUSubject{
							Cidr:  "172.16.0.0/12",
							Vlan:  300,
							VrfId: 2,
						},
						Destination: switchpolicy.DPUSubject{
							Cidr: "192.168.2.0/24",
							Vlan: 400,
							Ports: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
								{Port: 22, EndPort: 22, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP},
							},
						},
					},
				},
			},
			expected: []expectedPolicy{
				{
					Name:       "policy-1/rule-1",
					Effect:     ALLOW,
					Operation:  0,
					SourceIp:   "10.0.0.0/8",
					SourceVlan: 100,
					SourceVrf:  1,
					DestIp:     "192.168.1.0/24",
					DestVlan:   200,
					PortLow:    80,
					PortHigh:   80,
					Protocols:  []string{"tcp"},
				},
				{
					Name:       "policy-1/rule-1",
					Effect:     ALLOW,
					Operation:  0,
					SourceIp:   "10.0.0.0/8",
					SourceVlan: 100,
					SourceVrf:  1,
					DestIp:     "192.168.1.0/24",
					DestVlan:   200,
					PortLow:    443,
					PortHigh:   443,
					Protocols:  []string{"tcp"},
				},
				{
					Name:       "policy-2/rule-1",
					Effect:     DENY,
					Operation:  0,
					SourceIp:   "172.16.0.0/12",
					SourceVlan: 300,
					SourceVrf:  2,
					DestIp:     "192.168.2.0/24",
					DestVlan:   400,
					PortLow:    22,
					PortHigh:   22,
					Protocols:  []string{"tcp"},
				},
			},
		},
		{
			name: "Mixed allow and deny policies",
			op:   v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
			policySet: []*switchpolicy.DPUPolicyRule{
				{
					Oper: v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
					Policy: &switchpolicy.DPURule{
						K8SResourceVersion: "v1",
						K8SUid:             "uid-allow",
						PolicyName:         "allow-policy",
						RuleName:           "rule-1",
						Action:             v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
						Source:             switchpolicy.DPUSubject{Cidr: "10.0.0.0/8"},
						Destination: switchpolicy.DPUSubject{
							Cidr: "192.168.1.0/24",
							Ports: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
								{Port: 80, EndPort: 80, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP},
							},
						},
					},
				},
				{
					Oper: v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
					Policy: &switchpolicy.DPURule{
						K8SResourceVersion: "v1",
						K8SUid:             "uid-deny",
						PolicyName:         "deny-policy",
						RuleName:           "rule-1",
						Action:             v1alpha.PolicyAction_POLICY_ACTION_DENY,
						Source:             switchpolicy.DPUSubject{Cidr: "172.16.0.0/12"},
						Destination: switchpolicy.DPUSubject{
							Cidr: "192.168.2.0/24",
							Ports: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
								{Port: 443, EndPort: 443, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP},
							},
						},
					},
				},
			},
			expected: []expectedPolicy{
				{
					Name:      "allow-policy/rule-1",
					Effect:    ALLOW,
					Operation: 0,
					SourceIp:  "10.0.0.0/8",
					DestIp:    "192.168.1.0/24",
					PortLow:   80,
					PortHigh:  80,
					Protocols: []string{"tcp"},
				},
				{
					Name:      "deny-policy/rule-1",
					Effect:    DENY,
					Operation: 0,
					SourceIp:  "172.16.0.0/12",
					DestIp:    "192.168.2.0/24",
					PortLow:   443,
					PortHigh:  443,
					Protocols: []string{"tcp"},
				},
			},
		},
		{
			name: "Policy with multiple protocols on same port",
			op:   v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
			policySet: []*switchpolicy.DPUPolicyRule{
				{
					Oper: v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
					Policy: &switchpolicy.DPURule{
						K8SResourceVersion: "v1",
						K8SUid:             "uid-multi",
						PolicyName:         "multi-proto",
						RuleName:           "rule-1",
						Action:             v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
						Source:             switchpolicy.DPUSubject{Cidr: "10.0.0.0/8"},
						Destination: switchpolicy.DPUSubject{
							Cidr: "192.168.1.0/24",
							Ports: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
								{Port: 53, EndPort: 53, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP},
								{Port: 53, EndPort: 53, Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP},
							},
						},
					},
				},
			},
			expected: []expectedPolicy{
				{
					Name:      "multi-proto/rule-1",
					Effect:    ALLOW,
					Operation: 0,
					SourceIp:  "10.0.0.0/8",
					DestIp:    "192.168.1.0/24",
					PortLow:   53,
					PortHigh:  53,
					Protocols: []string{"tcp", "udp"},
				},
			},
		},
		{
			name:      "Empty policy set",
			op:        v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
			policySet: []*switchpolicy.DPUPolicyRule{},
			expected:  []expectedPolicy{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DPURuleToJSON(tt.op, tt.policySet)

			require.Len(t, result, len(tt.expected), "policy count mismatch")

			// Build a map of actual policies by name+port for matching
			type policyKey struct {
				name     string
				portLow  uint16
				portHigh uint16
			}
			actualByKey := make(map[policyKey]FwPolicyV2)
			for _, p := range result {
				var key policyKey
				key.name = p.Name
				if len(p.Destination.Ports) > 0 {
					key.portLow = p.Destination.Ports[0].PortLow
					key.portHigh = p.Destination.Ports[0].PortHigh
				}
				actualByKey[key] = p
			}

			// Validate each expected policy
			for _, exp := range tt.expected {
				key := policyKey{name: exp.Name, portLow: exp.PortLow, portHigh: exp.PortHigh}
				actual, found := actualByKey[key]
				require.True(t, found, "expected policy %s with port range %d-%d not found", exp.Name, exp.PortLow, exp.PortHigh)

				require.Equal(t, exp.Name, actual.Name, "Name mismatch")
				require.Equal(t, exp.Effect, actual.Effect, "Effect mismatch")
				require.Equal(t, exp.Operation, actual.Operation, "Operation mismatch")
				require.Equal(t, exp.SourceIp, actual.Source.Ip, "Source IP mismatch")
				require.Equal(t, exp.SourceVlan, actual.Source.Vlan, "Source VLAN mismatch")
				require.Equal(t, exp.SourceVrf, actual.Source.Vrf, "Source VRF mismatch")
				require.Equal(t, exp.DestIp, actual.Destination.Ip, "Destination IP mismatch")
				require.Equal(t, exp.DestVlan, actual.Destination.Vlan, "Destination VLAN mismatch")

				if exp.Protocols != nil {
					require.Len(t, actual.Destination.Ports, 1, "expected single port entry")
					require.Equal(t, exp.PortLow, actual.Destination.Ports[0].PortLow, "PortLow mismatch")
					require.Equal(t, exp.PortHigh, actual.Destination.Ports[0].PortHigh, "PortHigh mismatch")

					// Sort both protocol slices for comparison
					actualProtos := make([]string, len(actual.Destination.Ports[0].Protocol))
					copy(actualProtos, actual.Destination.Ports[0].Protocol)
					sort.Strings(actualProtos)
					expectedProtos := make([]string, len(exp.Protocols))
					copy(expectedProtos, exp.Protocols)
					sort.Strings(expectedProtos)
					require.Equal(t, expectedProtos, actualProtos, "Protocols mismatch")
				}

				require.NotEmpty(t, actual.Id, "ID should not be empty")
			}

			// Verify all IDs are unique
			ids := make(map[string]bool)
			for _, p := range result {
				require.False(t, ids[p.Id], "Duplicate ID found: %s", p.Id)
				ids[p.Id] = true
			}
		})
	}
}
