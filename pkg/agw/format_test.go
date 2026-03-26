// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package agw

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

// --- Tests for filterPolicyNames and matchPolicyPattern ---

func TestFilterPolicyNamesCases(t *testing.T) {
	cases := []struct {
		name     string
		names    []string
		filter   string
		expected []string
	}{
		{
			name:     "No filter returns all",
			names:    []string{"policy1", "policy2"},
			filter:   "",
			expected: []string{"policy1", "policy2"},
		},
		{
			name:     "Empty filter returns all",
			names:    []string{"policyA", "policyB"},
			filter:   "{}",
			expected: []string{"policyA", "policyB"},
		},
		{
			name:     "Exact match single",
			names:    []string{"policy1", "policy2"},
			filter:   "^policy1$",
			expected: []string{"policy1"},
		},
		{
			name:     "Exact match none",
			names:    []string{"policy1", "policy2"},
			filter:   "^policy3$",
			expected: []string{},
		},
		{
			name:     "Regex prefix",
			names:    []string{"foo-bar", "foo-baz", "bar-foo"},
			filter:   "^foo-.*$",
			expected: []string{"foo-bar", "foo-baz"},
		},
		{
			name:     "Regex suffix",
			names:    []string{"foo-bar", "baz-bar", "bar-foo"},
			filter:   ".*-bar$",
			expected: []string{"foo-bar", "baz-bar"},
		},
		{
			name:     "Regex middle",
			names:    []string{"foo-bar-baz", "foo-baz-bar", "bar-baz-foo"},
			filter:   "^foo.*-baz$",
			expected: []string{"foo-bar-baz"},
		},
		{
			name:     "Case insensitive match",
			names:    []string{"Policy1", "policy2"},
			filter:   "(?i)^policy1$",
			expected: []string{"Policy1"},
		},
		{
			name:     "Case sensitive match",
			names:    []string{"Policy1", "policy1"},
			filter:   "(?-i)^policy1$",
			expected: []string{"policy1"},
		},
		{
			name:     "Case sensitive flag not at prefix",
			names:    []string{"Policy1", "policy1"},
			filter:   "^(?-i)policy1$",
			expected: []string{"policy1"},
		},
		{
			name:     "Regex no match",
			names:    []string{"foo", "bar"},
			filter:   "^baz-.*$",
			expected: []string{},
		},
		{
			name:     "Regex contains",
			names:    []string{"foo-with-bar", "with-foo", "bar-with"},
			filter:   "with",
			expected: []string{"foo-with-bar", "with-foo", "bar-with"},
		},
		{
			name:     "Regex wildcard",
			names:    []string{"foo-with-bar", "with-foo", "bar-with"},
			filter:   "with*",
			expected: []string{"foo-with-bar", "with-foo", "bar-with"},
		},
		// --- regex test cases ---
		{
			name:     "Regex: two consecutive digits",
			names:    []string{"policy12", "policy1", "policy22", "policyA"},
			filter:   ".*[0-9]{2}.*",
			expected: []string{"policy12", "policy22"},
		},
		{
			name:     "Regex: starts with foo",
			names:    []string{"foo123", "barfoo", "foo-bar", "foobar"},
			filter:   "^foo.*",
			expected: []string{"foo123", "foo-bar", "foobar"},
		},
		{
			name:     "Regex: ends with bar",
			names:    []string{"foo-bar", "bar", "foobar", "barfoo"},
			filter:   ".*bar$",
			expected: []string{"foo-bar", "bar", "foobar"},
		},
		{
			name:     "Regex: contains dash",
			names:    []string{"foo-bar", "barfoo", "baz-qux", "qux"},
			filter:   ".*-.*",
			expected: []string{"foo-bar", "baz-qux"},
		},
		{
			name:     "Regex: only digits",
			names:    []string{"123", "abc", "456", "789a"},
			filter:   "^[0-9]+$",
			expected: []string{"123", "456"},
		},
		{
			name:     "Regex: policy followed by uppercase letter",
			names:    []string{"policyA", "policyb", "policyC", "policy1"},
			filter:   "policy[A-Z]",
			expected: []string{"policyA", "policyC"},
		},
		{
			name:     "Regex: match nothing",
			names:    []string{"foo", "bar"},
			filter:   "^baz$",
			expected: []string{},
		},
		{
			name:     "Regex: match all",
			names:    []string{"foo", "bar", "baz"},
			filter:   ".*",
			expected: []string{"foo", "bar", "baz"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := filterPolicyNames(tc.names, tc.filter)
			if len(got) != len(tc.expected) {
				require.Equal(t, tc.expected, got)
			}
			for i := range got {
				if got[i] != tc.expected[i] {
					require.Equal(t, tc.expected[i], got[i])
				}
			}
		})
	}
}

// --- Tests for formatNoPoliciesMessage and formatSummaryHeader ---

func TestFormatNoPoliciesMessage(t *testing.T) {
	cases := []struct {
		name     string
		filter   string
		expected string
	}{
		{
			name:     "No filter",
			filter:   "",
			expected: "No policies loaded\n",
		},
		{
			name:     "With filter",
			filter:   "foo",
			expected: "No policies found matching 'foo'",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := formatNoPoliciesMessage(tc.filter)
			if msg != tc.expected {
				require.Equal(t, tc.expected, msg)
			}
		})
	}
}

func TestFormatSummaryHeader(t *testing.T) {
	cases := []struct {
		name         string
		count        int
		filter       string
		expectFilter bool
	}{
		{
			name:         "No filter, count > 0",
			count:        3,
			filter:       "",
			expectFilter: false,
		},
		{
			name:         "With filter, count = 1",
			count:        1,
			filter:       "foo*",
			expectFilter: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := formatSummaryHeader(tc.count, tc.filter)
			if tc.expectFilter {
				if !contains(header, "Filter:") {
					t.Errorf("expected filter in header: %s", header)
				}
			} else {
				if len(header) == 0 || header[0] != '\n' {
					require.Fail(t, "unexpected header", header)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

// --- Tests for formatSwitchPolicy ---

func TestFormatSwitchPolicy(t *testing.T) {
	cases := []struct {
		name       string
		resourceID switchpolicy.ResourceID
		rulesList  switchpolicy.K8sRulesList
		expected   []string
	}{
		{
			name:       "Basic policy with one rule",
			resourceID: switchpolicy.NewResourceID("SmartSwitchNetworkPolicy", "default", "test-policy"),
			rulesList: switchpolicy.K8sRulesList{
				switchpolicy.NewPolicyRule("hash1", &switchpolicy.SmartSwitchNetworkPolicy{
					Action: switchpolicy.SmartSwitchNetworkAction{
						EnforceAction: switchpolicy.SmartSwitchEnforceAction{Allow: true},
					},
					Source: switchpolicy.SmartSwitchNetworkSource{
						Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{
							CIDR: "10.0.0.0/24",
							VRF:  "vrf1",
						},
					},
					Destination: switchpolicy.SmartSwitchNetworkDestination{
						Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{
							CIDR: "192.168.0.0/24",
						},
					},
				}),
			},
			expected: []string{
				"Policy: SmartSwitchNetworkPolicy/default/test-policy",
				"Total Rules:    1",
				"Rule 1",
				"Action:      Allow",
				"Source:",
				"CIDR: 10.0.0.0/24",
				"VRF: vrf1",
				"Destination:",
				"CIDR: 192.168.0.0/24",
			},
		},
		{
			name:       "Policy with multiple rules",
			resourceID: switchpolicy.NewResourceID("SmartSwitchNetworkPolicy", "default", "multi-rule-policy"),
			rulesList: switchpolicy.K8sRulesList{
				switchpolicy.NewPolicyRule("hash1", &switchpolicy.SmartSwitchNetworkPolicy{
					Action: switchpolicy.SmartSwitchNetworkAction{
						EnforceAction: switchpolicy.SmartSwitchEnforceAction{Allow: true},
					},
					Source: switchpolicy.SmartSwitchNetworkSource{
						Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{CIDR: "10.0.0.0/24"},
					},
					Destination: switchpolicy.SmartSwitchNetworkDestination{
						Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{CIDR: "192.168.0.0/24"},
					},
				}),
				switchpolicy.NewPolicyRule("hash2", &switchpolicy.SmartSwitchNetworkPolicy{
					Action: switchpolicy.SmartSwitchNetworkAction{
						EnforceAction: switchpolicy.SmartSwitchEnforceAction{Deny: true},
					},
					Source: switchpolicy.SmartSwitchNetworkSource{
						Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{CIDR: "172.16.0.0/16"},
					},
					Destination: switchpolicy.SmartSwitchNetworkDestination{
						Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{CIDR: "10.1.0.0/16"},
					},
				}),
			},
			expected: []string{
				"Policy: SmartSwitchNetworkPolicy/default/multi-rule-policy",
				"Total Rules:    2",
				"Rule 1",
				"Action:      Allow",
				"Rule 2",
				"Action:      Deny",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := formatSwitchPolicy(tc.resourceID, tc.rulesList)
			for _, substr := range tc.expected {
				if !contains(out, substr) {
					require.Contains(t, out, substr)
				}
			}
		})
	}
}

// --- Tests for formatSwitchPolicyRule ---

func TestFormatSwitchPolicyRule(t *testing.T) {
	cases := []struct {
		name      string
		idx       int
		rule      *switchpolicy.PolicyRule
		addSpacer bool
		expected  []string
	}{
		{
			name: "Basic rule with Allow action",
			idx:  1,
			rule: switchpolicy.NewPolicyRule("hash1", &switchpolicy.SmartSwitchNetworkPolicy{
				Action: switchpolicy.SmartSwitchNetworkAction{
					EnforceAction: switchpolicy.SmartSwitchEnforceAction{Allow: true},
				},
				Source: switchpolicy.SmartSwitchNetworkSource{
					Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{CIDR: "10.0.0.0/24"},
				},
				Destination: switchpolicy.SmartSwitchNetworkDestination{
					Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{CIDR: "192.168.0.0/24"},
				},
			}),
			addSpacer: false,
			expected: []string{
				"┌─ Rule 1 ─────────────────────────────────────────────────────",
				"│ Action:      Allow",
				"│ Source:",
				"│   • CIDR: 10.0.0.0/24",
				"│ Destination:",
				"│   • CIDR: 192.168.0.0/24",
				"└───────────────────────────────────────────────────────────────",
			},
		},
		{
			name: "Rule with Deny action and protocol/ports",
			idx:  2,
			rule: switchpolicy.NewPolicyRule("hash2", &switchpolicy.SmartSwitchNetworkPolicy{
				Action: switchpolicy.SmartSwitchNetworkAction{
					EnforceAction: switchpolicy.SmartSwitchEnforceAction{Deny: true},
				},
				Source: switchpolicy.SmartSwitchNetworkSource{
					Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{
						CIDR: "172.16.0.0/16",
						VRF:  "vrf1",
						VLAN: 100,
					},
				},
				Destination: switchpolicy.SmartSwitchNetworkDestination{
					Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{
						CIDR: "10.1.0.0/16",
					},
					ProtoPorts: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
						switchpolicy.SmartSwitchNetworkProtocolPorts{
							Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
							Port:     80,
							EndPort:  443,
						},
					},
				},
			}),
			addSpacer: true,
			expected: []string{
				"┌─ Rule 2 ─────────────────────────────────────────────────────",
				"│ Action:      Deny",
				"│ Source:",
				"│   • CIDR: 172.16.0.0/16",
				"│   • VRF: vrf1",
				"│   • VLAN: 100",
				"│ Destination:",
				"│   • CIDR: 10.1.0.0/16",
				"│   • Protocol: POLICY_PROTOCOL_TCP",
				"│   • Ports: 80-443",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := formatSwitchPolicyRule(tc.idx, tc.rule, tc.addSpacer)
			for _, substr := range tc.expected {
				if !contains(out, substr) {
					require.Contains(t, out, substr)
				}
			}
		})
	}
}

// --- Tests for formatAction ---

func TestFormatAction(t *testing.T) {
	cases := []struct {
		name     string
		policy   *switchpolicy.SmartSwitchNetworkPolicy
		expected string
	}{
		{
			name: "Allow action",
			policy: &switchpolicy.SmartSwitchNetworkPolicy{
				Action: switchpolicy.SmartSwitchNetworkAction{
					EnforceAction: switchpolicy.SmartSwitchEnforceAction{Allow: true},
				},
			},
			expected: "Allow",
		},
		{
			name: "Deny action",
			policy: &switchpolicy.SmartSwitchNetworkPolicy{
				Action: switchpolicy.SmartSwitchNetworkAction{
					EnforceAction: switchpolicy.SmartSwitchEnforceAction{Deny: true},
				},
			},
			expected: "Deny",
		},
		{
			name:     "Nil policy",
			policy:   nil,
			expected: "<unknown>",
		},
		{
			name: "No action set",
			policy: &switchpolicy.SmartSwitchNetworkPolicy{
				Action: switchpolicy.SmartSwitchNetworkAction{},
			},
			expected: "<unspecified>",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action := formatAction(tc.policy)
			require.Equal(t, tc.expected, action)
		})
	}
}

// --- Tests for formatSwitchSource ---

func TestFormatSwitchSource(t *testing.T) {
	cases := []struct {
		name     string
		source   switchpolicy.SmartSwitchNetworkSource
		expected []string
	}{
		{
			name: "Source with CIDR and VRF",
			source: switchpolicy.SmartSwitchNetworkSource{
				Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{
					CIDR: "10.0.0.0/24",
					VRF:  "vrf1",
				},
			},
			expected: []string{
				"│ Source:",
				"│   • CIDR: 10.0.0.0/24",
				"│   • VRF: vrf1",
			},
		},
		{
			name: "Source with CIDR, VRF and VLAN",
			source: switchpolicy.SmartSwitchNetworkSource{
				Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{
					CIDR: "192.168.1.0/24",
					VRF:  "vrf2",
					VLAN: 100,
				},
			},
			expected: []string{
				"│ Source:",
				"│   • CIDR: 192.168.1.0/24",
				"│   • VRF: vrf2",
				"│   • VLAN: 100",
			},
		},
		{
			name: "Source with only CIDR",
			source: switchpolicy.SmartSwitchNetworkSource{
				Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{
					CIDR: "172.16.0.0/16",
				},
			},
			expected: []string{
				"│ Source:",
				"│   • CIDR: 172.16.0.0/16",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := formatSwitchSource(tc.source)
			for _, substr := range tc.expected {
				if !contains(out, substr) {
					require.Contains(t, out, substr)
				}
			}
		})
	}
}

// --- Tests for formatSwitchDestination ---

func TestFormatSwitchDestination(t *testing.T) {
	cases := []struct {
		name     string
		dest     switchpolicy.SmartSwitchNetworkDestination
		expected []string
	}{
		{
			name: "Destination with CIDR",
			dest: switchpolicy.SmartSwitchNetworkDestination{
				Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{
					CIDR: "192.168.1.0/24",
				},
			},
			expected: []string{
				"│ Destination:",
				"│   • CIDR: 192.168.1.0/24",
			},
		},
		{
			name: "Destination with CIDR and Protocol",
			dest: switchpolicy.SmartSwitchNetworkDestination{
				Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{
					CIDR: "10.0.0.0/24",
				},
				ProtoPorts: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
					switchpolicy.SmartSwitchNetworkProtocolPorts{
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
					},
				},
			},
			expected: []string{
				"│ Destination:",
				"│   • CIDR: 10.0.0.0/24",
				"│   • Protocol: POLICY_PROTOCOL_TCP",
				"│   • Port: 0-65535",
			},
		},
		{
			name: "Destination with CIDR, Protocol and single Port",
			dest: switchpolicy.SmartSwitchNetworkDestination{
				Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{
					CIDR: "172.16.0.0/16",
				},
				ProtoPorts: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
					switchpolicy.SmartSwitchNetworkProtocolPorts{
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP,
						Port:     53,
					},
				},
			},
			expected: []string{
				"│ Destination:",
				"│   • CIDR: 172.16.0.0/16",
				"│   • Protocol: POLICY_PROTOCOL_UDP",
				"│   • Port: 53",
			},
		},
		{
			name: "Destination with CIDR, Protocol and Port range",
			dest: switchpolicy.SmartSwitchNetworkDestination{
				Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{
					CIDR: "10.1.0.0/16",
				},
				ProtoPorts: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
					switchpolicy.SmartSwitchNetworkProtocolPorts{
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
						Port:     80,
						EndPort:  443,
					},
				},
			},
			expected: []string{
				"│ Destination:",
				"│   • CIDR: 10.1.0.0/16",
				"│   • Protocol: POLICY_PROTOCOL_TCP",
				"│   • Ports: 80-443",
			},
		},
		{
			name: "Destination with all fields",
			dest: switchpolicy.SmartSwitchNetworkDestination{
				Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{
					CIDR: "192.168.0.0/24",
					VRF:  "vrf1",
					VLAN: 200,
				},
				ProtoPorts: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
					switchpolicy.SmartSwitchNetworkProtocolPorts{
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
						Port:     8080,
					},
				},
			},
			expected: []string{
				"│ Destination:",
				"│   • CIDR: 192.168.0.0/24",
				"│   • VRF: vrf1",
				"│   • VLAN: 200",
				"│   • Protocol: POLICY_PROTOCOL_TCP",
				"│   • Port: 8080",
			},
		},
		// Test cases for port formatting fix (Port=0 handling)
		{
			name: "Port range starting from 0 (original bug case)",
			dest: switchpolicy.SmartSwitchNetworkDestination{
				Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{
					CIDR: "100.213.1.0/24",
					VLAN: 3400,
				},
				ProtoPorts: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
					switchpolicy.SmartSwitchNetworkProtocolPorts{
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
						Port:     0,
						EndPort:  65534,
					},
				},
			},
			expected: []string{
				"│ Destination:",
				"│   • CIDR: 100.213.1.0/24",
				"│   • VLAN: 3400",
				"│   • Protocol: POLICY_PROTOCOL_TCP",
				"│   • Ports: 0-65534",
			},
		},
		{
			name: "Single port with same start and end port",
			dest: switchpolicy.SmartSwitchNetworkDestination{
				Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{
					CIDR: "10.0.0.0/24",
				},
				ProtoPorts: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
					switchpolicy.SmartSwitchNetworkProtocolPorts{
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP,
						Port:     80,
						EndPort:  80,
					},
				},
			},
			expected: []string{
				"│ Destination:",
				"│   • CIDR: 10.0.0.0/24",
				"│   • Protocol: POLICY_PROTOCOL_UDP",
				"│   • Port: 80",
			},
		},
		{
			name: "Traditional port range",
			dest: switchpolicy.SmartSwitchNetworkDestination{
				Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{
					CIDR: "192.168.1.0/24",
				},
				ProtoPorts: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
					switchpolicy.SmartSwitchNetworkProtocolPorts{
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
						Port:     1000,
						EndPort:  2000,
					},
				},
			},
			expected: []string{
				"│ Destination:",
				"│   • CIDR: 192.168.1.0/24",
				"│   • Protocol: POLICY_PROTOCOL_TCP",
				"│   • Ports: 1000-2000",
			},
		},
		{
			name: "Port 0 only (EndPort=0)",
			dest: switchpolicy.SmartSwitchNetworkDestination{
				Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{
					CIDR: "172.16.0.0/16",
				},
				ProtoPorts: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
					switchpolicy.SmartSwitchNetworkProtocolPorts{
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
						Port:     0,
						EndPort:  0,
					},
				},
			},
			expected: []string{
				"│ Destination:",
				"│   • CIDR: 172.16.0.0/16",
				"│   • Protocol: POLICY_PROTOCOL_TCP",
				"│   • Port: 0-65535",
			},
		},
		{
			name: "Port range starting from 0 with small range",
			dest: switchpolicy.SmartSwitchNetworkDestination{
				Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{
					CIDR: "10.10.0.0/16",
				},
				ProtoPorts: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
					switchpolicy.SmartSwitchNetworkProtocolPorts{
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_UDP,
						Port:     0,
						EndPort:  80,
					},
				},
			},
			expected: []string{
				"│ Destination:",
				"│   • CIDR: 10.10.0.0/16",
				"│   • Protocol: POLICY_PROTOCOL_UDP",
				"│   • Ports: 0-80",
			},
		},
		{
			name: "ICMP protocol without port information",
			dest: switchpolicy.SmartSwitchNetworkDestination{
				Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{
					CIDR: "100.213.1.0/24",
					VLAN: 3400,
				},
				ProtoPorts: &[]switchpolicy.SmartSwitchNetworkProtocolPorts{
					switchpolicy.SmartSwitchNetworkProtocolPorts{
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_ICMP,
						Port:     0,
						EndPort:  0,
					},
				},
			},
			expected: []string{
				"│ Destination:",
				"│   • CIDR: 100.213.1.0/24",
				"│   • VLAN: 3400",
				"│   • Protocol: POLICY_PROTOCOL_ICMP",
				// Note: No port information expected for ICMP
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := formatSwitchDestination(tc.dest)
			for _, substr := range tc.expected {
				if !contains(out, substr) {
					require.Contains(t, out, substr)
				}
			}
		})
	}
}

// --- Tests for formatSwitchPoliciesJsonStringByName ---

func TestFormatSwitchPoliciesJsonStringByName(t *testing.T) {
	cases := []struct {
		name          string
		filteredNames []string
		policyMap     map[switchpolicy.ResourceID]switchpolicy.K8sRulesList
		expectCount   int
	}{
		{
			name:          "Empty filtered names",
			filteredNames: []string{},
			policyMap: map[switchpolicy.ResourceID]switchpolicy.K8sRulesList{
				switchpolicy.NewResourceID("SmartSwitchNetworkPolicy", "default", "policy1"): {
					switchpolicy.NewPolicyRule("hash1", &switchpolicy.SmartSwitchNetworkPolicy{
						Action: switchpolicy.SmartSwitchNetworkAction{
							EnforceAction: switchpolicy.SmartSwitchEnforceAction{Allow: true},
						},
					}),
				},
			},
			expectCount: 0,
		},
		{
			name:          "Single matching policy",
			filteredNames: []string{"SmartSwitchNetworkPolicy/default/policy1"},
			policyMap: map[switchpolicy.ResourceID]switchpolicy.K8sRulesList{
				switchpolicy.NewResourceID("SmartSwitchNetworkPolicy", "default", "policy1"): {
					switchpolicy.NewPolicyRule("hash1", &switchpolicy.SmartSwitchNetworkPolicy{
						Action: switchpolicy.SmartSwitchNetworkAction{
							EnforceAction: switchpolicy.SmartSwitchEnforceAction{Allow: true},
						},
						Source: switchpolicy.SmartSwitchNetworkSource{
							Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{CIDR: "10.0.0.0/24"},
						},
						Destination: switchpolicy.SmartSwitchNetworkDestination{
							Endpoint: switchpolicy.SmartSwitchNetworkEndpoint{CIDR: "192.168.0.0/24"},
						},
					}),
				},
			},
			expectCount: 1,
		},
		{
			name: "Multiple matching policies",
			filteredNames: []string{
				"SmartSwitchNetworkPolicy/default/policy1",
				"SmartSwitchNetworkPolicy/default/policy2",
			},
			policyMap: map[switchpolicy.ResourceID]switchpolicy.K8sRulesList{
				switchpolicy.NewResourceID("SmartSwitchNetworkPolicy", "default", "policy1"): {
					switchpolicy.NewPolicyRule("hash1", &switchpolicy.SmartSwitchNetworkPolicy{
						Action: switchpolicy.SmartSwitchNetworkAction{
							EnforceAction: switchpolicy.SmartSwitchEnforceAction{Allow: true},
						},
					}),
				},
				switchpolicy.NewResourceID("SmartSwitchNetworkPolicy", "default", "policy2"): {
					switchpolicy.NewPolicyRule("hash2", &switchpolicy.SmartSwitchNetworkPolicy{
						Action: switchpolicy.SmartSwitchNetworkAction{
							EnforceAction: switchpolicy.SmartSwitchEnforceAction{Deny: true},
						},
					}),
				},
			},
			expectCount: 2,
		},
		{
			name:          "Filtered name not in policy map",
			filteredNames: []string{"SmartSwitchNetworkPolicy/default/nonexistent"},
			policyMap: map[switchpolicy.ResourceID]switchpolicy.K8sRulesList{
				switchpolicy.NewResourceID("SmartSwitchNetworkPolicy", "default", "policy1"): {
					switchpolicy.NewPolicyRule("hash1", &switchpolicy.SmartSwitchNetworkPolicy{
						Action: switchpolicy.SmartSwitchNetworkAction{
							EnforceAction: switchpolicy.SmartSwitchEnforceAction{Allow: true},
						},
					}),
				},
			},
			expectCount: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := formatSwitchPoliciesJsonStringByName(tc.filteredNames, tc.policyMap)

			// Verify it's valid JSON map
			var policies map[string]interface{}
			err := json.Unmarshal([]byte(result), &policies)
			require.NoError(t, err, "Result should be valid JSON")

			// Verify count
			require.Equal(t, tc.expectCount, len(policies), "Should have expected number of policies")

			// For non-empty results, verify that keys match filtered names that exist in policyMap
			if tc.expectCount > 0 {
				// Check that each filtered name that should match is in the result
				for resourceID := range tc.policyMap {
					policyName := resourceID.String()
					for _, filteredName := range tc.filteredNames {
						if policyName == filteredName {
							require.Contains(t, policies, filteredName, "JSON should contain policy with resourceId: "+filteredName)
							break
						}
					}
				}
			}
		})
	}
}
