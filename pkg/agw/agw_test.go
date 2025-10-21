package agw

import (
	"context"
	"strings"
	"testing"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	netpollibrary "github.com/isovalent/hubble-fgs/pkg/netpol/library"
	"github.com/isovalent/hubble-fgs/pkg/token"

	"github.com/stretchr/testify/require"
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
			filter:   "policy1",
			expected: []string{"policy1"},
		},
		{
			name:     "Exact match none",
			names:    []string{"policy1", "policy2"},
			filter:   "policy3",
			expected: []string{},
		},
		{
			name:     "Wildcard prefix",
			names:    []string{"foo-bar", "foo-baz", "bar-foo"},
			filter:   "foo-*",
			expected: []string{"foo-bar", "foo-baz"},
		},
		{
			name:     "Wildcard suffix",
			names:    []string{"foo-bar", "baz-bar", "bar-foo"},
			filter:   "*-bar",
			expected: []string{"foo-bar", "baz-bar"},
		},
		{
			name:     "Wildcard middle",
			names:    []string{"foo-bar-baz", "foo-baz-bar", "bar-baz-foo"},
			filter:   "foo*-baz",
			expected: []string{"foo-bar-baz"},
		},
		{
			name:     "Case insensitive match",
			names:    []string{"Policy1", "policy2"},
			filter:   "policy1",
			expected: []string{"Policy1"},
		},
		{
			name:     "Wildcard no match",
			names:    []string{"foo", "bar"},
			filter:   "baz-*",
			expected: []string{},
		},
		{
			name:     "With match",
			names:    []string{"foo-with-bar", "with-foo", "bar-with"},
			filter:   "*with*",
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

// --- Tests for formatPolicy, formatCRDPolicy, formatRule ---

func TestFormatPolicy(t *testing.T) {
	cases := []struct {
		name     string
		story    *netpollibrary.PolicyStory
		policyID uint64
		expect   []string
	}{
		{
			name: "Basic PolicyStory",
			story: &netpollibrary.PolicyStory{
				Title: "TestPolicy",
				CRDPolicy: &v1alpha1.TetragonNetworkPolicy{
					Spec: v1alpha1.NetworkPolicySpec{
						LogicalNetworkSelector: &v1alpha1.LogicalNetworkSelector{VRF: "vrf1"},
						DefaultAction:          "Allow",
						Rules: []v1alpha1.NetworkPolicyRule{
							{Action: "Allow", Hook: "Ingress"},
						},
					},
				},
			},
			policyID: 42,
			expect:   []string{"TestPolicy", "  Policy ID:      42"},
		},
		{
			name: "PolicyStory with Description and Source/Destination",
			story: &netpollibrary.PolicyStory{
				Title: "PolicyWithDesc",
				CRDPolicy: &v1alpha1.TetragonNetworkPolicy{
					Spec: v1alpha1.NetworkPolicySpec{
						LogicalNetworkSelector: &v1alpha1.LogicalNetworkSelector{VRF: "vrf2"},
						DefaultAction:          "Deny",
						Rules: []v1alpha1.NetworkPolicyRule{
							{
								Action:      "Deny",
								Hook:        "Egress",
								Description: "Block traffic",
								Source: []v1alpha1.NetworkSource{
									{
										IPBlock: &v1alpha1.NetworkDestinationCIDR{CIDR: "10.1.1.0/24"},
										Ports:   v1alpha1.NetworkDestinationPorts{Protocol: "TCP", Ports: []uint32{8080}},
									},
								},
								Destination: []v1alpha1.NetworkDestination{
									{
										IPBlock: &v1alpha1.NetworkDestinationCIDR{CIDR: "192.168.2.0/24"},
										Ports:   v1alpha1.NetworkDestinationPorts{Protocol: "UDP", Ports: []uint32{53}},
									},
								},
							},
						},
					},
				},
			},
			policyID: 99,
			expect: []string{
				"PolicyWithDesc",
				"  Policy ID:      99",
				"VRF:            vrf2",
				"Default Action: Deny",
				"Action:      Deny",
				"Description: Block traffic",
				"CIDR: 10.1.1.0/24",
				"Protocol: TCP",
				"CIDR: 192.168.2.0/24",
				"Protocol: UDP",
			},
		},
		{
			name: "PolicyStory with multiple rules",
			story: &netpollibrary.PolicyStory{
				Title: "MultiRulePolicy",
				CRDPolicy: &v1alpha1.TetragonNetworkPolicy{
					Spec: v1alpha1.NetworkPolicySpec{
						LogicalNetworkSelector: &v1alpha1.LogicalNetworkSelector{VRF: "vrf3"},
						DefaultAction:          "Allow",
						Rules: []v1alpha1.NetworkPolicyRule{
							{Action: "Allow", Hook: "Ingress"},
							{Action: "Deny", Hook: "Egress"},
						},
					},
				},
			},
			policyID: 123,
			expect: []string{
				"MultiRulePolicy",
				"  Policy ID:      123",
				"VRF:            vrf3",
				"Default Action: Allow",
				"Action:      Allow",
				"Action:      Deny",
			},
		},
		{
			name: "PolicyStory with nil CRDPolicy",
			story: &netpollibrary.PolicyStory{
				Title:     "NoCRDPolicy",
				CRDPolicy: nil,
			},
			policyID: 7,
			expect:   []string{"NoCRDPolicy", "  Policy ID:      7"},
		},
		{
			name: "PolicyStory with empty Title",
			story: &netpollibrary.PolicyStory{
				Title: "",
				CRDPolicy: &v1alpha1.TetragonNetworkPolicy{
					Spec: v1alpha1.NetworkPolicySpec{
						LogicalNetworkSelector: &v1alpha1.LogicalNetworkSelector{VRF: "vrf4"},
						DefaultAction:          "Allow",
						Rules: []v1alpha1.NetworkPolicyRule{
							{Action: "Allow", Hook: "Ingress"},
						},
					},
				},
			},
			policyID: 55,
			expect:   []string{"Policy #1: ", "  Policy ID:      55"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := formatPolicy(1, tc.story, tc.policyID)
			for _, substr := range tc.expect {
				if !contains(out, substr) {
					require.Contains(t, out, substr)
				}
			}
		})
	}
}

func TestFormatCRDPolicy(t *testing.T) {
	cases := []struct {
		name     string
		crd      *v1alpha1.TetragonNetworkPolicy
		expected []string
	}{
		{
			name: "Basic CRDPolicy",
			crd: &v1alpha1.TetragonNetworkPolicy{
				Spec: v1alpha1.NetworkPolicySpec{
					LogicalNetworkSelector: &v1alpha1.LogicalNetworkSelector{VRF: "vrf1"},
					DefaultAction:          "Allow",
					Rules: []v1alpha1.NetworkPolicyRule{
						{Action: "Allow", Hook: "Ingress"},
					},
				},
			},
			expected: []string{
				"  VRF:            vrf1",
				"  Default Action: Allow",
				"  Total Rules:    1",
				"  ┌─ Rule 1 ─────────────────────────────────────────────────────",
				"  │ Action:      Allow",
				"  │ Hook:        Ingress",
				"  │",
				"  └───────────────────────────────────────────────────────────────",
			},
		},
		{
			name: "CRDPolicy with multiple rules",
			crd: &v1alpha1.TetragonNetworkPolicy{
				Spec: v1alpha1.NetworkPolicySpec{
					LogicalNetworkSelector: &v1alpha1.LogicalNetworkSelector{VRF: "vrf2"},
					DefaultAction:          "Deny",
					Rules: []v1alpha1.NetworkPolicyRule{
						{Action: "Allow", Hook: "Ingress"},
						{Action: "Deny", Hook: "Egress"},
					},
				},
			},
			expected: []string{
				"  VRF:            vrf2",
				"  Default Action: Deny",
				"  Total Rules:    2",
				"  ┌─ Rule 1 ─────────────────────────────────────────────────────",
				"  │ Action:      Allow",
				"  │ Hook:        Ingress",
				"  │",
				"  └───────────────────────────────────────────────────────────────",
				"  │",
				"  ┌─ Rule 2 ─────────────────────────────────────────────────────",
				"  │ Action:      Deny",
				"  │ Hook:        Egress",
				"  │",
				"  └───────────────────────────────────────────────────────────────",
			},
		},
		{
			name: "CRDPolicy with nil LogicalNetworkSelector",
			crd: &v1alpha1.TetragonNetworkPolicy{
				Spec: v1alpha1.NetworkPolicySpec{
					LogicalNetworkSelector: nil,
					DefaultAction:          "Allow",
					Rules: []v1alpha1.NetworkPolicyRule{
						{Action: "Allow", Hook: "Ingress"},
					},
				},
			},
			expected: []string{
				"  VRF:            <nil>",
				"  Default Action: Allow",
				"  Total Rules:    1",
				"  ┌─ Rule 1 ─────────────────────────────────────────────────────",
				"  │ Action:      Allow",
				"  │ Hook:        Ingress",
				"  │",
				"  └───────────────────────────────────────────────────────────────",
			},
		},
		{
			name: "CRDPolicy with no rules",
			crd: &v1alpha1.TetragonNetworkPolicy{
				Spec: v1alpha1.NetworkPolicySpec{
					LogicalNetworkSelector: &v1alpha1.LogicalNetworkSelector{VRF: "vrf3"},
					DefaultAction:          "Allow",
					Rules:                  nil,
				},
			},
			expected: []string{
				"  VRF:            vrf3",
				"  Default Action: Allow",
				"  Total Rules:    0",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := formatCRDPolicy(tc.crd)
			for _, substr := range tc.expected {
				if !contains(out, substr) {
					require.Contains(t, out, substr)
				}
			}
		})
	}
}

func TestFormatRule(t *testing.T) {
	cases := []struct {
		name        string
		rule        v1alpha1.NetworkPolicyRule
		expect      []string
		showDetails bool
	}{
		{
			name: "Basic rule",
			rule: v1alpha1.NetworkPolicyRule{
				Action:      "Allow",
				Hook:        "Ingress",
				Description: "desc",
				Source:      []v1alpha1.NetworkSource{},
				Destination: []v1alpha1.NetworkDestination{},
			},
			expect: []string{
				"  ┌─ Rule 1 ─────────────────────────────────────────────────────",
				"  │ Action:      Allow",
				"  │ Hook:        Ingress",
				"  │ Description: desc",
				"  │",
				"  └───────────────────────────────────────────────────────────────",
			},
			showDetails: false,
		},
		{
			name: "Rule with Source and Destination",
			rule: v1alpha1.NetworkPolicyRule{
				Action:      "Deny",
				Hook:        "Egress",
				Description: "deny rule",
				Source: []v1alpha1.NetworkSource{
					{
						IPBlock: &v1alpha1.NetworkDestinationCIDR{CIDR: "10.0.0.0/24"},
						Ports:   v1alpha1.NetworkDestinationPorts{Protocol: "TCP", Ports: []uint32{80}},
					},
				},
				Destination: []v1alpha1.NetworkDestination{
					{
						IPBlock: &v1alpha1.NetworkDestinationCIDR{CIDR: "192.168.1.0/24"},
						Ports:   v1alpha1.NetworkDestinationPorts{Protocol: "UDP", Ports: []uint32{53}},
					},
				},
			},
			expect: []string{
				"  ┌─ Rule 2 ─────────────────────────────────────────────────────",
				"  │ Action:      Deny",
				"  │ Hook:        Egress",
				"  │ Description: deny rule",
				"  │ Source:",
				"  │   • CIDR: 10.0.0.0/24",
				"  │   • Protocol: TCP",
				"  │   • Ports: [80]",
				"  │ Destination:",
				"  │   • CIDR: 192.168.1.0/24",
				"  │   • Protocol: UDP",
				"  │   • Ports: [53]",
				"  │",
				"  └───────────────────────────────────────────────────────────────",
			},
			showDetails: true,
		},
		{
			name: "Rule with empty fields",
			rule: v1alpha1.NetworkPolicyRule{},
			expect: []string{
				"  ┌─ Rule 3 ─────────────────────────────────────────────────────",
				"  │ Action:      ",
				"  │ Hook:        ",
				"  │",
				"  └───────────────────────────────────────────────────────────────",
			},
			showDetails: false,
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := formatRule(i+1, &tc.rule, tc.showDetails)
			for _, substr := range tc.expect {
				if !contains(out, substr) {
					require.Contains(t, out, substr)
				}
			}
		})
	}
}

// --- Tests for formatSourceEndpoints and formatDestEndpoints ---

func TestFormatSourceEndpoints(t *testing.T) {
	cases := []struct {
		name      string
		endpoints []v1alpha1.NetworkSource
		expected  []string
	}{
		{
			name: "Single endpoint",
			endpoints: []v1alpha1.NetworkSource{
				{
					IPBlock: &v1alpha1.NetworkDestinationCIDR{CIDR: "10.0.0.0/24"},
					Ports:   v1alpha1.NetworkDestinationPorts{Protocol: "TCP", Ports: []uint32{80, 443}},
				},
			},
			expected: []string{
				"  │ Source:",
				"  │   • CIDR: 10.0.0.0/24",
				"  │   • Protocol: TCP",
				"  │   • Ports: [80 443]",
				"  │",
			},
		},
		{
			name: "Multiple endpoints",
			endpoints: []v1alpha1.NetworkSource{
				{
					IPBlock: &v1alpha1.NetworkDestinationCIDR{CIDR: "192.168.1.0/24"},
					Ports:   v1alpha1.NetworkDestinationPorts{Protocol: "UDP", Ports: []uint32{53}},
				},
				{
					IPBlock: &v1alpha1.NetworkDestinationCIDR{CIDR: "172.16.0.0/16"},
					Ports:   v1alpha1.NetworkDestinationPorts{Protocol: "TCP", Ports: []uint32{22}},
				},
			},
			expected: []string{
				"  │ Source:",
				"  │   • CIDR: 192.168.1.0/24",
				"  │   • Protocol: UDP",
				"  │   • Ports: [53]",
				"  │   • CIDR: 172.16.0.0/16",
				"  │   • Protocol: TCP",
				"  │   • Ports: [22]",
				"  │",
			},
		},
		{
			name:      "Empty endpoints",
			endpoints: []v1alpha1.NetworkSource{},
			expected:  []string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := formatSourceEndpoints("Source", tc.endpoints)
			for _, substr := range tc.expected {
				if !contains(out, substr) {
					require.Contains(t, out, substr)
				}
			}
		})
	}
}

func TestFormatDestEndpoints(t *testing.T) {
	cases := []struct {
		name      string
		endpoints []v1alpha1.NetworkDestination
		expected  []string
	}{
		{
			name: "Single endpoint",
			endpoints: []v1alpha1.NetworkDestination{
				{
					IPBlock: &v1alpha1.NetworkDestinationCIDR{CIDR: "192.168.1.0/24"},
					Ports:   v1alpha1.NetworkDestinationPorts{Protocol: "UDP", Ports: []uint32{53}},
				},
			},
			expected: []string{
				"  │ Destination:",
				"  │   • CIDR: 192.168.1.0/24",
				"  │   • Protocol: UDP",
				"  │   • Ports: [53]",
				"  │",
			},
		},
		{
			name: "Multiple endpoints",
			endpoints: []v1alpha1.NetworkDestination{
				{
					IPBlock: &v1alpha1.NetworkDestinationCIDR{CIDR: "10.0.0.0/24"},
					Ports:   v1alpha1.NetworkDestinationPorts{Protocol: "TCP", Ports: []uint32{80, 443}},
				},
				{
					IPBlock: &v1alpha1.NetworkDestinationCIDR{CIDR: "172.16.0.0/16"},
					Ports:   v1alpha1.NetworkDestinationPorts{Protocol: "UDP", Ports: []uint32{53}},
				},
			},
			expected: []string{
				"  │ Destination:",
				"  │   • CIDR: 10.0.0.0/24",
				"  │   • Protocol: TCP",
				"  │   • Ports: [80 443]",
				"  │   • CIDR: 172.16.0.0/16",
				"  │   • Protocol: UDP",
				"  │   • Ports: [53]",
				"  │",
			},
		},
		{
			name:      "Empty endpoints",
			endpoints: []v1alpha1.NetworkDestination{},
			expected:  []string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := formatDestEndpoints("Destination", tc.endpoints)
			for _, substr := range tc.expected {
				if !contains(out, substr) {
					require.Contains(t, out, substr)
				}
			}
		})
	}
}

// --- Tests for validateLogConfig ---

func TestValidateLogConfigValidAndInvalidCases(t *testing.T) {
	cases := []struct {
		name   string
		cfg    LogConfigData
		errMsg string
	}{
		{
			name: "Valid config - TCP",
			cfg: LogConfigData{
				Id:   "id1",
				Type: LogTypeSyslog,
				Config: LogConfigDataConfig{
					Host: "127.0.0.1",
					Port: "514",
					Mode: "tcp",
				},
			},
			errMsg: "",
		},
		{
			name: "Valid config - UDP",
			cfg: LogConfigData{
				Id:   "id2",
				Type: LogTypeSyslog,
				Config: LogConfigDataConfig{
					Host: "192.168.1.1",
					Port: "1514",
					Mode: "udp",
				},
			},
			errMsg: "",
		},
		{
			name: "Invalid host",
			cfg: LogConfigData{
				Id:   "id3",
				Type: LogTypeSyslog,
				Config: LogConfigDataConfig{
					Host: "not-an-ip",
					Port: "514",
					Mode: "tcp",
				},
			},
			errMsg: "invalid host: must be a valid IPv4 address",
		},
		{
			name: "Invalid port (non-numeric)",
			cfg: LogConfigData{
				Id:   "id4",
				Type: LogTypeSyslog,
				Config: LogConfigDataConfig{
					Host: "127.0.0.1",
					Port: "abc",
					Mode: "tcp",
				},
			},
			errMsg: "invalid port: must be a valid integer",
		},
		{
			name: "Invalid port (out of range)",
			cfg: LogConfigData{
				Id:   "id5",
				Type: LogTypeSyslog,
				Config: LogConfigDataConfig{
					Host: "127.0.0.1",
					Port: "70000",
					Mode: "tcp",
				},
			},
			errMsg: "invalid port: must be between 1 and 65535",
		},
		{
			name: "Invalid mode",
			cfg: LogConfigData{
				Id:   "id6",
				Type: LogTypeSyslog,
				Config: LogConfigDataConfig{
					Host: "127.0.0.1",
					Port: "514",
					Mode: "foo",
				},
			},
			errMsg: "invalid mode: must be 'tcp' or 'udp'",
		},
		{
			name: "Empty type",
			cfg: LogConfigData{
				Id:   "id7",
				Type: "",
				Config: LogConfigDataConfig{
					Host: "127.0.0.1",
					Port: "514",
					Mode: "tcp",
				},
			},
			errMsg: "log type is required",
		},
		{
			name: "Empty host",
			cfg: LogConfigData{
				Id:   "id8",
				Type: LogTypeSyslog,
				Config: LogConfigDataConfig{
					Host: "",
					Port: "514",
					Mode: "tcp",
				},
			},
			errMsg: "invalid host: must be a valid IPv4 address",
		},
		{
			name: "Empty port",
			cfg: LogConfigData{
				Id:   "id9",
				Type: LogTypeSyslog,
				Config: LogConfigDataConfig{
					Host: "127.0.0.1",
					Port: "",
					Mode: "tcp",
				},
			},
			errMsg: "invalid port: must be a valid integer",
		},
		{
			name: "Empty mode",
			cfg: LogConfigData{
				Id:   "id10",
				Type: LogTypeSyslog,
				Config: LogConfigDataConfig{
					Host: "127.0.0.1",
					Port: "514",
					Mode: "",
				},
			},
			errMsg: "log mode is required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateLogConfig(tc.cfg.Id, tc.cfg)
			if tc.errMsg == "" {
				require.NoError(t, err, "expected no error, got: %v", err)
			} else {
				require.Error(t, err, "expected error but got nil")
				require.EqualError(t, err, tc.errMsg)
			}
		})
	}
}

// --- Test for LoadSyslog with empty list ---

func TestLoadSyslogCases(t *testing.T) {
	agw := &AgentGateway{}
	cases := []struct {
		name      string
		input     string
		expectErr bool
		errMsg    string
	}{
		{
			name:      "Empty list",
			input:     "{}",
			expectErr: false,
			errMsg:    "",
		},
		{
			name:      "Invalid JSON",
			input:     "{invalid}",
			expectErr: true,
			errMsg:    "invalid character",
		},
		{
			name: "Valid single syslog config",
			input: `{
				"sys1": {
					"id": "sys1",
					"type": "syslog",
					"config": {
						"host": "127.0.0.1",
						"port": "514",
						"mode": "tcp"
					},
					"secrets": {}
				}
			}`,
			expectErr: false,
			errMsg:    "",
		},
		{
			name: "Valid syslog config with UDP",
			input: `{
				"sys2": {
					"id": "sys2",
					"type": "syslog",
					"config": {
						"host": "192.168.1.1",
						"port": "1514",
						"mode": "udp"
					},
					"secrets": {}
				}
			}`,
			expectErr: false,
			errMsg:    "",
		},
		{
			name: "Invalid type",
			input: `{
				"sys3": {
					"id": "sys3",
					"type": "unknown",
					"config": {
						"host": "127.0.0.1",
						"port": "514",
						"mode": "tcp"
					},
					"secrets": {}
				}
			}`,
			expectErr: true,
			errMsg:    "log type is invalid",
		},
		{
			name: "Missing type",
			input: `{
				"sys4": {
					"id": "sys4",
					"config": {
						"host": "127.0.0.1",
						"port": "514",
						"mode": "tcp"
					},
					"secrets": {}
				}
			}`,
			expectErr: true,
			errMsg:    "log type is required",
		},
		{
			name: "Invalid host",
			input: `{
				"sys5": {
					"id": "sys5",
					"type": "syslog",
					"config": {
						"host": "not-an-ip",
						"port": "514",
						"mode": "tcp"
					},
					"secrets": {}
				}
			}`,
			expectErr: true,
			errMsg:    "invalid host: must be a valid IPv4 address",
		},
		{
			name: "Invalid port (non-numeric)",
			input: `{
				"sys6": {
					"id": "sys6",
					"type": "syslog",
					"config": {
						"host": "127.0.0.1",
						"port": "abc",
						"mode": "tcp"
					},
					"secrets": {}
				}
			}`,
			expectErr: true,
			errMsg:    "invalid port: must be a valid integer",
		},
		{
			name: "Invalid port (out of range)",
			input: `{
				"sys7": {
					"id": "sys7",
					"type": "syslog",
					"config": {
						"host": "127.0.0.1",
						"port": "70000",
						"mode": "tcp"
					},
					"secrets": {}
				}
			}`,
			expectErr: true,
			errMsg:    "invalid port: must be between 1 and 65535",
		},
		{
			name: "Invalid mode",
			input: `{
				"sys8": {
					"id": "sys8",
					"type": "syslog",
					"config": {
						"host": "127.0.0.1",
						"port": "514",
						"mode": "foo"
					},
					"secrets": {}
				}
			}`,
			expectErr: true,
			errMsg:    "invalid mode: must be 'tcp' or 'udp'",
		},
		{
			name:      "Empty config object",
			input:     "",
			expectErr: true,
			errMsg:    "unexpected end of JSON input",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := agw.LoadSyslog(context.Background(), tc.input)
			if tc.expectErr {
				require.Error(t, err)
				if tc.errMsg != "" {
					require.Contains(t, err.Error(), tc.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// --- Test for ShowSyslog ---
func TestShowSyslogNoConfig(t *testing.T) {
	agw := &AgentGateway{}
	// Ensure config is deleted before testing
	_ = agw.LoadSyslog(context.Background(), "{}")
	out, err := agw.ShowSyslog(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "log config not found")
	require.Empty(t, out)
}

func TestShowSyslogWithConfig(t *testing.T) {
	agw := &AgentGateway{}
	// Load a valid syslog config
	input := `{
		"sys1": {
			"id": "sys1",
			"type": "syslog",
			"config": {
				"host": "127.0.0.1",
				"port": "514",
				"mode": "tcp"
			},
			"secrets": {
				"token": "tok",
				"username": "user",
				"password": "pass",
				"ca": "ca",
				"cert": "cert",
				"key": "key",
				"key_password": "keypass"
			}
		}
	}`
	err := agw.LoadSyslog(context.Background(), input)
	require.NoError(t, err)
	out, err := agw.ShowSyslog(context.Background())
	require.NoError(t, err)
	require.Contains(t, out, `"host": "127.0.0.1"`)
	require.Contains(t, out, `"port": "514"`)
	require.Contains(t, out, `"token": "tok"`)
	require.Contains(t, out, `"username": "user"`)
}

func TestLoadSyslogDeleteConfig(t *testing.T) {
	agw := &AgentGateway{}
	// Load a valid config first
	input := `{
		"sys1": {
			"id": "sys1",
			"type": "syslog",
			"config": {
				"host": "127.0.0.1",
				"port": "514",
				"mode": "tcp"
			},
			"secrets": {}
		}
	}`
	err := agw.LoadSyslog(context.Background(), input)
	require.NoError(t, err)
	// Now delete config by passing empty list
	err = agw.LoadSyslog(context.Background(), "{}")
	require.NoError(t, err)
	_, err = agw.ShowSyslog(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "log config not found")
}

// --- Test for ShowTokens ---

func TestShowTokens(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(*AgentGateway)
		expected string
	}{
		{
			name: "Empty tokens",
			setup: func(_ *AgentGateway) {
				// No setup, tokens should be empty
			},
			expected: "",
		},
		{
			name: "Single token",
			setup: func(agw *AgentGateway) {
				agw.Token = token.GetAgentToken()
				agw.Token.SetK8sAuthToken("token123")
			},
			expected: "token123",
		},
		{
			name: "Multiple tokens",
			setup: func(agw *AgentGateway) {
				agw.Token = token.GetAgentToken()
				agw.Token.SetK8sAuthToken("tokenA,tokenB")
			},
			expected: "tokenA,tokenB",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agw := &AgentGateway{}
			tc.setup(agw)
			token := agw.ShowTokens(context.Background())
			require.Equal(t, tc.expected, token)
		})
	}
}

// --- Test for Reopen ---

func TestReopen(t *testing.T) {
	agw := &AgentGateway{}
	result := agw.Reopen(context.Background())
	if result != "Reopen ok" {
		require.Equal(t, "Reopen ok", result)
	}
}

// --- Test for PingFwa ---

func TestPingFwa(t *testing.T) {
	agw := &AgentGateway{}
	result := agw.PingFwa(context.Background(), "dpu1")
	if result != "" {
		require.Equal(t, "", result)
	}
}
