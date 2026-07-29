// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build sudo_tests

package recordbpftest

import (
	"context"
	"net/netip"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/testutils/sensors"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/bpftest"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/datapath"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	"github.com/isovalent/hubble-fgs/pkg/workloadid"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"

	"github.com/isovalent/hubble-fgs/pkg/netpol/library"
)

var (
	prog datapath.Interface = &datapath.BPFProgrammer{}
)

type recordCheck struct {
	check        string
	expectDeny   bool // If true, this specific check should fail (be denied)
	expectReject bool // If true, expect fast failure instead of timeout
}

type recordTest struct {
	name    string
	records []record.DatapathRecord
	checks  []recordCheck
	deny    bool // Default deny expectation for checks without explicit expectDeny
	// Skip test if bpf_icmp_send kfunc is not available
	skipIfNoICMPSend bool
}

// Policy record building blocks
var (
	wildcardSrc = &types.ProcessTreeKey{
		WLID:  uint64(workloadid.WorkloadID(0)),
		Depth: 0,
		Self:  0,
		Path:  [8]uint64{0, 0, 0, 0, 0, 0, 0, 0},
	}

	ipLo1Policy = record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicy1",
			RuleName:   "testRule1",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				CIDR: netip.MustParsePrefix("127.0.0.1/32"),
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyDeny,
		},
	}
	ipLo1AllowPolicy = record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicyAllow1",
			RuleName:   "testRuleAllow1",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				CIDR: netip.MustParsePrefix("127.0.0.1/32"),
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyAllow,
		},
	}
	ipLo2Policy = record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicy2",
			RuleName:   "testRule2",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				CIDR: netip.MustParsePrefix("127.0.0.2/32"),
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyDeny,
		},
	}
	ipLo2AllowPolicy = record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicyAllow2",
			RuleName:   "testRuleAllow2",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				CIDR: netip.MustParsePrefix("127.0.0.2/32"),
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyAllow,
		},
	}
	ipLo3Policy = record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicy3",
			RuleName:   "testRule3",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				CIDR: netip.MustParsePrefix("127.0.0.0/24"),
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyDeny,
		},
	}
	ipLo3AllowPolicy = record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicyAllow3",
			RuleName:   "testRuleAllow3",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				CIDR: netip.MustParsePrefix("127.0.0.0/24"),
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyAllow,
		},
	}
	dnsLoDenyPolicy = record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicyDNSDeny",
			RuleName:   "testRuleDNSDeny",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_DNS,
				Dns:  "localhost.",
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyDeny,
		},
	}
	dnsLoDenyFooPolicy = record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicyDNSDeny",
			RuleName:   "testRuleDNSDeny",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_DNS,
				Dns:  "foo.io",
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyDeny,
		},
	}
	dnsLoAllowPolicy = record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicyDNSAllow",
			RuleName:   "testRuleDNSAllow",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_DNS,
				Dns:  "localhost.",
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyAllow,
		},
	}
	podDenyPolicy = record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicyPod",
			RuleName:   "testRulePod",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type:      tetragon.EndpointType_ENDPOINT_TYPE_POD,
				Kind:      "bpfTestKind",
				Namespace: "bpfTestNamespace",
				Name:      "bpfTestName",
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyDeny,
		},
	}
	podAllowPolicy = record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicyPod",
			RuleName:   "testRulePod",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type:      tetragon.EndpointType_ENDPOINT_TYPE_POD,
				Kind:      "bpfTestKind",
				Namespace: "bpfTestNamespace",
				Name:      "bpfTestName",
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyAllow,
		},
	}
	defaultAllow = record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicyPod",
			RuleName:   "testRulePod",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP:   nil,
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyAllow,
		},
	}
	defaultDeny = record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicyPod",
			RuleName:   "testRulePod",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP:   nil,
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyDeny,
		},
	}
	// Port-specific policies for testing wildcard local_id + specific port lookup
	// These policies use wildcard src (local_id=0) but specific ports
	ipLoPort8080DenyPolicy = record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicyPort8080",
			RuleName:   "testRulePort8080",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				CIDR: netip.MustParsePrefix("127.0.0.1/32"),
			},
			Port: 8080,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyDeny,
		},
	}
	ipLoPort8081AllowPolicy = record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicyPort8081",
			RuleName:   "testRulePort8081",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				CIDR: netip.MustParsePrefix("127.0.0.1/32"),
			},
			Port: 8081,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyAllow,
		},
	}
	// Wildcard port policy that should only match if specific port policies don't match
	ipLoWildcardPortAllowPolicy = record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicyWildcardPort",
			RuleName:   "testRuleWildcardPort",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				CIDR: netip.MustParsePrefix("127.0.0.1/32"),
			},
			Port: 0, // Wildcard port
		},
		Action: &record.DatapathAction{
			Action: record.PolicyAllow,
		},
	}
	// Reject policy, like deny but sends ICMP unreachable
	ipLo1RejectPolicy = record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicyReject1",
			RuleName:   "testRuleReject1",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				CIDR: netip.MustParsePrefix("127.0.0.1/32"),
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyReject | record.PolicyDeny,
		},
	}
)

// checks
var (
	curl       = []recordCheck{{check: "curl"}}
	digAndCurl = []recordCheck{{check: "dig"}, {check: "curl"}}
)

var tests = []recordTest{
	{ // Basic /32 hit and deny
		name:    "testDenyLo",
		records: []record.DatapathRecord{ipLo1Policy},
		checks:  curl,
		deny:    true,
	},
	{ // Test basic /32 deny record when a unspec entry exists in the dest map for a tuple
		name:    "testDenyLoDup",
		records: []record.DatapathRecord{ipLo1Policy},
		checks:  curl,
		deny:    true,
	},
	{ // policy deny miss for a different IP
		name:    "testMissDenyLo",
		records: []record.DatapathRecord{ipLo2Policy},
		checks:  curl,
		deny:    false,
	},
	{ // policy allow miss for a different IP
		name:    "testMissAllowLo",
		records: []record.DatapathRecord{ipLo2AllowPolicy},
		checks:  curl,
		deny:    false,
	},
	{ // policy deny for /24
		name:    "testDenyLo/24",
		records: []record.DatapathRecord{ipLo3Policy},
		checks:  curl,
		deny:    true,
	},
	{ // policy allow for /24
		name:    "testAllowLo/24",
		records: []record.DatapathRecord{ipLo3AllowPolicy},
		checks:  curl,
		deny:    false,
	},
	{ // policy deny ignores dns and drops connect
		name:    "testIgnoreDigWithCIDRLo",
		records: []record.DatapathRecord{ipLo1Policy},
		checks:  digAndCurl,
		deny:    true,
	},
	{ // policy allow ignores dns and allows connect
		name:    "testIgnoreDigWithCIDRLo",
		records: []record.DatapathRecord{ipLo1AllowPolicy},
		checks:  digAndCurl,
		deny:    false,
	},
	{ // basic localhost dns deny connect
		name:    "testDigDenyLo",
		records: []record.DatapathRecord{dnsLoDenyPolicy},
		checks:  digAndCurl,
		deny:    true,
	},
	{ // basic miss foo dns allow connect
		name:    "testDigDenyFooLo",
		records: []record.DatapathRecord{dnsLoDenyFooPolicy},
		checks:  digAndCurl,
		deny:    false,
	},
	{ // basic localhost dns allow connect
		name:    "testDigAllowLo",
		records: []record.DatapathRecord{dnsLoAllowPolicy},
		checks:  digAndCurl,
		deny:    false,
	},
	{ // test conflicting policy and dns deny wins
		name:    "testCIDRandDNSDeny",
		records: []record.DatapathRecord{dnsLoDenyPolicy, ipLo1AllowPolicy},
		checks:  digAndCurl,
		deny:    true,
	},
	{ // test conflicting policy and cidr deny wins
		name:    "testDNSandCIDRDeny",
		records: []record.DatapathRecord{dnsLoAllowPolicy, ipLo1Policy},
		checks:  digAndCurl,
		deny:    true,
	},
	{ // test two allow policy and cidr and dns so allow wins
		name:    "testDNSwithCIDRAllow",
		records: []record.DatapathRecord{dnsLoAllowPolicy, ipLo1AllowPolicy},
		checks:  digAndCurl,
		deny:    false,
	},
	{ // test two deny policy and cidr and dns so deny wins
		name:    "testDNSwithCIDRDeny",
		records: []record.DatapathRecord{dnsLoDenyPolicy, ipLo1Policy},
		checks:  digAndCurl,
		deny:    true,
	},
	{ // test basic Pod deny policy
		name:    "testPodDeny",
		records: []record.DatapathRecord{podDenyPolicy},
		checks:  curl,
		deny:    true,
	},
	{ // test basic Pod allow policy
		name:    "testPodAllow",
		records: []record.DatapathRecord{podAllowPolicy},
		checks:  curl,
		deny:    false,
	},
	{ // test conflicting Pod allow policy with DNS deny
		name:    "testPodAllowDNSDeny",
		records: []record.DatapathRecord{podAllowPolicy, dnsLoDenyPolicy},
		checks:  digAndCurl,
		deny:    true,
	},
	{ // test conflicting Pod allow policy with DNS deny, reverse order
		name:    "testPodAllowDNSDeny",
		records: []record.DatapathRecord{dnsLoDenyPolicy, podAllowPolicy},
		checks:  digAndCurl,
		deny:    true,
	},
	{ // test conflicting Pod deny policy with DNS allow
		name:    "testDNSAllowPodDeny",
		records: []record.DatapathRecord{podDenyPolicy, dnsLoAllowPolicy},
		checks:  digAndCurl,
		deny:    true,
	},
	{ // test conflicting Pod deny policy with DNS allow, reverse order
		name:    "testDNSAllowPoDDeny",
		records: []record.DatapathRecord{dnsLoDenyPolicy, podAllowPolicy},
		checks:  digAndCurl,
		deny:    true,
	},
	{ // test default deny with IP curl
		name:    "testDefaultDenyIP",
		records: []record.DatapathRecord{defaultDeny},
		checks:  curl,
		deny:    true,
	},
	{ // test default deny with dns curl
		name:    "testDefaultDenyDNS",
		records: []record.DatapathRecord{defaultDeny},
		checks:  digAndCurl,
		deny:    true,
	},
	{ // test default allow with IP curl
		name:    "testDefaultAllowIP",
		records: []record.DatapathRecord{defaultAllow},
		checks:  curl,
		deny:    false,
	},
	{ // test default allow with dns curl
		name:    "testDefaultAllowDNS",
		records: []record.DatapathRecord{defaultAllow},
		checks:  digAndCurl,
		deny:    false,
	},
	{ // test default deny with DNS deny with dig
		name:    "testDefaultDenyWithDNSDenyDig",
		records: []record.DatapathRecord{dnsLoDenyPolicy, defaultDeny},
		checks:  digAndCurl,
		deny:    true,
	},
	{ // test default deny with DNS allow with dig
		name:    "testDefaultDenyWithDNSAllowDig",
		records: []record.DatapathRecord{dnsLoAllowPolicy, defaultDeny},
		checks:  digAndCurl,
		deny:    false,
	},
	{ // test default allow with DNS deny with curl
		name:    "testDefaultDenyWithDNSAllowDig",
		records: []record.DatapathRecord{dnsLoDenyPolicy, defaultAllow},
		checks:  digAndCurl,
		deny:    true,
	},
	{ // test default allow with DNS Deny with curl
		name:    "testDefaultDenyWithDNSAllowDig",
		records: []record.DatapathRecord{dnsLoDenyPolicy, defaultAllow},
		checks:  digAndCurl,
		deny:    true,
	},
	{ // test default deny with IP deny with dig
		name:    "testDefaultDenyWithDNSDenyDig",
		records: []record.DatapathRecord{ipLo1Policy, defaultDeny},
		checks:  curl,
		deny:    true,
	},
	{ // test default deny with IP allow with dig
		name:    "testDefaultDenyWithDNSAllowDig",
		records: []record.DatapathRecord{ipLo1AllowPolicy, defaultDeny},
		checks:  curl,
		deny:    false,
	},
	{ // test default allow with IP deny with curl
		name:    "testDefaultDenyWithDNSAllowDig",
		records: []record.DatapathRecord{ipLo1Policy, defaultAllow},
		checks:  curl,
		deny:    true,
	},
	{ // test default allow with IP Deny with curl
		name:    "testDefaultDenyWithDNSAllowDig",
		records: []record.DatapathRecord{ipLo1Policy, defaultAllow},
		checks:  curl,
		deny:    true,
	},
	// Port-specific policy tests (verifies wildcard local_id + specific port lookup)
	{ // Test port-specific deny on 8080, allow on 8081
		name:    "testPortSpecificDeny8080Allow8081",
		records: []record.DatapathRecord{ipLoPort8080DenyPolicy, ipLoPort8081AllowPolicy},
		checks: []recordCheck{
			{check: "curl", expectDeny: true},      // 8080 should be denied
			{check: "curl8081", expectDeny: false}, // 8081 should be allowed
		},
		deny: false,
	},
	{ // Test port-specific deny takes precedence over wildcard allow
		name:    "testPortSpecificDenyOverridesWildcardAllow",
		records: []record.DatapathRecord{ipLoPort8080DenyPolicy, ipLoWildcardPortAllowPolicy},
		checks: []recordCheck{
			{check: "curl", expectDeny: true},      // 8080 should be denied (specific port match)
			{check: "curl8081", expectDeny: false}, // 8081 should be allowed (falls through to wildcard)
		},
		deny: false,
	},
	{ // Test wildcard port policy is used when no port-specific match
		name:    "testWildcardPortFallback",
		records: []record.DatapathRecord{ipLoWildcardPortAllowPolicy},
		checks: []recordCheck{
			{check: "curl", expectDeny: false},     // 8080 should match wildcard allow
			{check: "curl8081", expectDeny: false}, // 8081 should match wildcard allow
		},
		deny: false,
	},
	{ // Test reject policy sends ICMP and fails fast
		name:             "testRejectFastFailure",
		records:          []record.DatapathRecord{ipLo1RejectPolicy},
		skipIfNoICMPSend: true,
		checks: []recordCheck{
			{check: "curl", expectDeny: true, expectReject: true},
		},
		deny: true,
	},
}

// registerTestPolicies registers test policies with the global policy repository
// so that the BPF programmer can map policy names and rules to IDs. Without this,
// every record programming call logs warnings about failing to resolve policy IDs,
// flooding test output and masking real failures.
func registerTestPolicies(records []record.DatapathRecord) {
	// Group records by policy name to build complete PolicyStory entries
	policiesMap := make(map[string]map[types.TetragonPolicyUniqueID]record.DatapathRecord)

	for _, rec := range records {
		policyName := rec.PolicyUID.PolicyName
		if policiesMap[policyName] == nil {
			policiesMap[policyName] = make(map[types.TetragonPolicyUniqueID]record.DatapathRecord)
		}
		// Store unique policy UID (policy name + rule name)
		policiesMap[policyName][rec.PolicyUID] = rec
	}

	repo := library.GetRepository()

	// Register each policy with all its rules
	for policyName, rules := range policiesMap {
		// Skip if already registered
		if repo.Get(policyName) != nil {
			continue
		}

		// Build IrPolicy entries for this policy
		irPolicies := make([]*types.TetragonNetworkPolicy, 0, len(rules))
		for uid := range rules {
			irPolicies = append(irPolicies, &types.TetragonNetworkPolicy{
				PolicyUID:       uid,
				RuleDescription: uid.RuleName, // Critical: RuleDescription must match RuleName
			})
		}

		// Register the policy story
		repo.Add(&library.PolicyStory{
			Title:    policyName,
			IrPolicy: irPolicies,
		})
	}
}

func loadRecords(r *recordTest, t *testing.T) {
	// Register policies with the repository before programming records
	registerTestPolicies(r.records)

	for _, rec := range r.records {
		if rec.Endpoint.EP == nil {
			continue
		}
		if rec.Endpoint.EP.Type == tetragon.EndpointType_ENDPOINT_TYPE_POD {
			epPod := &v1alpha1.PodInfo{
				WorkloadType: metav1.TypeMeta{
					Kind: rec.Endpoint.EP.Kind,
				},
				WorkloadObject: v1alpha1.WorkloadObjectMeta{
					Namespace: rec.Endpoint.EP.Namespace,
					Name:      rec.Endpoint.EP.Name,
				},
				Status: v1alpha1.PodInfoStatus{
					PodIPs: []v1alpha1.PodIP{
						{IP: "127.0.0.1"},
					},
				},
			}
			c := endpoint.MustGet()
			c.AddIpPodMap(epPod)
		}
	}
	err := prog.AddRecords(r.records, true)
	require.NoError(t, err)
}

func unloadRecords(r *recordTest, t *testing.T) {
	err := prog.RemoveRecords(r.records)
	require.NoError(t, err)

	err = prog.FlushCachedEntries()
	require.NoError(t, err)
}

func checkCurlResult(t *testing.T, err error, expectDeny, expectReject bool) {
	t.Helper()
	if expectDeny {
		var exitErr *exec.ExitError
		require.ErrorAs(t, err, &exitErr)
		if expectReject {
			require.Equal(t, 7, exitErr.ExitCode(),
				"reject should return exit code 7 (connection refused)")
		} else {
			require.Equal(t, 28, exitErr.ExitCode(),
				"deny should return exit code 28 (timeout)")
		}
	} else {
		require.NoError(t, err)
	}
}

func runCmds(r *recordTest, t *testing.T) {
	for _, cmd := range r.checks {
		// Use per-check expectDeny if set, otherwise use test-level deny
		expectDeny := cmd.expectDeny
		if !expectDeny {
			expectDeny = r.deny
		}

		switch cmd.check {
		case "curl":
			curlCmd := exec.Command("curl", "--max-time", "0.5", "--ipv4", "127.0.0.1:8080")
			err := curlCmd.Run()
			t.Log("curl 8080...")
			checkCurlResult(t, err, expectDeny, cmd.expectReject)
		case "curl8081":
			curlCmd := exec.Command("curl", "--max-time", "0.5", "--ipv4", "127.0.0.1:8081")
			err := curlCmd.Run()
			t.Log("curl 8081...")
			checkCurlResult(t, err, expectDeny, cmd.expectReject)
		case "dig":
			digCmd := exec.Command("dig", "localhost")
			err := digCmd.Run()
			t.Log("dig...")
			require.NoError(t, err)
			// Give BPF DNS parser time to process the response and populate tg_dns_ip_id map
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func TestRecords(t *testing.T) {
	// So far DNS policy are only supported on amd64 but could be extend to arm64 on recent kernels
	if runtime.GOARCH != "amd64" || !kernels.MinKernelVersion("5.15.0") {
		t.Skip()
	}

	testutils.StartSimpleHTTPServer(t, ":8080")
	testutils.StartSimpleHTTPServer(t, ":8081")

	ctx, cancel := context.WithTimeout(context.Background(), sensors.ConfigDefaults.CmdWaitTime)
	defer cancel()

	bpftest.StartMinimalTetragonModel(ctx, t)

	curlArg := []string{"--max-time", "0.5", "--ipv4", "127.0.0.1:8080"}

	// Check that curl to the domain works
	// Note: wanted to use the Go HTTP request directly but the issue is
	// that the socket is reused between this test and the one after
	// tetragon started
	curlCmd := exec.Command("curl", curlArg...)
	err := curlCmd.Run()
	require.NoError(t, err)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.skipIfNoICMPSend && !utils.HasBPFICMPSendResult() {
				t.Skip("bpf_icmp_send kfunc not available")
			}
			loadRecords(&test, t)
			runCmds(&test, t)
			unloadRecords(&test, t)

			// Check unload provides clean state
			curlCmd := exec.Command("curl", curlArg...)
			err := curlCmd.Run()
			require.NoError(t, err)

			// Flush ghost cached entries created by the clean-state curl
			// above. The curl triggers BPF processing which can find zeroed
			// default templates (left by RemoveRecords) and create cached
			// ALLOW entries that leak into the next subtest.
			err = prog.FlushCachedEntries()
			require.NoError(t, err)
		})
	}

	// Special test: verify policy template flag behavior
	// This test verifies that policy entries have DEST_FLAG_POLICY_TEMPLATE_ONLY set,
	// and that cached entries created by real traffic do NOT have the flag set.
	// Uses 127.0.0.2 to avoid conflicts with leftover entries from port-specific tests.
	t.Run("testPolicyTemplateFlagClearing", func(t *testing.T) {
		testRecord := &recordTest{
			name:    "templateFlagTest",
			records: []record.DatapathRecord{ipLo2AllowPolicy},
			checks:  nil,
			deny:    false,
		}

		loadRecords(testRecord, t)
		defer unloadRecords(testRecord, t)

		time.Sleep(100 * time.Millisecond)

		// Open the destination_endpoint_map to check flags
		destMap := filepath.Join(bpf.MapPrefixPath(), "destination_endpoint_map")
		m, err := ebpf.LoadPinnedMap(destMap, nil)
		require.NoError(t, err, "Failed to open destination_endpoint_map")
		defer m.Close()

		// Find entries with the policy template flag set (before traffic)
		var foundPolicyEntry bool
		var k types.DestinationEndpointKey
		var v types.DestinationEndpointValue
		iter := m.Iterate()
		for iter.Next(&k, &v) {
			if v.Flags&types.DestFlagPolicyTemplateOnly != 0 {
				foundPolicyEntry = true
				t.Logf("Found policy entry with template flag: key=%+v flags=0x%x", k, v.Flags)
			}
		}
		require.True(t, foundPolicyEntry, "Expected policy entry with DEST_FLAG_POLICY_TEMPLATE_ONLY set")

		// Generate traffic to trigger cached entry creation (use 127.0.0.2 to avoid conflicts)
		curlCmd := exec.Command("curl", "--max-time", "0.5", "--ipv4", "127.0.0.2:8080")
		err = curlCmd.Run()
		require.NoError(t, err, "curl should succeed with allow policy")

		time.Sleep(100 * time.Millisecond)

		// Look for a cached entry WITHOUT the template flag
		var foundCachedEntry bool
		iter = m.Iterate()
		for iter.Next(&k, &v) {
			// Cached entries have non-zero LocalId (policy templates use LocalId=0)
			if v.Flags&types.DestFlagPolicyTemplateOnly == 0 && k.LocalId > 0 {
				foundCachedEntry = true
				t.Logf("Found cached entry: key=%+v flags=0x%x tx=%d rx=%d", k, v.Flags, v.TxBytes, v.RxBytes)
			}
		}
		require.True(t, foundCachedEntry, "Expected cached entry without template flag after traffic")
		t.Log("Verified: Policy template flag cleared for cached entries")
	})
}
