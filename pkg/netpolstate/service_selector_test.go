// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !nok8s

package netpolstate

import (
	"net/netip"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stype "k8s.io/apimachinery/pkg/types"

	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/netpol/servicemap"
)

// testServiceSelectorPolicy creates a serviceSelector policy for testing
func testServiceSelectorPolicy(name, subjectLabels, svcName, svcNamespace, action string, ports []uint32) *types.TetragonNetworkPolicy {
	denyAction := &types.TetragonEnforceAction{
		Deny:  true,
		Allow: false,
	}
	allowAction := &types.TetragonEnforceAction{
		Deny:  false,
		Allow: true,
	}

	ml := make(map[string]string)
	for _, l := range splitLabels(subjectLabels) {
		kv := splitLabel(l)
		if len(kv) == 2 {
			ml[kv[0]] = kv[1]
		}
	}

	policy := &types.TetragonNetworkPolicy{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: name,
			RuleName:   "rule1",
		},
		Subject: types.TetragonNetworkSubject{
			Labels: types.TetragonNetworkLabels{Equal: ml},
		},
		Destination: types.TetragonNetworkDestination{
			ServiceRef: &types.TetragonServiceRef{
				Name:      svcName,
				Namespace: svcNamespace,
			},
			Ports: ports,
		},
	}

	if action == "deny" {
		policy.Action.EnforceAction = denyAction
		policy.Default.EnforceAction = allowAction
	} else {
		policy.Action.EnforceAction = allowAction
		policy.Default.EnforceAction = denyAction
	}

	return policy
}

func splitLabels(labels string) []string {
	if labels == "" {
		return nil
	}
	return split(labels, ",")
}

func splitLabel(label string) []string {
	return split(label, "=")
}

func split(s, sep string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if string(s[i]) == sep {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}

// TestServiceSelectorRecordGeneration verifies that serviceSelector policies
// generate CIDR records for ClusterIP and endpoint IPs
func TestServiceSelectorRecordGeneration(t *testing.T) {
	s := NewFakePolicyState(t)

	srcPodName := "client-pod"
	srcPodLabels := "app=client"

	// Setup service in ServiceMap
	sm := servicemap.NewServiceMap(s)
	s.SetServiceMap(sm)
	clusterIP := netip.MustParseAddr("10.96.0.100")
	sm.AddOrUpdate(&servicemap.ServiceInfo{
		Name:       "backend-svc",
		Namespace:  "default",
		ClusterIP:  clusterIP,
		ClusterIPs: []netip.Addr{clusterIP},
		Labels:     map[string]string{"app": "backend"},
		Selector:   map[string]string{"app": "backend-pod"},
		Endpoints: []servicemap.EndpointInfo{
			{IP: netip.MustParseAddr("10.0.0.1"), Port: 80, Protocol: "TCP", PodName: "backend-pod-1"},
			{IP: netip.MustParseAddr("10.0.0.2"), Port: 80, Protocol: "TCP", PodName: "backend-pod-2"},
		},
	})
	t.Cleanup(func() {
		sm.Delete("default", "backend-svc")
	})

	// Create serviceSelector policy (deny access to backend-svc)
	policy := testServiceSelectorPolicy("deny-backend", srcPodLabels, "backend-svc", "default", "deny", []uint32{80})

	// Add policy to state
	err := s.createMatchLabelsPolicy(policy)
	require.NoError(t, err)

	// Verify policy was stored as serviceSelector policy
	policies := s.getServiceSelectorPolicies(map[string]string{"app": "client"})
	assert.Len(t, policies, 1, "should have one matching serviceSelector policy")

	// Add subject pod
	srcPod := newPodFromCluster(t, s, "testNamespace", srcPodName, "Deployment", srcPodLabels)
	t.Cleanup(func() {
		delPod(t)
	})

	// Create serviceSelector records for the pod
	records, err := s.createServiceSelectorRecords(srcPod)
	require.NoError(t, err)

	// Count record types
	dnsCount, podCount, cidrCount, _ := cntRecordsEPTypes(records)

	// Should NOT have DNS records (serviceSelector uses CIDR only)
	assert.Zero(t, dnsCount, "should not have DNS records")

	// Should have CIDR records for:
	// - ClusterIP 10.96.0.100 (port 80 only)
	// - Endpoint 10.0.0.1 (port 80 only)
	// - Endpoint 10.0.0.2 (port 80 only)
	// 3 IPs * 1 port-specific record each = 3 records
	assert.Equal(t, 3, cidrCount, "should have CIDR records for ClusterIP and endpoints (port-specific only)")

	// Should not have pod-type records (serviceSelector doesn't use pod matching)
	assert.Zero(t, podCount, "should not have pod-type records")

	// Verify all records have deny action and target port 80 (no wildcard port=0)
	for _, r := range records {
		assert.Equal(t, record.PolicyDeny, r.Action.Action, "record should have deny action")
		assert.Equal(t, uint32(80), r.Endpoint.Port, "record should target port 80, not wildcard")
	}
}

// TestServiceSelectorWithPorts verifies port-specific serviceSelector policies
func TestServiceSelectorWithPorts(t *testing.T) {
	s := NewFakePolicyState(t)

	srcPodName := "client-pod"
	srcPodLabels := "app=client"

	// Setup service in ServiceMap with multiple ports
	sm := servicemap.NewServiceMap(s)
	s.SetServiceMap(sm)
	clusterIP := netip.MustParseAddr("10.96.0.101")
	sm.AddOrUpdate(&servicemap.ServiceInfo{
		Name:       "multi-port-svc",
		Namespace:  "default",
		ClusterIP:  clusterIP,
		ClusterIPs: []netip.Addr{clusterIP},
		Endpoints: []servicemap.EndpointInfo{
			{IP: netip.MustParseAddr("10.0.1.1"), Port: 80, Protocol: "TCP", PodName: "backend-1"},
		},
	})
	t.Cleanup(func() {
		sm.Delete("default", "multi-port-svc")
	})

	// Create policy that only blocks port 443
	policy := testServiceSelectorPolicy("deny-https", srcPodLabels, "multi-port-svc", "default", "deny", []uint32{443})

	err := s.createMatchLabelsPolicy(policy)
	require.NoError(t, err)

	// Add subject pod
	srcPod := newPodFromCluster(t, s, "testNamespace", srcPodName, "Deployment", srcPodLabels)
	t.Cleanup(func() {
		delPod(t)
	})

	// Create serviceSelector records
	records, err := s.createServiceSelectorRecords(srcPod)
	require.NoError(t, err)

	// All records should target port 443 only — no wildcard port=0 records
	for _, r := range records {
		assert.Equal(t, uint32(443), r.Endpoint.Port, "all records should target port 443, not wildcard")
		assert.Equal(t, record.PolicyDeny, r.Action.Action, "port 443 records should have deny action")
	}

	// Should have exactly 2 records: ClusterIP + 1 endpoint, both port 443
	assert.Equal(t, 2, len(records), "should have 2 port-specific records (ClusterIP + endpoint)")
}

// TestServiceSelectorNoMatchingService verifies behavior when service doesn't exist in servicemap.
// No records are generated since CIDR records require the service to exist to get ClusterIP/endpoint IPs.
func TestServiceSelectorNoMatchingService(t *testing.T) {
	s := NewFakePolicyState(t)

	srcPodName := "client-pod"
	srcPodLabels := "app=client"

	// Create policy for non-existent service (not in servicemap)
	policy := testServiceSelectorPolicy("deny-nonexistent", srcPodLabels, "nonexistent-svc", "default", "deny", nil)

	err := s.createMatchLabelsPolicy(policy)
	require.NoError(t, err)

	// Add subject pod
	srcPod := newPodFromCluster(t, s, "testNamespace", srcPodName, "Deployment", srcPodLabels)
	t.Cleanup(func() {
		delPod(t)
	})

	// Create serviceSelector records - should not fail even if service doesn't exist
	records, err := s.createServiceSelectorRecords(srcPod)
	require.NoError(t, err)

	// No records should be generated since service doesn't exist in servicemap
	// (no ClusterIP or endpoint IPs to block)
	assert.Len(t, records, 0, "should have no records for non-existent service")
}

// TestServiceSelectorPodNotMatchingSubject verifies that pods not matching
// the subject selector don't get serviceSelector records
func TestServiceSelectorPodNotMatchingSubject(t *testing.T) {
	s := NewFakePolicyState(t)

	srcPodName := "other-pod"
	srcPodLabels := "app=other" // Different from policy subject

	// Setup service
	sm := servicemap.NewServiceMap(s)
	s.SetServiceMap(sm)
	sm.AddOrUpdate(&servicemap.ServiceInfo{
		Name:      "test-svc",
		Namespace: "default",
		ClusterIP: netip.MustParseAddr("10.96.0.102"),
	})
	t.Cleanup(func() {
		sm.Delete("default", "test-svc")
	})

	// Create policy that applies to "app=client" pods
	policy := testServiceSelectorPolicy("deny-test-svc", "app=client", "test-svc", "default", "deny", nil)

	err := s.createMatchLabelsPolicy(policy)
	require.NoError(t, err)

	// Add pod with different labels (app=other)
	srcPod := newPodFromCluster(t, s, "testNamespace", srcPodName, "Deployment", srcPodLabels)
	t.Cleanup(func() {
		delPod(t)
	})

	// Get matching policies - should be empty
	policies := s.getServiceSelectorPolicies(map[string]string{"app": "other"})
	assert.Len(t, policies, 0, "should have no matching policies for app=other")

	// Create serviceSelector records - should be empty
	records, err := s.createServiceSelectorRecords(srcPod)
	require.NoError(t, err)
	assert.Len(t, records, 0, "should have no records for non-matching pod")
}

// TestServiceSelectorAllowAction verifies allow rules work correctly
func TestServiceSelectorAllowAction(t *testing.T) {
	s := NewFakePolicyState(t)

	srcPodName := "client-pod"
	srcPodLabels := "app=client"

	// Setup service
	sm := servicemap.NewServiceMap(s)
	s.SetServiceMap(sm)
	sm.AddOrUpdate(&servicemap.ServiceInfo{
		Name:      "allowed-svc",
		Namespace: "default",
		ClusterIP: netip.MustParseAddr("10.96.0.103"),
		Endpoints: []servicemap.EndpointInfo{
			{IP: netip.MustParseAddr("10.0.2.1"), Port: 80, Protocol: "TCP", PodName: "backend-1"},
		},
	})
	t.Cleanup(func() {
		sm.Delete("default", "allowed-svc")
	})

	// Create allow policy (with default deny)
	policy := testServiceSelectorPolicy("allow-svc", srcPodLabels, "allowed-svc", "default", "allow", []uint32{80})

	err := s.createMatchLabelsPolicy(policy)
	require.NoError(t, err)

	// Add subject pod
	srcPod := newPodFromCluster(t, s, "testNamespace", srcPodName, "Deployment", srcPodLabels)
	t.Cleanup(func() {
		delPod(t)
	})

	records, err := s.createServiceSelectorRecords(srcPod)
	require.NoError(t, err)

	// Verify service records have allow action
	for _, r := range records {
		if r.Endpoint.EP != nil { // Skip default action record
			assert.Equal(t, record.PolicyAllow, r.Action.Action, "service records should have allow action")
		}
	}

	// Verify default action is deny
	for _, r := range records {
		if r.Endpoint.EP == nil {
			assert.Equal(t, record.PolicyDeny, r.Action.Action, "default action should be deny")
		}
	}
}

// TestServiceSelectorMultiplePolicies verifies multiple serviceSelector policies work together
func TestServiceSelectorMultiplePolicies(t *testing.T) {
	s := NewFakePolicyState(t)

	srcPodName := "client-pod"
	srcPodLabels := "app=client"

	// Setup two services
	sm := servicemap.NewServiceMap(s)
	s.SetServiceMap(sm)
	sm.AddOrUpdate(&servicemap.ServiceInfo{
		Name:      "svc-1",
		Namespace: "default",
		ClusterIP: netip.MustParseAddr("10.96.0.104"),
	})
	sm.AddOrUpdate(&servicemap.ServiceInfo{
		Name:      "svc-2",
		Namespace: "default",
		ClusterIP: netip.MustParseAddr("10.96.0.105"),
	})
	t.Cleanup(func() {
		sm.Delete("default", "svc-1")
		sm.Delete("default", "svc-2")
	})

	// Create two policies - one deny, one allow
	policy1 := testServiceSelectorPolicy("deny-svc-1", srcPodLabels, "svc-1", "default", "deny", nil)
	policy2 := testServiceSelectorPolicy("allow-svc-2", srcPodLabels, "svc-2", "default", "allow", nil)

	err := s.createMatchLabelsPolicy(policy1)
	require.NoError(t, err)
	err = s.createMatchLabelsPolicy(policy2)
	require.NoError(t, err)

	// Verify both policies stored
	policies := s.getServiceSelectorPolicies(map[string]string{"app": "client"})
	assert.Len(t, policies, 2, "should have two matching policies")

	// Add subject pod
	srcPod := newPodFromCluster(t, s, "testNamespace", srcPodName, "Deployment", srcPodLabels)
	t.Cleanup(func() {
		delPod(t)
	})

	records, err := s.createServiceSelectorRecords(srcPod)
	require.NoError(t, err)

	// Should have records from both policies
	hasSvc1Records := false
	hasSvc2Records := false
	for _, r := range records {
		if r.Endpoint.EP != nil {
			if r.Endpoint.EP.Type == tetragon.EndpointType_ENDPOINT_TYPE_CIDR {
				if r.Endpoint.EP.CIDR.String() == "10.96.0.104/32" {
					hasSvc1Records = true
				}
				if r.Endpoint.EP.CIDR.String() == "10.96.0.105/32" {
					hasSvc2Records = true
				}
			}
		}
	}
	assert.True(t, hasSvc1Records, "should have records for svc-1")
	assert.True(t, hasSvc2Records, "should have records for svc-2")
}

// TestServiceSelectorDefaultNamespace verifies CIDR records are generated for services in default namespace
func TestServiceSelectorDefaultNamespace(t *testing.T) {
	s := NewFakePolicyState(t)

	srcPodName := "client-pod"
	srcPodLabels := "app=client"

	// Setup service in default namespace
	sm := servicemap.NewServiceMap(s)
	s.SetServiceMap(sm)
	sm.AddOrUpdate(&servicemap.ServiceInfo{
		Name:      "default-ns-svc",
		Namespace: "default",
		ClusterIP: netip.MustParseAddr("10.96.0.106"),
	})
	t.Cleanup(func() {
		sm.Delete("default", "default-ns-svc")
	})

	// Create policy
	policy := testServiceSelectorPolicy("test-default-ns", srcPodLabels, "default-ns-svc", "default", "deny", nil)

	err := s.createMatchLabelsPolicy(policy)
	require.NoError(t, err)

	// Add subject pod
	srcPod := newPodFromCluster(t, s, "testNamespace", srcPodName, "Deployment", srcPodLabels)
	t.Cleanup(func() {
		delPod(t)
	})

	records, err := s.createServiceSelectorRecords(srcPod)
	require.NoError(t, err)

	// Should have CIDR records for the ClusterIP
	_, _, cidrCount, _ := cntRecordsEPTypes(records)
	assert.Greater(t, cidrCount, 0, "should have CIDR records for ClusterIP")

	// Verify the ClusterIP is in the records
	hasClusterIP := false
	for _, r := range records {
		if r.Endpoint.EP != nil && r.Endpoint.EP.CIDR.String() == "10.96.0.106/32" {
			hasClusterIP = true
			break
		}
	}
	assert.True(t, hasClusterIP, "should have CIDR record for ClusterIP 10.96.0.106")
}

// TestServiceSelectorPolicyRemoval verifies policy removal cleans up correctly
func TestServiceSelectorPolicyRemoval(t *testing.T) {
	s := NewFakePolicyState(t)

	srcPodName := "client-pod"
	srcPodLabels := "app=client"

	// Setup service
	sm := servicemap.NewServiceMap(s)
	s.SetServiceMap(sm)
	sm.AddOrUpdate(&servicemap.ServiceInfo{
		Name:      "removable-svc",
		Namespace: "default",
		ClusterIP: netip.MustParseAddr("10.96.0.107"),
	})
	t.Cleanup(func() {
		sm.Delete("default", "removable-svc")
	})

	// Create policy
	policy := testServiceSelectorPolicy("removable-policy", srcPodLabels, "removable-svc", "default", "deny", nil)

	err := s.createMatchLabelsPolicy(policy)
	require.NoError(t, err)

	// Verify policy exists
	policies := s.getServiceSelectorPolicies(map[string]string{"app": "client"})
	assert.Len(t, policies, 1)

	// Add subject pod
	srcPod := newPodFromCluster(t, s, "testNamespace", srcPodName, "Deployment", srcPodLabels)

	// Create records
	records, err := s.createServiceSelectorRecords(srcPod)
	require.NoError(t, err)
	assert.Greater(t, len(records), 0)

	// Remove policy
	err = s.RemovePolicy(policy)
	require.NoError(t, err)

	// Verify policy removed from serviceSelector list
	policies = s.getServiceSelectorPolicies(map[string]string{"app": "client"})
	assert.Len(t, policies, 0, "should have no policies after removal")

	// Cleanup
	delPod(t)
}

// TestServiceSelectorMultiPortNoWildcard is a regression test for issue #8050.
// When a serviceSelector policy specifies multiple ports, only port-specific CIDR
// records should be created — NOT wildcard port=0 records. A wildcard record would
// cause the BPF fallback lookup to match ALL ports, bypassing the port restriction.
// This test uses multiple ports to differentiate from TestServiceSelectorRecordGeneration.
func TestServiceSelectorMultiPortNoWildcard(t *testing.T) {
	s := NewFakePolicyState(t)

	srcPodName := "client-pod"
	srcPodLabels := "app=client"

	// Setup service with endpoints
	sm := servicemap.NewServiceMap(s)
	s.SetServiceMap(sm)
	clusterIP := netip.MustParseAddr("10.96.0.200")
	sm.AddOrUpdate(&servicemap.ServiceInfo{
		Name:       "server-svc",
		Namespace:  "ns-a",
		ClusterIP:  clusterIP,
		ClusterIPs: []netip.Addr{clusterIP},
		Endpoints: []servicemap.EndpointInfo{
			{IP: netip.MustParseAddr("10.0.5.1"), Port: 80, Protocol: "TCP", PodName: "server-a-1"},
		},
	})

	// Create deny policy targeting ports 80 AND 443 (multi-port case)
	policy := testServiceSelectorPolicy("deny-svc-multi-port", srcPodLabels, "server-svc", "ns-a", "deny", []uint32{80, 443})

	err := s.createMatchLabelsPolicy(policy)
	require.NoError(t, err)

	// Add subject pod
	srcPod := newPodFromCluster(t, s, "testNamespace", srcPodName, "Deployment", srcPodLabels)

	records, err := s.createServiceSelectorRecords(srcPod)
	require.NoError(t, err)

	// Verify NO wildcard (port=0) records exist — this was the bug
	for _, r := range records {
		assert.NotEqual(t, uint32(0), r.Endpoint.Port,
			"port-specific policy must NOT generate wildcard port=0 records (issue #8050)")
	}

	// Count records by port
	portCounts := make(map[uint32]int)
	for _, r := range records {
		portCounts[r.Endpoint.Port]++
	}

	// 2 IPs (ClusterIP + 1 endpoint) × 2 ports (80, 443) = 4 records
	assert.Equal(t, 4, len(records), "should have 4 port-specific records")
	assert.Equal(t, 2, portCounts[80], "should have 2 records for port 80 (ClusterIP + endpoint)")
	assert.Equal(t, 2, portCounts[443], "should have 2 records for port 443 (ClusterIP + endpoint)")
	assert.Equal(t, 0, portCounts[0], "should have no wildcard port=0 records")
}

// TestServiceSelectorWildcardWhenNoPorts verifies that when no ports are specified,
// wildcard (port=0) records are correctly generated, applying the policy to all ports.
func TestServiceSelectorWildcardWhenNoPorts(t *testing.T) {
	s := NewFakePolicyState(t)

	srcPodName := "client-pod"
	srcPodLabels := "app=client"

	sm := servicemap.NewServiceMap(s)
	s.SetServiceMap(sm)
	clusterIP := netip.MustParseAddr("10.96.0.201")
	sm.AddOrUpdate(&servicemap.ServiceInfo{
		Name:       "wildcard-svc",
		Namespace:  "default",
		ClusterIP:  clusterIP,
		ClusterIPs: []netip.Addr{clusterIP},
		Endpoints: []servicemap.EndpointInfo{
			{IP: netip.MustParseAddr("10.0.6.1"), Port: 80, Protocol: "TCP", PodName: "backend-1"},
		},
	})

	// Create deny policy with NO port restriction — should block all ports
	policy := testServiceSelectorPolicy("deny-all-ports", srcPodLabels, "wildcard-svc", "default", "deny", nil)

	err := s.createMatchLabelsPolicy(policy)
	require.NoError(t, err)

	srcPod := newPodFromCluster(t, s, "testNamespace", srcPodName, "Deployment", srcPodLabels)

	records, err := s.createServiceSelectorRecords(srcPod)
	require.NoError(t, err)

	// All records should be wildcard (port=0)
	for _, r := range records {
		assert.Equal(t, uint32(0), r.Endpoint.Port,
			"policy without ports should generate wildcard port=0 records")
	}

	// Should have 2 records: ClusterIP + 1 endpoint
	assert.Equal(t, 2, len(records), "should have 2 wildcard records")
}

// TestGenerateEndpointCIDRRecordsPortSpecific verifies that generateEndpointCIDRRecords
// (used by HandleEndpointChange for delta updates) respects port specifications.
// This is the function called in the endpoint add/remove delta path.
func TestGenerateEndpointCIDRRecordsPortSpecific(t *testing.T) {
	policyUID := types.TetragonPolicyUniqueID{PolicyName: "test-policy", RuleName: "rule1"}
	src := &types.ProcessTreeKey{WLID: 42}
	ip := netip.MustParseAddr("10.0.10.1")
	action := &record.DatapathAction{Action: record.PolicyDeny}

	t.Run("with_ports", func(t *testing.T) {
		records := generateEndpointCIDRRecords(policyUID, src, ip, []uint32{80, 443}, action)

		// Should have exactly 2 records (one per port), no wildcard
		assert.Equal(t, 2, len(records), "should have 2 port-specific records")
		portSet := make(map[uint32]bool)
		for _, r := range records {
			portSet[r.Endpoint.Port] = true
			assert.NotEqual(t, uint32(0), r.Endpoint.Port,
				"should not have wildcard port=0 in port-specific mode")
		}
		assert.True(t, portSet[80], "should have port 80 record")
		assert.True(t, portSet[443], "should have port 443 record")
	})

	t.Run("without_ports", func(t *testing.T) {
		records := generateEndpointCIDRRecords(policyUID, src, ip, nil, action)

		// Should have exactly 1 wildcard record
		assert.Equal(t, 1, len(records), "should have 1 wildcard record")
		assert.Equal(t, uint32(0), records[0].Endpoint.Port, "should be wildcard port=0")
	})

	t.Run("ipv6", func(t *testing.T) {
		ipv6 := netip.MustParseAddr("fd00::1")
		records := generateEndpointCIDRRecords(policyUID, src, ipv6, []uint32{443}, action)

		assert.Equal(t, 1, len(records), "should have 1 port-specific record")
		assert.Equal(t, uint32(443), records[0].Endpoint.Port, "should target port 443")
		assert.Equal(t, "fd00::1/128", records[0].Endpoint.EP.CIDR.String(), "should be /128 prefix for IPv6")
	})
}

// TestServiceSelectorWithNamespaceSelector verifies that serviceSelector policies
// with a namespaceSelector are correctly matched against pods. The namespaceSelector
// is encoded as _tnp_ prefixed labels in the policy subject. The serviceSelector
// code must augment pod labels with namespace labels before matching.
func TestServiceSelectorWithNamespaceSelector(t *testing.T) {
	s := NewFakePolicyState(t)

	srcPodName := "client-pod"
	srcPodLabels := "app=client"

	// Setup service
	sm := servicemap.NewServiceMap(s)
	s.SetServiceMap(sm)
	clusterIP := netip.MustParseAddr("10.96.0.210")
	sm.AddOrUpdate(&servicemap.ServiceInfo{
		Name:       "target-svc",
		Namespace:  "default",
		ClusterIP:  clusterIP,
		ClusterIPs: []netip.Addr{clusterIP},
		Endpoints: []servicemap.EndpointInfo{
			{IP: netip.MustParseAddr("10.0.8.1"), Port: 80, Protocol: "TCP", PodName: "target-1"},
		},
	})

	// Create policy with namespaceSelector — the _tnp_ prefix is how xlate.go
	// encodes namespace labels into the subject. The fake k8sReader returns
	// kubernetes.io/metadata.name=<namespace> for any namespace lookup.
	// Pod is in "testNamespace", so namespace label is _tnp_kubernetes.io/metadata.name=testNamespace
	policy := testServiceSelectorPolicy(
		"deny-with-ns",
		"app=client,_tnp_kubernetes.io/metadata.name=testNamespace",
		"target-svc", "default", "deny", []uint32{80},
	)

	err := s.createMatchLabelsPolicy(policy)
	require.NoError(t, err)

	// Add subject pod in "testNamespace" — pod labels are {app:client} only
	srcPod := newPodFromCluster(t, s, "testNamespace", srcPodName, "Deployment", srcPodLabels)

	// createServiceSelectorRecords should match despite namespace label in policy,
	// because the function now augments pod labels with namespace labels.
	records, err := s.createServiceSelectorRecords(srcPod)
	require.NoError(t, err)

	// Should have 2 records: ClusterIP + 1 endpoint, port 80
	assert.Equal(t, 2, len(records), "should have 2 records (ClusterIP + endpoint)")
	for _, r := range records {
		assert.Equal(t, uint32(80), r.Endpoint.Port, "all records should target port 80")
	}
}

// TestServiceSelectorNamespaceMismatch verifies that pods in a non-matching namespace
// are NOT matched by a policy with a namespaceSelector.
func TestServiceSelectorNamespaceMismatch(t *testing.T) {
	s := NewFakePolicyState(t)

	srcPodName := "client-pod"
	srcPodLabels := "app=client"

	// Setup service
	sm := servicemap.NewServiceMap(s)
	s.SetServiceMap(sm)
	sm.AddOrUpdate(&servicemap.ServiceInfo{
		Name:      "target-svc",
		Namespace: "default",
		ClusterIP: netip.MustParseAddr("10.96.0.211"),
	})

	// Policy requires namespace "production", but pod is in "testNamespace"
	policy := testServiceSelectorPolicy(
		"deny-wrong-ns",
		"app=client,_tnp_kubernetes.io/metadata.name=production",
		"target-svc", "default", "deny", nil,
	)

	err := s.createMatchLabelsPolicy(policy)
	require.NoError(t, err)

	srcPod := newPodFromCluster(t, s, "testNamespace", srcPodName, "Deployment", srcPodLabels)

	// Should NOT match — pod is in "testNamespace", policy requires "production"
	records, err := s.createServiceSelectorRecords(srcPod)
	require.NoError(t, err)
	assert.Len(t, records, 0, "should have no records — namespace mismatch")
}

// TestServiceSelectorNilLabelsMatchesNamespaceOnly verifies that a pod with
// nil metadata.labels still matches a serviceSelector policy whose subject is
// satisfied entirely by namespaceSelector labels. The prior implementation
// returned early on nil labels, silently skipping namespace-only matches.
func TestServiceSelectorNilLabelsMatchesNamespaceOnly(t *testing.T) {
	s := NewFakePolicyState(t)

	srcPodName := "client-pod"
	srcNamespace := "testNamespace"

	sm := servicemap.NewServiceMap(s)
	s.SetServiceMap(sm)
	clusterIP := netip.MustParseAddr("10.96.0.220")
	sm.AddOrUpdate(&servicemap.ServiceInfo{
		Name:       "ns-only-svc",
		Namespace:  "default",
		ClusterIP:  clusterIP,
		ClusterIPs: []netip.Addr{clusterIP},
	})

	// Policy subject is satisfied by namespace label alone — no pod-label requirement.
	policy := testServiceSelectorPolicy(
		"deny-ns-only",
		"_tnp_kubernetes.io/metadata.name=testNamespace",
		"ns-only-svc", "default", "deny", []uint32{80},
	)
	err := s.createMatchLabelsPolicy(policy)
	require.NoError(t, err)

	// Build a pod with Labels:nil directly (newPod always creates a non-nil map).
	registerWorkloadID(t, s, srcNamespace, srcPodName, "Deployment")
	srcPod := &v1alpha1.PodInfo{
		WorkloadType:   metav1.TypeMeta{Kind: "Deployment"},
		WorkloadObject: v1alpha1.WorkloadObjectMeta{Name: srcPodName, Namespace: srcNamespace},
		Name:           srcPodName,
		Namespace:      srcNamespace,
		UID:            k8stype.UID(srcPodName),
		Labels:         nil,
	}

	records, err := s.createServiceSelectorRecords(srcPod)
	require.NoError(t, err)
	assert.Equal(t, 1, len(records), "nil-label pod must still match namespace-only policy")
	assert.Equal(t, uint32(80), records[0].Endpoint.Port, "record should target port 80")
}

// TestServiceSelectorTnpPodLabelSpoof verifies that a pod cannot satisfy a
// namespaceSelector by setting _tnp_-prefixed labels on itself.
func TestServiceSelectorTnpPodLabelSpoof(t *testing.T) {
	s := NewFakePolicyState(t)

	srcPodName := "malicious-pod"
	// Pod tries to self-label into the "production" namespace.
	srcPodLabels := "app=client,_tnp_kubernetes.io/metadata.name=production"

	sm := servicemap.NewServiceMap(s)
	s.SetServiceMap(sm)
	sm.AddOrUpdate(&servicemap.ServiceInfo{
		Name:      "prod-svc",
		Namespace: "default",
		ClusterIP: netip.MustParseAddr("10.96.0.221"),
	})

	// Policy subject requires production namespace.
	policy := testServiceSelectorPolicy(
		"allow-prod-only",
		"app=client,_tnp_kubernetes.io/metadata.name=production",
		"prod-svc", "default", "allow", nil,
	)
	err := s.createMatchLabelsPolicy(policy)
	require.NoError(t, err)

	// Pod lives in testNamespace, not production. Self-supplied _tnp_ must be ignored.
	srcPod := newPodFromCluster(t, s, "testNamespace", srcPodName, "Deployment", srcPodLabels)

	records, err := s.createServiceSelectorRecords(srcPod)
	require.NoError(t, err)
	assert.Len(t, records, 0, "pod must not spoof namespaceSelector via _tnp_ self-labels")
}
