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

package netpolstate

import (
	"net/netip"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	s := NewPolicyState()
	SetRealizedState(s)

	srcId := nextId()
	srcPodName := "client-pod"
	srcPodLabels := "app=client"

	// Setup service in ServiceMap
	sm := servicemap.NewServiceMap()
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
	err := s.CreateMatchLabelsPolicy(policy)
	require.NoError(t, err)

	// Verify policy was stored as serviceSelector policy
	policies := s.GetServiceSelectorPolicies(map[string]string{"app": "client"})
	assert.Len(t, policies, 1, "should have one matching serviceSelector policy")

	// Add subject pod
	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "svc-sel-test-1", "testNamespace", srcPodName, "Deployment", srcPodLabels)
	t.Cleanup(func() {
		delPod(t, srcId)
	})

	// Create serviceSelector records for the pod
	records, err := s.CreateServiceSelectorRecords(srcPod)
	require.NoError(t, err)

	// Count record types
	dnsCount, podCount, cidrCount, _ := cntRecordsEPTypes(records)

	// Should NOT have DNS records (serviceSelector uses CIDR only)
	assert.Zero(t, dnsCount, "should not have DNS records")

	// Should have CIDR records for:
	// - ClusterIP 10.96.0.100 (with port 80 + wildcard)
	// - Endpoint 10.0.0.1 (with port 80 + wildcard)
	// - Endpoint 10.0.0.2 (with port 80 + wildcard)
	// CIDR records should be >= 6 (3 IPs * 2 port records each)
	assert.GreaterOrEqual(t, cidrCount, 6, "should have CIDR records for ClusterIP and endpoints")

	// Should not have pod-type records (serviceSelector doesn't use pod matching)
	assert.Zero(t, podCount, "should not have pod-type records")

	// Note: Default action records are NOT generated by serviceSelector record generation.
	// They are handled separately by the policy processing layer.
	// So we don't check nilCount here.

	// Verify all records have deny action (since policy action is deny)
	for _, r := range records {
		assert.Equal(t, record.PolicyDeny, r.Action.Action, "record should have deny action")
	}
}

// TestServiceSelectorWithPorts verifies port-specific serviceSelector policies
func TestServiceSelectorWithPorts(t *testing.T) {
	s := NewPolicyState()
	SetRealizedState(s)

	srcId := nextId()
	srcPodName := "client-pod"
	srcPodLabels := "app=client"

	// Setup service in ServiceMap with multiple ports
	sm := servicemap.NewServiceMap()
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

	err := s.CreateMatchLabelsPolicy(policy)
	require.NoError(t, err)

	// Add subject pod
	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "svc-sel-port-1", "testNamespace", srcPodName, "Deployment", srcPodLabels)
	t.Cleanup(func() {
		delPod(t, srcId)
	})

	// Create serviceSelector records
	records, err := s.CreateServiceSelectorRecords(srcPod)
	require.NoError(t, err)

	// Count port 443 records
	port443Count := 0
	for _, r := range records {
		if r.Endpoint.Port == 443 {
			port443Count++
		}
	}

	// Should have records specifically for port 443
	assert.Greater(t, port443Count, 0, "should have records for port 443")

	// Verify port 443 records have deny action
	for _, r := range records {
		if r.Endpoint.Port == 443 {
			assert.Equal(t, record.PolicyDeny, r.Action.Action, "port 443 records should have deny action")
		}
	}
}

// TestServiceSelectorNoMatchingService verifies behavior when service doesn't exist in servicemap.
// No records are generated since CIDR records require the service to exist to get ClusterIP/endpoint IPs.
func TestServiceSelectorNoMatchingService(t *testing.T) {
	s := NewPolicyState()
	SetRealizedState(s)

	srcId := nextId()
	srcPodName := "client-pod"
	srcPodLabels := "app=client"

	// Create policy for non-existent service (not in servicemap)
	policy := testServiceSelectorPolicy("deny-nonexistent", srcPodLabels, "nonexistent-svc", "default", "deny", nil)

	err := s.CreateMatchLabelsPolicy(policy)
	require.NoError(t, err)

	// Add subject pod
	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "svc-sel-noexist-1", "testNamespace", srcPodName, "Deployment", srcPodLabels)
	t.Cleanup(func() {
		delPod(t, srcId)
	})

	// Create serviceSelector records - should not fail even if service doesn't exist
	records, err := s.CreateServiceSelectorRecords(srcPod)
	require.NoError(t, err)

	// No records should be generated since service doesn't exist in servicemap
	// (no ClusterIP or endpoint IPs to block)
	assert.Len(t, records, 0, "should have no records for non-existent service")
}

// TestServiceSelectorPodNotMatchingSubject verifies that pods not matching
// the subject selector don't get serviceSelector records
func TestServiceSelectorPodNotMatchingSubject(t *testing.T) {
	s := NewPolicyState()
	SetRealizedState(s)

	srcId := nextId()
	srcPodName := "other-pod"
	srcPodLabels := "app=other" // Different from policy subject

	// Setup service
	sm := servicemap.NewServiceMap()
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

	err := s.CreateMatchLabelsPolicy(policy)
	require.NoError(t, err)

	// Add pod with different labels (app=other)
	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "svc-sel-nomatch-1", "testNamespace", srcPodName, "Deployment", srcPodLabels)
	t.Cleanup(func() {
		delPod(t, srcId)
	})

	// Get matching policies - should be empty
	policies := s.GetServiceSelectorPolicies(map[string]string{"app": "other"})
	assert.Len(t, policies, 0, "should have no matching policies for app=other")

	// Create serviceSelector records - should be empty
	records, err := s.CreateServiceSelectorRecords(srcPod)
	require.NoError(t, err)
	assert.Len(t, records, 0, "should have no records for non-matching pod")
}

// TestServiceSelectorAllowAction verifies allow rules work correctly
func TestServiceSelectorAllowAction(t *testing.T) {
	s := NewPolicyState()
	SetRealizedState(s)

	srcId := nextId()
	srcPodName := "client-pod"
	srcPodLabels := "app=client"

	// Setup service
	sm := servicemap.NewServiceMap()
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

	err := s.CreateMatchLabelsPolicy(policy)
	require.NoError(t, err)

	// Add subject pod
	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "svc-sel-allow-1", "testNamespace", srcPodName, "Deployment", srcPodLabels)
	t.Cleanup(func() {
		delPod(t, srcId)
	})

	records, err := s.CreateServiceSelectorRecords(srcPod)
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
	s := NewPolicyState()
	SetRealizedState(s)

	srcId := nextId()
	srcPodName := "client-pod"
	srcPodLabels := "app=client"

	// Setup two services
	sm := servicemap.NewServiceMap()
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

	err := s.CreateMatchLabelsPolicy(policy1)
	require.NoError(t, err)
	err = s.CreateMatchLabelsPolicy(policy2)
	require.NoError(t, err)

	// Verify both policies stored
	policies := s.GetServiceSelectorPolicies(map[string]string{"app": "client"})
	assert.Len(t, policies, 2, "should have two matching policies")

	// Add subject pod
	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "svc-sel-multi-1", "testNamespace", srcPodName, "Deployment", srcPodLabels)
	t.Cleanup(func() {
		delPod(t, srcId)
	})

	records, err := s.CreateServiceSelectorRecords(srcPod)
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
	s := NewPolicyState()
	SetRealizedState(s)

	srcId := nextId()
	srcPodName := "client-pod"
	srcPodLabels := "app=client"

	// Setup service in default namespace
	sm := servicemap.NewServiceMap()
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

	err := s.CreateMatchLabelsPolicy(policy)
	require.NoError(t, err)

	// Add subject pod
	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "svc-sel-default-ns-1", "testNamespace", srcPodName, "Deployment", srcPodLabels)
	t.Cleanup(func() {
		delPod(t, srcId)
	})

	records, err := s.CreateServiceSelectorRecords(srcPod)
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
	s := NewPolicyState()
	SetRealizedState(s)

	srcId := nextId()
	srcPodName := "client-pod"
	srcPodLabels := "app=client"

	// Setup service
	sm := servicemap.NewServiceMap()
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

	err := s.CreateMatchLabelsPolicy(policy)
	require.NoError(t, err)

	// Verify policy exists
	policies := s.GetServiceSelectorPolicies(map[string]string{"app": "client"})
	assert.Len(t, policies, 1)

	// Add subject pod
	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "svc-sel-remove-1", "testNamespace", srcPodName, "Deployment", srcPodLabels)

	// Create records
	records, err := s.CreateServiceSelectorRecords(srcPod)
	require.NoError(t, err)
	assert.Greater(t, len(records), 0)

	// Remove policy
	err = s.RemovePolicy(policy)
	require.NoError(t, err)

	// Verify policy removed from serviceSelector list
	policies = s.GetServiceSelectorPolicies(map[string]string{"app": "client"})
	assert.Len(t, policies, 0, "should have no policies after removal")

	// Cleanup
	delPod(t, srcId)
}
