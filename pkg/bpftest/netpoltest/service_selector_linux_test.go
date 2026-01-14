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

// Package netpoltest provides BPF integration tests for TetragonNetworkPolicy.
// This file tests serviceSelector functionality, which blocks access to Service
// ClusterIPs and endpoint IPs using CIDR records.
//
// NOTE: These tests use Port=0 (wildcard) matching, following the recordtest patterns.
// Port-specific matching is not tested here as it requires additional implementation.
package netpoltest

import (
	"context"
	"net/netip"
	"os/exec"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/bpftest"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/datapath"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/netpol/servicemap"
	"github.com/isovalent/hubble-fgs/pkg/testutils"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

var (
	prog datapath.Interface = &datapath.BpfProgrammer{}
)

// wildcardSrc matches all source processes/pods (NSID=0 means host)
var wildcardSrc = &types.ProcessTreeKey{
	NSID:  uint64(policyfilter.StateID(0)),
	Depth: 0,
	Self:  0,
	Path:  [8]uint64{0, 0, 0, 0, 0, 0, 0, 0},
}

// Test helper to create a CIDR deny record (simulates ClusterIP/endpoint blocking)
func makeCIDRDenyRecord(policyName, cidr string) *record.DatapathRecord {
	return &record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: policyName,
			RuleName:   "serviceSelector-cidr",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				CIDR: netip.MustParsePrefix(cidr),
			},
			Port: 0, // Wildcard - matches all ports
		},
		Action: &record.DatapathAction{
			Action: record.PolicyDeny,
		},
	}
}

// Test helper to create a CIDR allow record
func makeCIDRAllowRecord(policyName, cidr string) *record.DatapathRecord {
	return &record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: policyName,
			RuleName:   "serviceSelector-cidr",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				CIDR: netip.MustParsePrefix(cidr),
			},
			Port: 0, // Wildcard - matches all ports
		},
		Action: &record.DatapathAction{
			Action: record.PolicyAllow,
		},
	}
}

// Test helper to create a default action record
func makeDefaultRecord(policyName string, allow bool) *record.DatapathRecord {
	action := record.PolicyDeny
	if allow {
		action = record.PolicyAllow
	}
	return &record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: policyName,
			RuleName:   "default",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP:   nil, // nil EP means default action
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: action,
		},
	}
}

// TestServiceSelectorBlocking tests CIDR-based deny/allow rules for serviceSelector.
//
// These tests verify that serviceSelector policies correctly block access to
// Service ClusterIPs and endpoint IPs using CIDR records.
func TestServiceSelectorBlocking(t *testing.T) {
	if !utils.SupportProcessTree() {
		t.Skip()
	}

	ctx, cancel := context.WithTimeout(context.Background(), sensors.ConfigDefaults.CmdWaitTime)
	defer cancel()

	// Start HTTP servers (following recordtest pattern - start BEFORE tetragon model)
	testutils.StartSimpleHTTPServer(t, ":8080")
	testutils.StartSimpleHTTPServer(t, ":8081")

	bpftest.StartMinimalTetragonModel(ctx, t)

	// Common curl args for testing connectivity (use absolute path for sudo)
	curlCmd := "/usr/bin/curl"
	curlArgs := []string{"--max-time", "0.5", "--ipv4", "127.0.0.1:8080"}

	// Verify connectivity before any policy
	err := exec.Command(curlCmd, curlArgs...).Run()
	require.NoError(t, err, "curl should work before any policy")

	// Subtest: Basic CIDR deny (simulates blocking ClusterIP)
	t.Run("DenyClusterIP", func(t *testing.T) {
		records := []*record.DatapathRecord{
			makeCIDRDenyRecord("deny-clusterip", "127.0.0.1/32"),
		}
		err := prog.AddRecords(records, true)
		require.NoError(t, err, "failed to add records")

		// Should be blocked
		err = exec.Command(curlCmd, curlArgs...).Run()
		require.Error(t, err, "curl should fail after CIDR deny (simulates ClusterIP block)")

		// Cleanup
		err = prog.RemoveRecords(records)
		require.NoError(t, err)

		// Verify clean state
		err = exec.Command(curlCmd, curlArgs...).Run()
		require.NoError(t, err, "curl should work after records removed")
	})

	// Subtest: CIDR deny for subnet (simulates blocking multiple endpoints)
	t.Run("DenySubnet", func(t *testing.T) {
		records := []*record.DatapathRecord{
			makeCIDRDenyRecord("deny-subnet", "127.0.0.0/24"),
		}
		err := prog.AddRecords(records, true)
		require.NoError(t, err, "failed to add records")

		// Should be blocked (127.0.0.1 is in 127.0.0.0/24)
		err = exec.Command(curlCmd, curlArgs...).Run()
		require.Error(t, err, "curl should fail after subnet deny")

		// Cleanup
		err = prog.RemoveRecords(records)
		require.NoError(t, err)

		// Verify clean state
		err = exec.Command(curlCmd, curlArgs...).Run()
		require.NoError(t, err, "curl should work after records removed")
	})

	// Subtest: CIDR allow (verify allow doesn't block)
	t.Run("AllowClusterIP", func(t *testing.T) {
		records := []*record.DatapathRecord{
			makeCIDRAllowRecord("allow-clusterip", "127.0.0.1/32"),
		}
		err := prog.AddRecords(records, true)
		require.NoError(t, err, "failed to add records")

		// Should NOT be blocked (allow rule)
		err = exec.Command(curlCmd, curlArgs...).Run()
		require.NoError(t, err, "curl should succeed with allow rule")

		// Cleanup
		err = prog.RemoveRecords(records)
		require.NoError(t, err)
	})

	// Subtest: Default deny blocks traffic
	t.Run("DefaultDeny", func(t *testing.T) {
		records := []*record.DatapathRecord{
			makeDefaultRecord("default-deny-policy", false),
		}
		err := prog.AddRecords(records, true)
		require.NoError(t, err, "failed to add records")

		// Should be blocked by default deny
		err = exec.Command(curlCmd, curlArgs...).Run()
		require.Error(t, err, "curl should fail with default deny")

		// Cleanup
		err = prog.RemoveRecords(records)
		require.NoError(t, err)

		// Verify clean state
		err = exec.Command(curlCmd, curlArgs...).Run()
		require.NoError(t, err, "curl should work after records removed")
	})

	// Subtest: Allow rule with default deny
	// This simulates: "allow access to this service, deny everything else"
	t.Run("AllowWithDefaultDeny", func(t *testing.T) {
		records := []*record.DatapathRecord{
			makeCIDRAllowRecord("allow-default-deny-policy", "127.0.0.1/32"),
			makeDefaultRecord("allow-default-deny-policy", false),
		}
		err := prog.AddRecords(records, true)
		require.NoError(t, err, "failed to add records")

		// Allowed IP should work
		err = exec.Command(curlCmd, curlArgs...).Run()
		require.NoError(t, err, "curl to allowed IP should succeed")

		// Cleanup
		err = prog.RemoveRecords(records)
		require.NoError(t, err)
	})

	// Subtest: Multiple CIDR records (simulates ClusterIP + endpoint blocking)
	t.Run("MultipleCIDRDeny", func(t *testing.T) {
		// Block 127.0.0.1 (simulates ClusterIP) and 127.0.0.2 (simulates endpoint)
		records := []*record.DatapathRecord{
			makeCIDRDenyRecord("deny-multi-1", "127.0.0.1/32"),
			makeCIDRDenyRecord("deny-multi-2", "127.0.0.2/32"),
		}
		err := prog.AddRecords(records, true)
		require.NoError(t, err, "failed to add records")

		// 127.0.0.1 should be blocked
		err = exec.Command(curlCmd, curlArgs...).Run()
		require.Error(t, err, "curl to 127.0.0.1 should fail")

		// Cleanup
		err = prog.RemoveRecords(records)
		require.NoError(t, err)

		// Verify clean state
		err = exec.Command(curlCmd, curlArgs...).Run()
		require.NoError(t, err, "curl should work after records removed")
	})

	// Subtest: Deny and allow different IPs
	// This simulates: "deny service A, allow service B"
	t.Run("DenyOneAllowAnother", func(t *testing.T) {
		// Deny 127.0.0.2 but allow 127.0.0.1
		records := []*record.DatapathRecord{
			makeCIDRDenyRecord("deny-other", "127.0.0.2/32"),
			makeCIDRAllowRecord("allow-this", "127.0.0.1/32"),
		}
		err := prog.AddRecords(records, true)
		require.NoError(t, err, "failed to add records")

		// 127.0.0.1 should work (explicit allow)
		err = exec.Command(curlCmd, curlArgs...).Run()
		require.NoError(t, err, "curl to 127.0.0.1 should succeed (allow rule)")

		// Cleanup
		err = prog.RemoveRecords(records)
		require.NoError(t, err)
	})

	// Subtest: ServiceMap integration test
	// This tests the full flow: servicemap + CIDR blocking
	t.Run("WithServiceMap", func(t *testing.T) {
		// Populate servicemap (simulates K8s service tracking)
		sm := servicemap.NewServiceMap()
		clusterIP := netip.MustParseAddr("127.0.0.1")
		sm.AddOrUpdate(&servicemap.ServiceInfo{
			Name:      "test-svc",
			Namespace: "default",
			ClusterIP: clusterIP,
			Endpoints: []servicemap.EndpointInfo{
				{IP: clusterIP, Port: 8080, Protocol: "TCP", PodName: "backend-1"},
			},
		})
		defer sm.Delete("default", "test-svc")

		// Verify the service is tracked
		svc := sm.GetByClusterIP(clusterIP)
		require.NotNil(t, svc, "service should be tracked in servicemap")
		require.Equal(t, "test-svc", svc.Name)

		// Block the service ClusterIP
		records := []*record.DatapathRecord{
			makeCIDRDenyRecord("block-test-svc", "127.0.0.1/32"),
		}
		err := prog.AddRecords(records, true)
		require.NoError(t, err, "failed to add records")

		// Service should be blocked
		err = exec.Command(curlCmd, curlArgs...).Run()
		require.Error(t, err, "curl to service ClusterIP should fail")

		// Cleanup
		err = prog.RemoveRecords(records)
		require.NoError(t, err)

		// Verify clean state
		err = exec.Command(curlCmd, curlArgs...).Run()
		require.NoError(t, err, "curl should work after records removed")
	})
}
