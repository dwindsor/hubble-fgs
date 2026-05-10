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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

func testMatchSrcLabelsPolicy(name, labels string) *types.TetragonNetworkPolicy {
	ml := make(map[string]string)
	for l := range strings.SplitSeq(labels, ",") {
		kv := strings.Split(l, "=")
		ml[kv[0]] = kv[1]
	}

	s := types.TetragonNetworkSubject{
		Labels: types.TetragonNetworkLabels{Equal: ml},
	}
	f := &types.TetragonNetworkFQDN{
		Names: []string{"test.io", "test.com"},
	}
	d := types.TetragonNetworkDestination{
		FQDN: f,
	}
	quota := &types.TetragonQuotaAction{
		Quota: "1",
		Reset: "120s",
	}
	a := types.TetragonNetworkAction{
		QuotaAction: quota,
	}
	policy := &types.TetragonNetworkPolicy{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: name,
			RuleName:   "rule1",
		},
		Subject:     s,
		Destination: d,
		Action:      a,
	}
	return policy
}

func testMatchDstLabelsPolicy(name, src, dst string) *types.TetragonNetworkPolicy {
	p := testMatchSrcLabelsPolicy(name, src)
	ml := make(map[string]string)
	for l := range strings.SplitSeq(dst, ",") {
		kv := strings.Split(l, "=")
		ml[kv[0]] = kv[1]
	}
	p.Destination.Labels.Equal = ml
	return p
}

func testMatchDstLabelsDenyPolicy(name, src, dst, action string) *types.TetragonNetworkPolicy {
	denyAction := &types.TetragonEnforceAction{
		Deny:  true,
		Allow: false,
	}
	allowAction := &types.TetragonEnforceAction{
		Deny:  false,
		Allow: true,
	}

	netpol := testMatchDstLabelsPolicy(name, src, dst)
	if strings.Compare(action, "deny") == 0 {
		netpol.Action.EnforceAction = denyAction
		netpol.Default.EnforceAction = allowAction
	} else {
		netpol.Action.EnforceAction = allowAction
		netpol.Default.EnforceAction = denyAction
	}

	netpol.Action.QuotaAction = nil
	netpol.Default.QuotaAction = nil

	return netpol
}

func testMatchDstProcessLabelsDenyPolicy(name, src, dst, action string) *types.TetragonNetworkPolicy {
	process := []string{"/usr/bin/curl", "/usr/sbin/curl"}
	netpol := testMatchDstLabelsDenyPolicy(name, src, dst, action)
	netpol.Subject.InProcessName = process

	return netpol
}

func testMatchPortDstProcessLabelsDenyPolicy(name, src, dst, action string) *types.TetragonNetworkPolicy {
	process := []string{"/usr/bin/curl", "/usr/sbin/curl"}
	ports := []uint32{80, 81}
	netpol := testMatchDstLabelsDenyPolicy(name, src, dst, action)
	netpol.Subject.InProcessName = process
	netpol.Destination.Ports = ports

	return netpol
}

func testMatchPortCIDRDstProcessLabelsDenyPolicy(name, src, dst, action, cidr string) *types.TetragonNetworkPolicy {
	netpol := testMatchPortDstProcessLabelsDenyPolicy(name, src, dst, action)
	netpol.Destination.CIDR = netip.MustParsePrefix(cidr)
	return netpol
}

func TestCreateSrcMatchLabelsPolicy(t *testing.T) {
	s := NewFakePolicyState(t)
	name := "testName"

	policy := testMatchSrcLabelsPolicy(name, "A=a,B=b")
	s.createSrcMatchLabelsPolicy(policy)

	assert.Equal(t, 1, len(s.src))

	err := s.RemovePolicy(policy)
	require.NoError(t, err)

	assert.Equal(t, 0, len(s.src))
}

func TestCreateDstMatchLabelsPolicy(t *testing.T) {
	s := NewFakePolicyState(t)
	name := "testName"

	policy := testMatchDstLabelsPolicy(name, "A=a,B=b", "D1=d1,D2=d2")
	s.createDstMatchLabelsPolicy(policy)

	assert.Equal(t, 1, len(s.dst))

	err := s.RemovePolicy(policy)
	require.NoError(t, err)

	assert.Equal(t, 0, len(s.dst))
}

func TestCreateSrcKey(t *testing.T) {
	s := NewFakePolicyState(t)

	ml := make(map[string]string)
	ml["A"] = "a"
	ml["B"] = "b"

	wl := types.TetragonWorkloadNetworkSubject{
		Namespace: "testNamespace",
		Name:      "testName",
		Kind:      "testKind",
	}

	subject := types.TetragonNetworkSubject{
		Labels:   types.TetragonNetworkLabels{Equal: ml},
		Workload: wl,
	}

	labels := make(map[string]string)
	labels["A"] = "a"
	labels["B"] = "b"

	mlDst := types.TetragonNetworkLabels{
		Equal: labels,
	}

	dest := types.TetragonNetworkDestination{
		Labels: mlDst,
	}

	enforce := &types.TetragonEnforceAction{
		Deny: true,
	}

	action := types.TetragonNetworkAction{
		EnforceAction: enforce,
	}

	netpol := &types.TetragonNetworkPolicy{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testUID",
			RuleName:   "rule1",
		},
		Subject:     subject,
		Destination: dest,
		Action:      action,
	}

	s.createSrcMatchLabelsPolicy(netpol)
	assert.Equal(t, 1, len(s.src))
}

func CreateDstMatchLabels(t *testing.T) {
	s := NewFakePolicyState(t)
	name := "testPol"
	netpol := testMatchDstLabelsPolicy(name, "A=a,B=b", "D1=d1,D2=d2")
	s.createDstMatchLabelsPolicy(netpol)
	d := s.dst[netpol.PolicyUID]
	assert.Equal(t, "d1", d.Labels["D1"])
	assert.Equal(t, "d2", d.Labels["D2"])
	assert.Equal(t, 0, len(d.Endpoints)) // no pods yet so no endpoints
}

func CreateSrcMatchLabels(t *testing.T) {
	s := NewFakePolicyState(t)
	name := "testPol"
	netpol := testMatchDstLabelsPolicy(name, "A=a,B=b", "D1=d1,D2=d2")
	s.createSrcMatchLabelsPolicy(netpol)
	src := s.src[netpol.PolicyUID]
	assert.NotNil(t, src)
	assert.Equal(t, "a", src.Labels["A"])
	assert.Equal(t, "b", src.Labels["B"])
	assert.Equal(t, 0, len(src.Subjects)) // no pods yet so no subjects either
}

func TestAddNetworkPolicy(t *testing.T) {
	s := NewFakePolicyState(t)
	name := "testPol"
	netpol := testMatchDstLabelsPolicy(name, "A=a,B=b", "D1=d1,D2=d2")
	err := s.createMatchLabelsPolicy(netpol)
	require.NoError(t, err)
	d := s.dst[netpol.PolicyUID]
	assert.NotNil(t, d)
	assert.Equal(t, "d1", d.Labels["D1"])
	assert.Equal(t, "d2", d.Labels["D2"])
	assert.Equal(t, 0, len(d.Endpoints)) // no pods yet so no endpoints
	src := s.src[netpol.PolicyUID]
	assert.NotNil(t, src)
	assert.Equal(t, "a", src.Labels["A"])
	assert.Equal(t, "b", src.Labels["B"])
	assert.Equal(t, 0, len(src.Subjects)) // no pods yet so no subjects either
}

func testAddNetworkActionPolicy(t *testing.T, action string) {
	s := NewFakePolicyState(t)
	name := "testPol"
	netpol := testMatchDstLabelsDenyPolicy(name, "A=a,B=b", "D1=d1,D2=d2", action)
	err := s.createMatchLabelsPolicy(netpol)
	require.NoError(t, err)
	d := s.dst[netpol.PolicyUID]
	assert.NotNil(t, d)
	assert.Equal(t, "d1", d.Labels["D1"])
	assert.Equal(t, "d2", d.Labels["D2"])
	assert.Equal(t, 0, len(d.Endpoints)) // no pods yet so no endpoints
	src := s.src[netpol.PolicyUID]
	assert.NotNil(t, src)
	assert.Equal(t, "a", src.Labels["A"])
	assert.Equal(t, "b", src.Labels["B"])
	assert.Equal(t, 0, len(src.Subjects)) // no pods yet so no subjects either

}

func TestAddNetworkAllowPolicy(t *testing.T) {
	testAddNetworkActionPolicy(t, "allow")
}

func TestAddNetworkDenyPolicy(t *testing.T) {
	testAddNetworkActionPolicy(t, "deny")
}

type policyCalcTest struct {
	PodML  []string
	Policy []string
	Check  []string
}

var tests = []policyCalcTest{
	{
		PodML:  []string{"testPod:A=a,B=b"},
		Policy: []string{"testPolicy:A=a,B=b:ebpf.io:deny"},
		Check:  []string{"testPolicy:testPod"},
	},
}

func TestMatchLabelsTable(t *testing.T) {
	s := NewFakePolicyState(t)

	for _, test := range tests {
		testPolicyCalculator(t, s, test.PodML, test.Policy, test.Check)
	}
}

func testPolicyCalculator(t *testing.T, s *PolicyState, podML, policy, check []string) {

	policyMap := make(map[string]*types.TetragonNetworkPolicy)
	// podMap := []policyfilter.PodID{}

	for _, pod := range podML {
		x := strings.Split(pod, ":")
		assert.Equal(t, len(x), 2)

		registerWorkloadID(t, s, testNamespace, x[0], testKind)
	}

	for _, p := range policy {
		x := strings.Split(p, ":")
		assert.Equal(t, len(x), 4)

		parsedPolicy := testMatchSrcLabelsPolicy(x[0], x[1])
		assert.NotNil(t, parsedPolicy)

		policyMap[x[0]] = parsedPolicy

		s.createSrcMatchLabelsPolicy(parsedPolicy)
		s.createDstMatchLabelsPolicy(parsedPolicy)
	}

	for _, pod := range podML {
		x := strings.Split(pod, ":")
		assert.Equal(t, len(x), 2)

		p := newPodFromCluster(t, s, "testNamespace", x[0], "testKind", x[1])
		_, _ = s.objectAdd(p)
	}

	for _, c := range check {
		x := strings.Split(c, ":")
		assert.Equal(t, len(x), 2)

		policyUID := types.TetragonPolicyUniqueID{
			PolicyName: x[0],
			RuleName:   "rule1",
		}
		policy := s.src[policyUID]
		found := false
		for _, s := range policy.Subjects {
			if s.WLID == 0x1 {
				found = true
				break
			}
		}
		assert.True(t, found)
	}

	for _, p := range policyMap {
		err := s.RemovePolicy(p)
		require.NoError(t, err)
	}

	// Before we were cleaning up the pod calling del Pod but we don't use
	// the policy filter so this should not be needed
}
