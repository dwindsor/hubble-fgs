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

package dns

import (
	"strings"
	"testing"

	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/stretchr/testify/assert"

	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

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
	s := NewPolicyState()
	SetRealizedState(s)

	for _, test := range tests {
		testPolicyCalculator(t, test.PodML, test.Policy, test.Check)
	}
}

func testPolicyCalculator(t *testing.T, podML, policy, check []string) {
	s := GetRealizedState()

	policyMap := make(map[string]*types.TetragonNetworkPolicy)
	podMap := []policyfilter.PodID{}

	for _, pod := range podML {
		x := strings.Split(pod, ":")
		assert.Equal(t, len(x), 2)

		id := nextId()
		addPod(t, id, x[0], x[1])
		podMap = append(podMap, id)
	}

	for _, p := range policy {
		x := strings.Split(p, ":")
		assert.Equal(t, len(x), 4)

		parsedPolicy := testMatchSrcLabelsPolicy(x[0], x[1])
		assert.NotNil(t, parsedPolicy)

		policyMap[x[0]] = parsedPolicy

		s.CreateSrcMatchLabelsPolicy(parsedPolicy)
		s.CreateDstMatchLabelsPolicy(parsedPolicy)
	}

	for _, pod := range podML {
		x := strings.Split(pod, ":")
		assert.Equal(t, len(x), 2)

		p := testPod(t, "100", "testNamespace", x[0], "testKind", x[1])
		PodAdd(p)
	}

	for _, c := range check {
		x := strings.Split(c, ":")
		assert.Equal(t, len(x), 2)

		policyUID := types.TetragonPolicyUniqueID{
			PolicyName: x[0],
			RuleName:   "rule1",
		}
		policy := s.Src[policyUID]
		found := false
		for _, s := range policy.Subjects {
			if s.NSID == 0x1 {
				found = true
				break
			}
		}
		assert.True(t, found)
	}

	for _, p := range policyMap {
		err := s.RemovePolicy(p)
		assert.NoError(t, err)
	}

	for _, i := range podMap {
		delPod(t, i)
	}
}
