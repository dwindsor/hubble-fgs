package dns

import (
	"strings"
	"testing"

	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/stretchr/testify/assert"
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
	for _, test := range tests {
		testPolicyCalculator(t, test.PodML, test.Policy, test.Check)
	}
}

func testPolicyCalculator(t *testing.T, podML, policy, check []string) {

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

		parsedPolicy := testMatchLabelsPolicy(x[0], x[1])
		assert.NotNil(t, parsedPolicy)

		policyMap[x[0]] = parsedPolicy

		createMatchLabelsPolicy(x[0], parsedPolicy)
	}

	for _, pod := range podML {
		x := strings.Split(pod, ":")
		assert.Equal(t, len(x), 2)

		p := testPod("testNamespace", x[0], "Pod", x[1])
		CheckPodAdd(p)
	}

	for _, c := range check {
		x := strings.Split(c, ":")
		assert.Equal(t, len(x), 2)

		policy := matchLabelPolicy[x[0]]
		found := false
		for _, pod := range policy.EPPods {
			if pod.WorkloadObject.Name == x[1] {
				found = true
				break
			}
		}
		assert.True(t, found)
	}

	for i, p := range policyMap {
		err := RemoveMatchLabelNetworkPolicy(i, p)
		assert.NoError(t, err)
	}

	for _, i := range podMap {
		delPod(t, i)
	}
}
