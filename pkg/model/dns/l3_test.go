//go:build sudo_tests

package dns

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

func vrfSubject(color string) types.TetragonLogicalNetworkSubject {
	return types.TetragonLogicalNetworkSubject{
		VRF: color,
	}
}

func networkSubject(color string) types.TetragonNetworkSubject {
	return types.TetragonNetworkSubject{
		LogicalNetwork: vrfSubject(color),
	}
}

func networkSource(src string) *types.TetragonNetworkSource {
	c := &types.TetragonNetworkCIDR{
		CIDR: src,
	}
	return &types.TetragonNetworkSource{
		CIDR: c,
	}
}

func networkDestination(dst string) types.TetragonNetworkDestination {
	c := &types.TetragonNetworkCIDR{
		CIDR: dst,
	}
	return types.TetragonNetworkDestination{
		CIDR:  c,
		Ports: []uint32{443, 80},
	}
}

func enforceAction(deny bool) types.TetragonNetworkAction {
	enforce := &types.TetragonEnforceAction{
		Deny:  deny,
		Allow: !deny,
	}
	return types.TetragonNetworkAction{
		EnforceAction: enforce,
	}
}

func defAction(_ bool) types.TetragonNetworkAction {
	return enforceAction(true)

}

func testVrfPolicy(name, rule, color, src, dst string, def, deny bool) *types.TetragonNetworkPolicy {
	subject := networkSubject(color)
	source := networkSource(src)
	dest := networkDestination(dst)
	action := enforceAction(deny)
	defAction := defAction(def)

	return &types.TetragonNetworkPolicy{
		Name:        name,
		Rule:        rule,
		Subject:     subject,
		Source:      source,
		Destination: dest,
		Action:      action,
		Default:     defAction,
	}
}

func smartswitchTestVrfPolicy(name, rule, color, src, dst string) *types.TetragonNetworkPolicy {
	return testVrfPolicy(name, rule, color, src, dst, true, false)
}

func findRecords(records []*record.DatapathRecord, name, rule, color, src, dst string, dport uint32) error {
	for _, r := range records {
		// Policy names have a unique id postfix
		if !strings.HasPrefix(r.Policy.Name, name) {
			continue
		}
		if r.Policy.Rule != rule {
			continue
		}
		if r.L3Src.Ip != src {
			continue
		}
		if r.L3Src.Port != 0 {
			return fmt.Errorf("unexpected sport value")
		}
		if r.Endpoint.EP == nil {
			return fmt.Errorf("unexpected nil EP")
		}
		if r.Endpoint.EP.Ip != dst {
			continue
		}
		if r.Endpoint.Port != dport {
			continue
		}
		return nil
	}

	fmt.Printf("no match! searching[%s:%s %s %s->%s:%d\n", name, rule, color, src, dst, dport)
	for i, r := range records {
		fmt.Printf("%d: %s\n", i, r)
	}

	return fmt.Errorf("could not find matching record")
}

func TestBasicIntraVRFPolicy(t *testing.T) {
	s := NewPolicyState()
	SetRealizedState(s)
	s = GetRealizedState()

	// Bug wth two policy on "red" wit different CIDRS.
	vrfMap := make(map[string]uint32)
	vrfMap["red"] = 1
	vrfMap["blue"] = 2
	vrfMap["green"] = 3
	s.SetL3NetworkMap(vrfMap)

	// Add a red policy and ensure we generate correct records for each port
	netpolR := smartswitchTestVrfPolicy("redPolicy", "singleton", "red", "10.1.0.0/16", "10.2.0.0/16")
	netpolSetR := []*types.TetragonNetworkPolicy{netpolR}
	state, addSet, removeSet, errSet := createMatchLabelsPolicySet(netpolSetR)
	assert.Equal(t, 2, len(addSet))
	err := findRecords(addSet, "redPolicy", "singleton", "red", "10.1.0.0/16", "10.2.0.0/16", uint32(443))
	assert.NoError(t, err)
	err = findRecords(addSet, "redPolicy", "singleton", "red", "10.1.0.0/16", "10.2.0.0/16", uint32(80))
	assert.NoError(t, err)
	assert.Zero(t, len(removeSet))
	assert.NoError(t, errSet)
	SetRealizedState(state)

	// Add a blue policy with overlapping cidrs and ensure we generate correct records for each port
	netpolB := smartswitchTestVrfPolicy("bluePolicy", "singleton", "blue", "10.1.0.0/16", "10.2.0.0/16")
	netpolSetB := []*types.TetragonNetworkPolicy{netpolB}
	state, addSet, removeSet, errSet = createMatchLabelsPolicySet(netpolSetB)
	assert.Equal(t, 4, len(addSet))
	err = findRecords(addSet, "redPolicy", "singleton", "red", "10.1.0.0/16", "10.2.0.0/16", uint32(443))
	assert.NoError(t, err)
	err = findRecords(addSet, "redPolicy", "singleton", "red", "10.1.0.0/16", "10.2.0.0/16", uint32(80))
	assert.NoError(t, err)
	err = findRecords(addSet, "bluePolicy", "singleton", "blue", "10.1.0.0/16", "10.2.0.0/16", uint32(443))
	assert.NoError(t, err)
	err = findRecords(addSet, "bluePolicy", "singleton", "blue", "10.1.0.0/16", "10.2.0.0/16", uint32(80))
	assert.NoError(t, err)
	assert.Zero(t, len(removeSet))
	assert.NoError(t, errSet)
	SetRealizedState(state)

	// Add a 2nd red policy and ensure we generate correct records for each port
	netpolR2 := smartswitchTestVrfPolicy("redPolicy2", "singleton2", "red", "10.3.0.0/16", "10.2.0.0/16")
	netpolSetR2 := []*types.TetragonNetworkPolicy{netpolR2}
	state, addSet, removeSet, errSet = createMatchLabelsPolicySet(netpolSetR2)
	assert.Equal(t, 6, len(addSet))
	err = findRecords(addSet, "redPolicy2", "singleton2", "red", "10.3.0.0/16", "10.2.0.0/16", uint32(443))
	assert.NoError(t, err)
	err = findRecords(addSet, "redPolicy2", "singleton2", "red", "10.3.0.0/16", "10.2.0.0/16", uint32(80))
	assert.NoError(t, err)
	err = findRecords(addSet, "red", "singleton", "red", "10.1.0.0/16", "10.2.0.0/16", uint32(443))
	assert.NoError(t, err)
	err = findRecords(addSet, "red", "singleton", "red", "10.1.0.0/16", "10.2.0.0/16", uint32(80))
	assert.NoError(t, err)
	err = findRecords(addSet, "blue", "singleton", "blue", "10.1.0.0/16", "10.2.0.0/16", uint32(443))
	assert.NoError(t, err)
	err = findRecords(addSet, "blue", "singleton", "blue", "10.1.0.0/16", "10.2.0.0/16", uint32(80))
	assert.NoError(t, err)
	assert.Zero(t, len(removeSet))
	assert.NoError(t, errSet)
	SetRealizedState(state)

	// Remove red policy and ensure we generate removal records for each port
	// Removes need to use the unique idea assigned at create* time. The caller to this code will
	// track that policy user name to the internal unique id. We can test that separately, but
	// for now we know its a monotonic counter so we can just fake it.
	removeSet, addSet, errSet = state.removeMatchLabelNetworkPolicy("redPolicy_0", netpolR)
	assert.Equal(t, 2, len(addSet))
	assert.Equal(t, 2, len(removeSet))
	err = findRecords(removeSet, "red", "singleton", "red", "10.1.0.0/16", "10.2.0.0/16", uint32(443))
	assert.NoError(t, err)
	err = findRecords(removeSet, "red", "singleton", "red", "10.1.0.0/16", "10.2.0.0/16", uint32(80))
	assert.NoError(t, err)
	assert.NoError(t, errSet)
	SetRealizedState(state)

	// Remove blue policy and ensure we generate removal records for each port
	removeSet, addSet, errSet = state.removeMatchLabelNetworkPolicy("bluePolicy_0", netpolB)
	assert.Equal(t, 0, len(addSet))
	assert.Equal(t, 2, len(removeSet))
	err = findRecords(removeSet, "blue", "singleton", "red", "10.1.0.0/16", "10.2.0.0/16", uint32(443))
	assert.NoError(t, err)
	err = findRecords(removeSet, "blue", "singleton", "red", "10.1.0.0/16", "10.2.0.0/16", uint32(80))
	assert.NoError(t, err)
	assert.NoError(t, errSet)
	SetRealizedState(state)

	// Remove remaining red policy and ensure we generate removal records for each port
	removeSet, addSet, errSet = state.removeMatchLabelNetworkPolicy("redPolicy2_0", netpolR2)
	assert.Equal(t, 0, len(addSet))
	assert.Equal(t, 2, len(removeSet))
	err = findRecords(removeSet, "redPolicy2", "singleton2", "red", "10.3.0.0/16", "10.2.0.0/16", uint32(443))
	assert.NoError(t, err)
	err = findRecords(removeSet, "redPolicy2", "singleton2", "red", "10.3.0.0/16", "10.2.0.0/16", uint32(80))
	assert.NoError(t, err)
	assert.NoError(t, errSet)
	SetRealizedState(state)
}
