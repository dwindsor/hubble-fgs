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
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: name,
			RuleName:   rule,
		},
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
		if !strings.HasPrefix(r.PolicyUID.PolicyName, name) {
			continue
		}
		if r.PolicyUID.RuleName != rule {
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
	removeSet, addSet, errSet = state.removeMatchLabelNetworkPolicy(netpolR)
	assert.Equal(t, 2, len(addSet))
	assert.Equal(t, 2, len(removeSet))
	err = findRecords(removeSet, "red", "singleton", "red", "10.1.0.0/16", "10.2.0.0/16", uint32(443))
	assert.NoError(t, err)
	err = findRecords(removeSet, "red", "singleton", "red", "10.1.0.0/16", "10.2.0.0/16", uint32(80))
	assert.NoError(t, err)
	assert.NoError(t, errSet)
	SetRealizedState(state)

	// Remove blue policy and ensure we generate removal records for each port
	removeSet, addSet, errSet = state.removeMatchLabelNetworkPolicy(netpolB)
	assert.Equal(t, 0, len(addSet))
	assert.Equal(t, 2, len(removeSet))
	err = findRecords(removeSet, "blue", "singleton", "red", "10.1.0.0/16", "10.2.0.0/16", uint32(443))
	assert.NoError(t, err)
	err = findRecords(removeSet, "blue", "singleton", "red", "10.1.0.0/16", "10.2.0.0/16", uint32(80))
	assert.NoError(t, err)
	assert.NoError(t, errSet)
	SetRealizedState(state)

	// Remove remaining red policy and ensure we generate removal records for each port
	removeSet, addSet, errSet = state.removeMatchLabelNetworkPolicy(netpolR2)
	assert.Equal(t, 0, len(addSet))
	assert.Equal(t, 2, len(removeSet))
	err = findRecords(removeSet, "redPolicy2", "singleton2", "red", "10.3.0.0/16", "10.2.0.0/16", uint32(443))
	assert.NoError(t, err)
	err = findRecords(removeSet, "redPolicy2", "singleton2", "red", "10.3.0.0/16", "10.2.0.0/16", uint32(80))
	assert.NoError(t, err)
	assert.NoError(t, errSet)
	SetRealizedState(state)
}

func findVrf(t *testing.T, vrf string, id uint32) {
	s := GetRealizedState()
	for k, v := range s.networkL3Objects {
		if k == vrf {
			assert.Equal(t, v, id)
			return
		}
	}
	assert.Fail(t, "find VRF could not find a matching VRF name.")
}

func TestAddVRFWithNoPolicy(t *testing.T) {
	s := NewPolicyState()
	SetRealizedState(s)
	s = GetRealizedState()

	vrfMap := make(map[string]uint32)
	vrfMap["red"] = 1
	vrfMap["blue"] = 2
	vrfMap["green"] = 3
	s.SetL3NetworkMap(vrfMap)

	// Check get state has update
	s = GetRealizedState()
	assert.Equal(t, len(s.networkL3Objects), 3)
	findVrf(t, "red", 1)
	findVrf(t, "blue", 2)
	findVrf(t, "green", 3)
}

func TestAddVRFAfterPolicy(t *testing.T) {
	var err error

	state := NewPolicyState()
	SetRealizedState(state)

	// Add a red policy no records should be created until we have a VRF map.
	netpolR := smartswitchTestVrfPolicy("redPolicy", "singleton", "red", "10.1.0.0/16", "10.2.0.0/16")
	netpolSetR := []*types.TetragonNetworkPolicy{netpolR}
	state, addSet, removeSet, errSet := createMatchLabelsPolicySet(netpolSetR)
	assert.Zero(t, len(addSet))
	assert.Zero(t, len(removeSet))
	assert.NoError(t, errSet)
	SetRealizedState(state)

	// Add a blue policy with overlapping cidrs until we have a VRF map no records should be created.
	netpolB := smartswitchTestVrfPolicy("bluePolicy", "singleton", "blue", "10.1.0.0/16", "10.2.0.0/16")
	netpolSetB := []*types.TetragonNetworkPolicy{netpolB}
	state, addSet, removeSet, errSet = createMatchLabelsPolicySet(netpolSetB)
	assert.Zero(t, len(addSet))
	assert.Zero(t, len(removeSet))
	assert.NoError(t, errSet)
	SetRealizedState(state)

	// Add some colors with existing policy.
	vrfMap := make(map[string]uint32)
	vrfMap["red"] = 1
	vrfMap["blue"] = 2
	vrfMap["green"] = 3
	state, addSet, removeSet, err = state.setL3NetworkMap(vrfMap)
	assert.NoError(t, err)
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

	// Remove a single VRF and check update, delete. Also check we can reuse the deleted id to be sure
	// nothing unexpected happens.
	vrfMap = make(map[string]uint32)
	vrfMap["red"] = 1
	vrfMap["green"] = 2
	state, addSet, removeSet, err = state.setL3NetworkMap(vrfMap)
	assert.NoError(t, err)

	assert.Equal(t, 2, len(addSet))
	err = findRecords(addSet, "redPolicy", "singleton", "red", "10.1.0.0/16", "10.2.0.0/16", uint32(443))
	assert.NoError(t, err)
	err = findRecords(addSet, "redPolicy", "singleton", "red", "10.1.0.0/16", "10.2.0.0/16", uint32(80))
	assert.NoError(t, err)

	assert.Equal(t, 2, len(removeSet))
	err = findRecords(removeSet, "bluePolicy", "singleton", "blue", "10.1.0.0/16", "10.2.0.0/16", uint32(443))
	assert.NoError(t, err)
	err = findRecords(removeSet, "bluePolicy", "singleton", "blue", "10.1.0.0/16", "10.2.0.0/16", uint32(80))
	assert.NoError(t, err)

	// Remove all the VRFs that are referenced by a policy so that we remove the remaining records.
	vrfMap = make(map[string]uint32)
	vrfMap["green"] = 2
	state, addSet, removeSet, err = state.setL3NetworkMap(vrfMap)
	assert.NoError(t, err)

	assert.Zero(t, len(addSet))

	assert.Equal(t, 2, len(removeSet))
	err = findRecords(removeSet, "redPolicy", "singleton", "red", "10.1.0.0/16", "10.2.0.0/16", uint32(443))
	assert.NoError(t, err)
	err = findRecords(removeSet, "redPolicy", "singleton", "red", "10.1.0.0/16", "10.2.0.0/16", uint32(80))
	assert.NoError(t, err)

	SetRealizedState(state)
}
