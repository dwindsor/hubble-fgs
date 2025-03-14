package dns

import (
	"strings"
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/stretchr/testify/assert"
)

func testFQDNPolicy(name string) *types.TetragonNetworkPolicy {
	wl := types.TetragonWorkloadNetworkSubject{
		Namespace: "testNamespace",
		Name:      "testName",
		Kind:      "testKind",
	}
	s := types.TetragonNetworkSubject{
		Workload: wl,
	}
	f := &types.TetragonNetworkFQDN{
		Names: []string{"test.io", "test.com"},
	}
	d := types.TetragonNetworkDestination{
		FQDN: f,
	}

	policy := &types.TetragonNetworkPolicy{
		Name:        name,
		Subject:     s,
		Destination: d,
	}
	return policy
}

func testMatchSrcLabelsPolicy(name, labels string) *types.TetragonNetworkPolicy {
	ml := make(map[string]string)
	for _, l := range strings.Split(labels, ",") {
		kv := strings.Split(l, "=")
		ml[kv[0]] = kv[1]
	}

	s := types.TetragonNetworkSubject{
		MatchLabelsEqual: ml,
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
		Name:        name,
		Subject:     s,
		Destination: d,
		Action:      a,
	}
	return policy
}

func testMatchDstLabelsPolicy(name, src, dst string) *types.TetragonNetworkPolicy {
	p := testMatchSrcLabelsPolicy(name, src)
	ml := make(map[string]string)
	for _, l := range strings.Split(dst, ",") {
		kv := strings.Split(l, "=")
		ml[kv[0]] = kv[1]
	}
	p.Destination.Labels.Equal = ml
	return p
}

func TestQueueWorkloadPolicy(t *testing.T) {
	name := "test"
	policy := testFQDNPolicy(name)

	QueueWorkloadNetworkPolicy(policy)
	assert.Equal(t, 1, len(queueWl))

	err := RemoveNetworkPolicy(name, policy)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(queueWl))
}

func TestCreateSrcKeyNoState(t *testing.T) {
	name := "test"
	policy := testFQDNPolicy(name)
	_, err := createSrcPolicy(policy)
	assert.NoError(t, err)
	err = RemoveNetworkPolicy(name, policy)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(queueWl))
}

func TestCreateSrcKeyNamespaceNoState(t *testing.T) {
	name := "test"
	policy := testFQDNPolicy(name)
	policy.Subject.Workload.Name = ""
	policy.Subject.Workload.Kind = ""
	key, err := createSrcPolicy(policy)
	assert.NoError(t, err)
	assert.Nil(t, key)

	err = RemoveNetworkPolicy(name, policy)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(queueWl))
}

func TestCreateSrcKeyGlobal(t *testing.T) {
	name := "test"
	policy := testFQDNPolicy(name)
	policy.Subject.Workload.Namespace = ""
	policy.Subject.Workload.Name = ""
	policy.Subject.Workload.Kind = ""
	key, err := createSrcPolicy(policy)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), key.CgroupId)
	assert.Equal(t, uint64(0), key.Depth)
	assert.Equal(t, uint64(0), key.Self)

	err = RemoveNetworkPolicy(name, policy)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(queueWl))
}

func TestCreateSrcMatchLabelsPolicy(t *testing.T) {
	name := "testName"
	uid := "testName"

	policy := testMatchSrcLabelsPolicy(name, "A=a,B=b")
	err := CreateSrcMatchLabelsPolicy(uid, policy)
	assert.NoError(t, err)

	assert.Equal(t, 1, len(matchLabelPolicy))

	err = RemoveMatchLabelNetworkPolicy(uid, policy)
	assert.NoError(t, err)

	assert.Equal(t, 0, len(matchLabelPolicy))
}

func TestCreateDstMatchLabelsPolicy(t *testing.T) {
	name := "testName"
	uid := "testName"

	nextId()

	policy := testMatchDstLabelsPolicy(name, "A=a,B=b", "D1=d1,D2=d2")
	err := CreateDstMatchLabelsPolicy(uid, policy)
	assert.NoError(t, err)

	assert.Equal(t, 1, len(matchLabelDstPolicy))

	err = RemoveMatchLabelNetworkPolicy(uid, policy)
	assert.NoError(t, err)

	assert.Equal(t, 0, len(matchLabelDstPolicy))
}

func TestCreateSrcKey(t *testing.T) {
	ml := make(map[string]string)
	ml["A"] = "a"
	ml["B"] = "b"

	wl := types.TetragonWorkloadNetworkSubject{
		Namespace: "testNamespace",
		Name:      "testName",
		Kind:      "testKind",
	}

	subject := types.TetragonNetworkSubject{
		MatchLabelsEqual: ml,
		Workload:         wl,
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
		Name:        "testNetpol",
		Subject:     subject,
		Destination: dest,
		Action:      action,
	}

	err := CreateSrcMatchLabelsPolicy("testUID", netpol)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(matchLabelPolicy))
}

func CreateDstMatchLabels(t *testing.T) {
	name := "testPol"
	netpol := testMatchDstLabelsPolicy(name, "A=a,B=b", "D1=d1,D2=d2")
	err := CreateDstMatchLabelsPolicy(name, netpol)
	assert.NoError(t, err)
	d := matchLabelDstPolicy[name]
	assert.Equal(t, "d1", d.Label["D1"])
	assert.Equal(t, "d2", d.Label["D2"])
	assert.Equal(t, 0, len(d.Endpoints)) // no pods yet so no endpoints
}

func CreateSrcMatchLabels(t *testing.T) {
	name := "testPol"
	netpol := testMatchDstLabelsPolicy(name, "A=a,B=b", "D1=d1,D2=d2")
	err := CreateSrcMatchLabelsPolicy(name, netpol)
	assert.NoError(t, err)
	s := matchLabelPolicy[name]
	assert.NotNil(t, s)
	assert.Equal(t, "a", s.Label["A"])
	assert.Equal(t, "b", s.Label["B"])
	assert.Equal(t, 0, len(s.Subjects)) // no pods yet so no subjects either
}

func TestAddNetworkPolicy(t *testing.T) {
	name := "testPol"
	netpol := testMatchDstLabelsPolicy(name, "A=a,B=b", "D1=d1,D2=d2")
	err := CreateMatchLabelsPolicy(name, netpol)
	assert.NoError(t, err)
	d := matchLabelDstPolicy[name]
	assert.NotNil(t, d)
	assert.Equal(t, "d1", d.Label["D1"])
	assert.Equal(t, "d2", d.Label["D2"])
	assert.Equal(t, 0, len(d.Endpoints)) // no pods yet so no endpoints
	s := matchLabelPolicy[name]
	assert.NotNil(t, s)
	assert.Equal(t, "a", s.Label["A"])
	assert.Equal(t, "b", s.Label["B"])
	assert.Equal(t, 0, len(s.Subjects)) // no pods yet so no subjects either
}
