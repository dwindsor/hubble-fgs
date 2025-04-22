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
	netpol.Destination.CIDR = &types.TetragonNetworkCIDR{
		CIDR: cidr,
	}

	return netpol
}

func TestQueueWorkloadPolicy(t *testing.T) {
	s := NewPolicyState()
	name := "test"
	policy := testFQDNPolicy(name)

	QueueWorkloadNetworkPolicy(policy)
	assert.Equal(t, 1, len(queueWl))

	err := s.RemoveNetworkPolicy(name, policy)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(queueWl))
}

func TestCreateSrcKeyNoState(t *testing.T) {
	s := NewPolicyState()
	name := "test"
	policy := testFQDNPolicy(name)
	_, err := createSrcPolicy(policy)
	assert.NoError(t, err)
	err = s.RemoveNetworkPolicy(name, policy)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(queueWl))
}

func TestCreateSrcKeyNamespaceNoState(t *testing.T) {
	s := NewPolicyState()
	name := "test"
	policy := testFQDNPolicy(name)
	policy.Subject.Workload.Name = ""
	policy.Subject.Workload.Kind = ""
	key, err := createSrcPolicy(policy)
	assert.NoError(t, err)
	assert.Nil(t, key)

	err = s.RemoveNetworkPolicy(name, policy)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(queueWl))
}

func TestCreatSrcKeyGlobal(t *testing.T) {
	s := NewPolicyState()
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

	err = s.RemoveNetworkPolicy(name, policy)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(queueWl))
}

func TestCreateSrcMatchLabelsPolicy(t *testing.T) {
	s := NewPolicyState()
	name := "testName"
	uid := "testName"

	policy := testMatchSrcLabelsPolicy(name, "A=a,B=b")
	s.CreateSrcMatchLabelsPolicy(uid, policy)

	assert.Equal(t, 1, len(s.Src))

	err := s.RemoveMatchLabelNetworkPolicy(uid, policy)
	assert.NoError(t, err)

	assert.Equal(t, 0, len(s.Src))
}

func TestCreateDstMatchLabelsPolicy(t *testing.T) {
	s := NewPolicyState()
	name := "testName"
	uid := "testName"

	nextId()

	policy := testMatchDstLabelsPolicy(name, "A=a,B=b", "D1=d1,D2=d2")
	s.CreateDstMatchLabelsPolicy(uid, policy)

	assert.Equal(t, 1, len(s.Dst))

	err := s.RemoveMatchLabelNetworkPolicy(uid, policy)
	assert.NoError(t, err)

	assert.Equal(t, 0, len(s.Dst))
}

func TestCreateSrcKey(t *testing.T) {
	s := NewPolicyState()

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
		Name:        "testNetpol",
		Subject:     subject,
		Destination: dest,
		Action:      action,
	}

	s.CreateSrcMatchLabelsPolicy("testUID", netpol)
	assert.Equal(t, 1, len(s.Src))
}

func CreateDstMatchLabels(t *testing.T) {
	s := NewPolicyState()
	name := "testPol"
	netpol := testMatchDstLabelsPolicy(name, "A=a,B=b", "D1=d1,D2=d2")
	s.CreateDstMatchLabelsPolicy(name, netpol)
	d := s.Dst[name]
	assert.Equal(t, "d1", d.Labels["D1"])
	assert.Equal(t, "d2", d.Labels["D2"])
	assert.Equal(t, 0, len(d.Endpoints)) // no pods yet so no endpoints
}

func CreateSrcMatchLabels(t *testing.T) {
	s := NewPolicyState()
	name := "testPol"
	netpol := testMatchDstLabelsPolicy(name, "A=a,B=b", "D1=d1,D2=d2")
	s.CreateSrcMatchLabelsPolicy(name, netpol)
	src := s.Src[name]
	assert.NotNil(t, src)
	assert.Equal(t, "a", src.Labels["A"])
	assert.Equal(t, "b", src.Labels["B"])
	assert.Equal(t, 0, len(src.Subjects)) // no pods yet so no subjects either
}

func TestAddNetworkPolicy(t *testing.T) {
	s := NewPolicyState()
	name := "testPol"
	netpol := testMatchDstLabelsPolicy(name, "A=a,B=b", "D1=d1,D2=d2")
	err := s.CreateMatchLabelsPolicy(name, netpol)
	assert.NoError(t, err)
	d := s.Dst[name]
	assert.NotNil(t, d)
	assert.Equal(t, "d1", d.Labels["D1"])
	assert.Equal(t, "d2", d.Labels["D2"])
	assert.Equal(t, 0, len(d.Endpoints)) // no pods yet so no endpoints
	src := s.Src[name]
	assert.NotNil(t, src)
	assert.Equal(t, "a", src.Labels["A"])
	assert.Equal(t, "b", src.Labels["B"])
	assert.Equal(t, 0, len(src.Subjects)) // no pods yet so no subjects either
}

func testAddNetworkActionPolicy(t *testing.T, action string) {
	s := NewPolicyState()
	name := "testPol"
	netpol := testMatchDstLabelsDenyPolicy(name, "A=a,B=b", "D1=d1,D2=d2", action)
	err := s.CreateMatchLabelsPolicy(name, netpol)
	assert.NoError(t, err)
	d := s.Dst[name]
	assert.NotNil(t, d)
	assert.Equal(t, "d1", d.Labels["D1"])
	assert.Equal(t, "d2", d.Labels["D2"])
	assert.Equal(t, 0, len(d.Endpoints)) // no pods yet so no endpoints
	src := s.Src[name]
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
