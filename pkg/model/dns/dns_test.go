package dns

import (
	"os"
	"strings"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// One thing that is odd about these tests is we are working over the NSID
// State cache. So checking NSID values depends on if there is an existing
// Pod* -> NSID match in the cache. I decided the pain of tracking this to
// be worthwhile so I could verify CGID expected values. A couple tests will
// check this to be sure we are correctly doing mappings and after that we
// just expect non-zero cgid.

var (
	globalCgId = uint64(0)
)

func nextId() policyfilter.PodID {
	var next policyfilter.PodID
	globalCgId++

	next = [16]byte{
		byte(0xff & globalCgId),
		byte(0xff & (globalCgId >> 8)),
		byte(0xff & (globalCgId >> 16)),
		byte(0xff & (globalCgId >> 24))}
	return next
}

func testMatchLabelsPolicy(name, labels string) *types.TetragonNetworkPolicy {
	ml := make(map[string]string)
	for _, l := range strings.Split(labels, ",") {
		kv := strings.Split(l, "=")
		ml[kv[0]] = kv[1]
	}

	s := types.TetragonNetworkSubject{
		MatchLabelsEqual: ml,
	}
	d := types.TetragonNetworkDestination{
		Names: []string{"test.io", "test.com"},
	}
	quota := &types.TetragonQuotaAction{
		Quota: "1",
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

func testPolicy(name string) *types.TetragonNetworkPolicy {
	wl := types.TetragonWorkloadNetworkSubject{
		Namespace: "testNamespace",
		Name:      "testName",
		Kind:      "testKind",
	}
	s := types.TetragonNetworkSubject{
		Workload: wl,
	}
	d := types.TetragonNetworkDestination{
		Names: []string{"test.io", "test.com"},
	}

	policy := &types.TetragonNetworkPolicy{
		Name:        name,
		Subject:     s,
		Destination: d,
	}
	return policy
}

func delPod(t *testing.T, id policyfilter.PodID) {
	state, err := policyfilter.GetState()
	assert.NoError(t, err)

	err = state.DelPod(id)
	assert.NoError(t, err)
}

func addPod(t *testing.T, id policyfilter.PodID, name, labels string) {
	state, err := policyfilter.GetState()
	assert.NoError(t, err)

	matchLabels := make(map[string]string)
	for _, l := range strings.Split(labels, ",") {
		kv := strings.Split(l, "=")
		matchLabels[kv[0]] = kv[1]
	}

	cgid := policyfilter.CgroupID(0x2)

	err = state.AddPodContainer(id,
		"testNamespace", name, "testKind",
		matchLabels,
		"testContainerID", cgid, "testContainerName")
	assert.NoError(t, err)
}

func testPod(ns, name, kind, matchLabels string) *v1alpha1.PodInfo {
	ml := make(map[string]string)
	for _, l := range strings.Split(matchLabels, ",") {
		kv := strings.Split(l, "=")
		if len(kv) == 2 {
			ml[kv[0]] = kv[1]
		}
	}

	wl := v1alpha1.WorkloadObjectMeta{
		Name:      name,
		Namespace: ns,
	}
	ty := metav1.TypeMeta{
		Kind: kind,
	}
	meta := metav1.ObjectMeta{
		Labels: ml,
	}
	return &v1alpha1.PodInfo{
		TypeMeta:       ty,
		WorkloadObject: wl,
		ObjectMeta:     meta,
	}
}

func TestMain(m *testing.M) {
	bpf.CheckOrMountCgroup2()
	option.Config.EnablePolicyFilter = true
	ec := runner.TestSensorsRun(m, "ModelDns")
	os.Exit(ec)
}

func TestQueueWorkloadPolicy(t *testing.T) {
	name := "test"
	policy := testPolicy(name)

	QueueWorkloadNetworkPolicy(policy)
	assert.Equal(t, 1, len(queueWl))

	err := RemoveNetworkPolicy(name, policy)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(queueWl))
}

func TestCreateSrcKeyNoState(t *testing.T) {
	name := "test"
	policy := testPolicy(name)
	key, err := createSrcPolicy(policy)
	assert.NoError(t, err)
	assert.Nil(t, key)

	err = RemoveNetworkPolicy(name, policy)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(queueWl))
}

func TestCreateSrcKeyNamespaceNoState(t *testing.T) {
	name := "test"
	policy := testPolicy(name)
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
	policy := testPolicy(name)
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

// This tests assumes NSID space is incrementing every addPolicyFilter
// which allows us to check cgroupID
func TestSrcKeyLookup(t *testing.T) {
	test1Id := nextId()
	_test1Id := globalCgId
	test2Id := nextId()
	_test2Id := globalCgId

	addPod(t, test1Id, "test1", "A=a")
	addPod(t, test2Id, "test2", "B=b")

	key, err := createSrcKey("testNamespace", "test1", "testKind")
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, _test1Id, key.CgroupId)

	key, err = createSrcKey("testNamespace", "test2", "testKind")
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, _test2Id, key.CgroupId)

	delPod(t, test1Id)
	delPod(t, test2Id)

}

func TestSrcPolicyLookup(t *testing.T) {
	name1 := "testName1"
	name2 := "testName2"

	test1Id := nextId()
	_test1Id := globalCgId
	test2Id := nextId()
	_test2Id := globalCgId

	addPod(t, test1Id, name1, "A=a")
	addPod(t, test2Id, name2, "A=a")

	policy1 := testPolicy(name1)
	policy1.Subject.Workload.Name = name1
	key, err := createSrcPolicy(policy1)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, _test1Id, key.CgroupId)
	assert.Equal(t, 0, len(queueWl))

	policy2 := testPolicy(name2)
	policy2.Subject.Workload.Name = name2
	key, err = createSrcPolicy(policy2)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, _test2Id, key.CgroupId)
	assert.Equal(t, 0, len(queueWl))

	err = RemoveNetworkPolicy(name1, policy1)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(queueWl))

	err = RemoveNetworkPolicy(name2, policy2)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(queueWl))

	delPod(t, test1Id)
	delPod(t, test2Id)
}

func TestCheckWorkloadExists(t *testing.T) {
	name := "testName"

	test1Id := nextId()
	addPod(t, test1Id, name, "A=a")

	policy := testPolicy(name)
	key, err := createSrcPolicy(policy)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.NotZero(t, key.CgroupId)
	assert.Equal(t, 0, len(queueWl))

	pod := testPod("testNamespace", "testNameFoo", "Pod", "")
	err = checkWorkloadQuotaPolicy(pod)
	assert.NoError(t, err)

	err = RemoveNetworkPolicy(name, policy)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(queueWl))

	delPod(t, test1Id)
}

func TestCreateMatchLabelsPolicy(t *testing.T) {
	name := "testName"
	uid := "testName"

	policy := testMatchLabelsPolicy(name, "A=a,B=b")
	err := createMatchLabelsPolicy(uid, policy)
	assert.NoError(t, err)

	assert.Equal(t, 1, len(matchLabelPolicy))

	err = RemoveMatchLabelNetworkPolicy(uid, policy)
	assert.NoError(t, err)

	assert.Equal(t, 0, len(matchLabelPolicy))
}

func TestCheckMatchLabelsPolicy(t *testing.T) {
	name := "testName"
	uid := "testName"

	policy := testMatchLabelsPolicy(name, "A=a,B=b")
	err := createMatchLabelsPolicy(uid, policy)
	assert.NoError(t, err)

	assert.Equal(t, 1, len(matchLabelPolicy))

	podMatch1 := testPod("testNamespace", "testNamePod", "Pod", "A=a,B=b")
	err = checkMatchLabelsPolicy(podMatch1)
	assert.NoError(t, err)

	podMatch2 := testPod("testNamespace", "testNamePod", "Pod", "A=a,B=b,C=c")
	err = checkMatchLabelsPolicy(podMatch2)
	assert.NoError(t, err)

	podErr1 := testPod("testNamespace", "testNamePod", "Pod", "A=a,B=c")
	err = checkMatchLabelsPolicy(podErr1)
	assert.Error(t, err)

	podErr2 := testPod("testNamespace", "testNamePod", "Pod", "A=a")
	err = checkMatchLabelsPolicy(podErr2)
	assert.Error(t, err)

	podErr3 := testPod("testNamespace", "testNamePod", "Pod", "")
	err = checkMatchLabelsPolicy(podErr3)
	assert.Error(t, err)

	err = RemoveMatchLabelNetworkPolicy(uid, policy)
	assert.NoError(t, err)

	assert.Equal(t, 0, len(matchLabelPolicy))
}
