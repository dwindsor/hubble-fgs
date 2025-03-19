package dns

import (
	"strings"
	"testing"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// One thing that is odd about these tests is we are working over the NSID
// State cache. So checking NSID values depends on if there is an existing
// Pod* -> NSID match in the cache. I decided the pain of tracking this to
// be worthwhile so I could verify CGID expected values. A couple tests will
// check this to be sure we are correctly doing mappings and after that we
// just expect non-zero cgid.
//
// Second trouble here is nothign is parallizable.
var (
	globalCgId = 0
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

func podId(id string) policyfilter.PodID {
	uid := [16]byte{}

	copy(uid[:], id)
	return uid
}

func testPod(t *testing.T, id, ns, name, kind, matchLabels string) *v1alpha1.PodInfo {
	state, err := policyfilter.GetState()
	assert.NoError(t, err)

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
	podInfo := &v1alpha1.PodInfo{
		WorkloadType:   ty,
		WorkloadObject: wl,
		ObjectMeta:     meta,
	}

	cgid := policyfilter.CgroupID(0x01)
	err = state.AddPodContainer(podId(id), ns, name, kind, ml, "testContainerID", cgid, "testContainerName")
	assert.NoError(t, err)

	return podInfo
}

func TestCheckWorkloadExists(t *testing.T) {
	name := "testName"

	test1Id := nextId()
	addPod(t, test1Id, name, "A=a")

	policy := testFQDNPolicy(name)
	key, err := createSrcPolicy(policy)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.NotZero(t, key.CgroupId)
	assert.Equal(t, 0, len(queueWl))

	pod := testPod(t, "1", "testNamespace", "testNameFoo", "Pod", "")
	err = checkWorkloadQuotaPolicy(pod)
	assert.NoError(t, err)

	err = RemoveNetworkPolicy(name, policy)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(queueWl))

	delPod(t, test1Id)
}

// This tests assumes NSID space is incrementing every addPolicyFilter
// which allows us to check cgroupID
func TestSrcKeyLookup(t *testing.T) {
	test1Id := nextId()
	test2Id := nextId()

	addPod(t, test1Id, "test1", "A=a")
	addPod(t, test2Id, "test2", "B=b")

	key, err := createSrcKey("testNamespace", "test1", "testKind")
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.NotZero(t, key.CgroupId)

	key, err = createSrcKey("testNamespace", "test2", "testKind")
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.NotZero(t, key.CgroupId)

	delPod(t, test1Id)
	delPod(t, test2Id)

}

func TestSrcPolicyLookup(t *testing.T) {
	name1 := "testName1"
	name2 := "testName2"

	test1Id := nextId()
	test2Id := nextId()

	addPod(t, test1Id, name1, "A=a")
	addPod(t, test2Id, name2, "A=a")

	policy1 := testFQDNPolicy(name1)
	policy1.Subject.Workload.Name = name1
	key, err := createSrcPolicy(policy1)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.NotZero(t, key.CgroupId)
	assert.Equal(t, 0, len(queueWl))

	policy2 := testFQDNPolicy(name2)
	policy2.Subject.Workload.Name = name2
	key, err = createSrcPolicy(policy2)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.NotZero(t, key.CgroupId)
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

func TestCheckMatchLabelsPolicy(t *testing.T) {
	name := "netpol"
	srcId := nextId()
	dstId := nextId()
	dstIdKeep := nextId()

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	dstPodNameKeep := "testNamePodDstKeep"

	netpol := testMatchDstLabelsPolicy(name, srcPodLabels, dstPodLabels)
	err := CreateMatchLabelsPolicy(name, netpol)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(matchLabelPolicy))
	assert.Equal(t, 1, len(matchLabelDstPolicy))

	// srcPod matches subject labels so will be granted to records one for FQDN name.
	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "2", "testNamespace", srcPodName, "testPod", srcPodLabels)
	r1, err := __PodAdd(srcPod, true)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(r1))
	assert.NotZero(t, r1[0].Src.CgroupId)
	assert.Equal(t, endpoint.DnsType, r1[0].EP.Type)
	assert.Equal(t, "test.io", r1[0].EP.Dns)
	assert.Equal(t, endpoint.DnsType, r1[1].EP.Type)
	assert.Equal(t, "test.com", r1[1].EP.Dns)

	// dstPod does not match subject so will have no FQDN records but will match endpoint
	// labels and srcPod needs to be given a record for the srcPod->dstPod pair.
	addPod(t, dstId, dstPodName, dstPodLabels)
	dstPod := testPod(t, "3", "testNamespace", dstPodName, "testPod", dstPodLabels)
	r2, err := __PodAdd(dstPod, true)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(r2))
	assert.Equal(t, r1[0].Src.CgroupId, r2[0].Src.CgroupId)
	assert.Equal(t, endpoint.PodType, r2[0].EP.Type)
	assert.Equal(t, dstPodName, r2[0].EP.Name)

	addPod(t, dstIdKeep, dstPodNameKeep, dstPodLabels)
	dstPodKeep := testPod(t, "4", "testNamespace", dstPodNameKeep, "testPod", dstPodLabels)
	r3, err := __PodAdd(dstPodKeep, true)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(r3))
	assert.Equal(t, r1[0].Src.CgroupId, r3[0].Src.CgroupId)
	assert.Equal(t, endpoint.PodType, r3[0].EP.Type)
	assert.Equal(t, dstPodNameKeep, r3[0].EP.Name)

	// Test matchLabels keys are tracking the subjects
	src, _ := matchLabelPolicy[name]
	assert.NotNil(t, src)
	assert.Equal(t, 1, len(src.Subjects))
	assert.Equal(t, r1[0].Src.CgroupId, src.Subjects[0].CgroupId)

	// Test matchLAbelsDstPolicy is tracking endpoints
	dst := matchLabelDstPolicy[name]
	assert.NotNil(t, dst)
	assert.Equal(t, 2, len(dst.Endpoints))
	assert.Equal(t, endpoint.PodType, dst.Endpoints[0].Type)
	assert.Equal(t, dstPodName, dst.Endpoints[0].Name)
	assert.Equal(t, "testNamespace", dst.Endpoints[0].Namespace)
	assert.Equal(t, "testPod", dst.Endpoints[0].Kind)

	// Deleting dstId pod will remove the Endpoints but because
	// its a subjects no change that will not change.
	delPod(t, dstId)
	deleted, err := PodRemove(dstPod, true)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(dst.Endpoints))
	assert.Equal(t, 1, len(src.Subjects))
	assert.Equal(t, 1, deleted)

	// Interesting artifact is deleting duplicate twice
	// will build same endpoint recordSet.
	deleted, err = PodRemove(dstPod, true)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(dst.Endpoints))
	assert.Equal(t, 1, len(src.Subjects))
	assert.Equal(t, 1, deleted)

	delPod(t, dstIdKeep)
	deleted, err = PodRemove(dstPodKeep, true)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(dst.Endpoints))
	assert.Equal(t, 1, len(src.Subjects))
	assert.Equal(t, 1, deleted)

	delPod(t, srcId)
	deleted, err = PodRemove(srcPod, true)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(dst.Endpoints))
	assert.Equal(t, 0, len(src.Subjects))
	assert.Equal(t, 2, deleted)

	zombieSet, err := __RemoveMatchLabelNetworkPolicy(name, netpol)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(zombieSet))
}

func TestSrcPolicyAddsDefaultAction(t *testing.T) {
	name := "netpol"
	srcId := nextId()

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	netpol := testMatchDstLabelsDenyPolicy(name, srcPodLabels, dstPodLabels, "deny")
	err := CreateMatchLabelsPolicy(name, netpol)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(matchLabelPolicy))
	assert.Equal(t, 1, len(matchLabelDstPolicy))

	// srcPod matches subject labels so will be granted to records one for default action
	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "2", "testNamespace", srcPodName, "testPod", srcPodLabels)
	r1, err := __PodAdd(srcPod, true)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(r1))

	assert.NotZero(t, r1[0].Src.CgroupId)
	assert.Equal(t, endpoint.DnsType, r1[0].EP.Type)
	assert.Equal(t, "test.io", r1[0].EP.Dns)
	assert.Equal(t, r1[0].Action.Deny, record.PolicyDeny)

	assert.NotZero(t, r1[1].Src.CgroupId)
	assert.Equal(t, endpoint.DnsType, r1[1].EP.Type)
	assert.Equal(t, "test.com", r1[1].EP.Dns)
	assert.Equal(t, r1[1].Action.Deny, record.PolicyDeny)

	assert.NotZero(t, r1[2].Src.CgroupId)
	assert.Nil(t, r1[2].EP)
	assert.Equal(t, r1[2].Action.Deny, record.PolicyAllow)

	// Remove pod and policy
	delPod(t, srcId)
	deleted, err := PodRemove(srcPod, true)
	assert.NoError(t, err)
	assert.Equal(t, 3, deleted)

	zombieSet, err := __RemoveMatchLabelNetworkPolicy(name, netpol)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(zombieSet))
}

// Test addPod again, but bring up subject after destinations are already loaded
func TestSrcPolicyAddsDefaultActionDstFirst(t *testing.T) {
	name := "netpol"
	srcId := nextId()
	dstId := nextId()

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	netpol := testMatchDstLabelsDenyPolicy(name, srcPodLabels, dstPodLabels, "allow")
	err := CreateMatchLabelsPolicy(name, netpol)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(matchLabelPolicy))
	assert.Equal(t, 1, len(matchLabelDstPolicy))

	// add dst pod first which does not match a subject for any policy8
	addPod(t, dstId, dstPodName, dstPodLabels)
	dstPod := testPod(t, "3", "testNamespace", dstPodName, "testPod", dstPodLabels)
	rDst, err := __PodAdd(dstPod, true)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(rDst)) // no records to program datapath bc not a subject

	// add src pod next and ensure we build correct policy
	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "2", "testNamespace", srcPodName, "testPod", srcPodLabels)
	r1, err := __PodAdd(srcPod, true)
	assert.NoError(t, err)
	assert.Equal(t, 4, len(r1)) // program datapath now for subject->dst

	assert.NotZero(t, r1[0].Src.CgroupId)
	assert.Equal(t, endpoint.DnsType, r1[0].EP.Type)
	assert.Equal(t, "test.io", r1[0].EP.Dns)
	assert.Equal(t, r1[0].Action.Deny, record.PolicyAllow)

	assert.NotZero(t, r1[1].Src.CgroupId)
	assert.Equal(t, endpoint.DnsType, r1[1].EP.Type)
	assert.Equal(t, "test.com", r1[1].EP.Dns)
	assert.Equal(t, r1[1].Action.Deny, record.PolicyAllow)

	assert.NotZero(t, r1[2].Src.CgroupId)
	assert.Equal(t, endpoint.PodType, r1[2].EP.Type)
	assert.Equal(t, r1[2].Action.Deny, record.PolicyAllow)

	assert.NotZero(t, r1[3].Src.CgroupId)
	assert.Nil(t, r1[3].EP)
	assert.Equal(t, r1[3].Action.Deny, record.PolicyDeny)

	// Remove pod and policy
	delPod(t, dstId)
	deleted, err := PodRemove(dstPod, true)
	assert.NoError(t, err)
	assert.Equal(t, 1, deleted)

	// Remove pod and policy
	delPod(t, srcId)
	deleted, err = PodRemove(srcPod, true)
	assert.NoError(t, err)
	assert.Equal(t, 3, deleted)

	zombieSet, err := __RemoveMatchLabelNetworkPolicy(name, netpol)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(zombieSet))
}
