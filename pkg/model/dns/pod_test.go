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

	"github.com/cilium/tetragon/pkg/podhelpers"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stype "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
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
		"testContainerID", cgid,
		podhelpers.ContainerInfo{Name: "testContainerName", Repo: "testContainerRepo"})
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
		Labels:    ml,
		UID:       k8stype.UID(name),
		Name:      name,
		Namespace: ns,
	}
	podInfo := &v1alpha1.PodInfo{
		WorkloadType:   ty,
		WorkloadObject: wl,
		ObjectMeta:     meta,
	}

	cgid := policyfilter.CgroupID(0x01)
	err = state.AddPodContainer(
		podId(id), ns, name, kind, ml, "testContainerID", cgid,
		podhelpers.ContainerInfo{Name: "testContainerName", Repo: "testContainerRepo"})
	assert.NoError(t, err)

	return podInfo
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
	assert.NotZero(t, key.NSID)

	key, err = createSrcKey("testNamespace", "test2", "testKind")
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.NotZero(t, key.NSID)

	delPod(t, test1Id)
	delPod(t, test2Id)

}

func TestCheckMatchLabelsPolicy(t *testing.T) {
	s := NewPolicyState()
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
	err := s.CreateMatchLabelsPolicy(netpol)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(s.Src))
	assert.Equal(t, 1, len(s.Dst))

	// srcPod matches subject labels so will be granted to records one for FQDN name.
	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "2", "testNamespace", srcPodName, "testPod", srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(r1))
	assert.NotZero(t, r1[0].Src.NSID)
	assert.Equal(t, tetragon.EndpointType_ENDPOINT_TYPE_DNS, r1[0].Endpoint.EP.Type)
	assert.Equal(t, "test.io", r1[0].Endpoint.EP.Dns)
	assert.Equal(t, tetragon.EndpointType_ENDPOINT_TYPE_DNS, r1[1].Endpoint.EP.Type)
	assert.Equal(t, "test.com", r1[1].Endpoint.EP.Dns)

	// dstPod does not match subject so will have no FQDN records but will match endpoint
	// labels and srcPod needs to be given a record for the srcPod->dstPod pair.
	addPod(t, dstId, dstPodName, dstPodLabels)
	dstPod := testPod(t, "3", "testNamespace", dstPodName, "testPod", dstPodLabels)
	r2, err := s.objectAdd(dstPod)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(r2))
	assert.Equal(t, r1[0].Src.NSID, r2[0].Src.NSID)
	assert.Equal(t, tetragon.EndpointType_ENDPOINT_TYPE_POD, r2[0].Endpoint.EP.Type)
	assert.Equal(t, dstPodName, r2[0].Endpoint.EP.Name)

	addPod(t, dstIdKeep, dstPodNameKeep, dstPodLabels)
	dstPodKeep := testPod(t, "4", "testNamespace", dstPodNameKeep, "testPod", dstPodLabels)
	r3, err := s.objectAdd(dstPodKeep)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(r3))
	assert.Equal(t, r1[0].Src.NSID, r3[0].Src.NSID)
	assert.Equal(t, tetragon.EndpointType_ENDPOINT_TYPE_POD, r3[0].Endpoint.EP.Type)
	assert.Equal(t, dstPodNameKeep, r3[0].Endpoint.EP.Name)

	// Test matchLabels keys are tracking the subjects
	src := s.Src[netpol.PolicyUID]
	assert.NotNil(t, src)
	assert.Equal(t, 1, len(src.Subjects))
	assert.Equal(t, r1[0].Src.NSID, src.Subjects[0].NSID)

	// Test matchLAbelsDstPolicy is tracking endpoints
	dst := s.Dst[netpol.PolicyUID]
	assert.NotNil(t, dst)
	assert.Equal(t, 2, len(dst.Endpoints))
	assert.Equal(t, tetragon.EndpointType_ENDPOINT_TYPE_POD, dst.Endpoints[0].Type)
	assert.Equal(t, dstPodName, dst.Endpoints[0].Name)
	assert.Equal(t, "testNamespace", dst.Endpoints[0].Namespace)
	assert.Equal(t, "testPod", dst.Endpoints[0].Kind)

	// Deleting dstId pod will remove the Endpoints but because
	// its a subjects no change that will not change.
	delPod(t, dstId)
	deleted, err := s.podRemove(dstPod)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(dst.Endpoints))
	assert.Equal(t, 1, len(src.Subjects))
	assert.Equal(t, 1, len(deleted))

	// Interesting artifact is deleting duplicate twice
	// will build same endpoint recordSet.
	deleted, err = s.podRemove(dstPod)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(dst.Endpoints))
	assert.Equal(t, 1, len(src.Subjects))
	assert.Equal(t, 1, len(deleted))

	delPod(t, dstIdKeep)
	deleted, err = s.podRemove(dstPodKeep)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(dst.Endpoints))
	assert.Equal(t, 1, len(src.Subjects))
	assert.Equal(t, 1, len(deleted))

	delPod(t, srcId)
	deleted, err = s.podRemove(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(dst.Endpoints))
	assert.Equal(t, 0, len(src.Subjects))
	assert.Equal(t, 2, len(deleted))

	zombieSet, updateSet, err := s.recordsFromPolicyRemoval(netpol)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(zombieSet))
	assert.Equal(t, 0, len(updateSet))
}

func TestSrcPolicyAddsDefaultAction(t *testing.T) {
	s := NewPolicyState()
	name := "netpol"
	srcId := nextId()

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	netpol := testMatchDstLabelsDenyPolicy(name, srcPodLabels, dstPodLabels, "deny")
	err := s.CreateMatchLabelsPolicy(netpol)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(s.Src))
	assert.Equal(t, 1, len(s.Dst))

	// srcPod matches subject labels so will be granted to records one for default action
	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "2", "testNamespace", srcPodName, "testPod", srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(r1))

	assert.NotZero(t, r1[0].Src.NSID)
	assert.Equal(t, tetragon.EndpointType_ENDPOINT_TYPE_DNS, r1[0].Endpoint.EP.Type)
	assert.Equal(t, "test.io", r1[0].Endpoint.EP.Dns)
	assert.Equal(t, r1[0].Action.Action, record.PolicyDeny)

	assert.NotZero(t, r1[1].Src.NSID)
	assert.Equal(t, tetragon.EndpointType_ENDPOINT_TYPE_DNS, r1[1].Endpoint.EP.Type)
	assert.Equal(t, "test.com", r1[1].Endpoint.EP.Dns)
	assert.Equal(t, r1[1].Action.Action, record.PolicyDeny)

	assert.NotZero(t, r1[2].Src.NSID)
	assert.Nil(t, r1[2].Endpoint.EP)
	assert.Equal(t, r1[2].Action.Action, record.PolicyAllow)

	// Remove pod and policy
	delPod(t, srcId)
	deleted, err := s.podRemove(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(deleted))

	zombieSet, updateSet, err := s.recordsFromPolicyRemoval(netpol)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(zombieSet))
	assert.Equal(t, 0, len(updateSet))
}

// Test addPod again, but bring up subject after destinations are already loaded
func TestSrcPolicyAddsDefaultActionDstFirst(t *testing.T) {
	s := NewPolicyState()
	name := "netpol"
	srcId := nextId()
	dstId := nextId()

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	netpol := testMatchDstLabelsDenyPolicy(name, srcPodLabels, dstPodLabels, "allow")
	err := s.CreateMatchLabelsPolicy(netpol)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(s.Src))
	assert.Equal(t, 1, len(s.Dst))

	// add dst pod first which does not match a subject for any policy8
	addPod(t, dstId, dstPodName, dstPodLabels)
	dstPod := testPod(t, "3", "testNamespace", dstPodName, "testPod", dstPodLabels)
	rDst, err := s.objectAdd(dstPod)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(rDst)) // no records to program datapath bc not a subject

	// add src pod next and ensure we build correct policy
	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "2", "testNamespace", srcPodName, "testPod", srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 4, len(r1)) // program datapath now for subject->dst

	assert.NotZero(t, r1[0].Src.NSID)
	assert.Equal(t, tetragon.EndpointType_ENDPOINT_TYPE_DNS, r1[0].Endpoint.EP.Type)
	assert.Equal(t, "test.io", r1[0].Endpoint.EP.Dns)
	assert.Equal(t, r1[0].Action.Action, record.PolicyAllow)

	assert.NotZero(t, r1[1].Src.NSID)
	assert.Equal(t, tetragon.EndpointType_ENDPOINT_TYPE_DNS, r1[1].Endpoint.EP.Type)
	assert.Equal(t, "test.com", r1[1].Endpoint.EP.Dns)
	assert.Equal(t, r1[1].Action.Action, record.PolicyAllow)

	assert.NotZero(t, r1[2].Src.NSID)
	assert.Equal(t, tetragon.EndpointType_ENDPOINT_TYPE_POD, r1[2].Endpoint.EP.Type)
	assert.Equal(t, r1[2].Action.Action, record.PolicyAllow)

	assert.NotZero(t, r1[3].Src.NSID)
	assert.Nil(t, r1[3].Endpoint.EP)
	assert.Equal(t, r1[3].Action.Action, record.PolicyDeny)

	// Remove pod and policy
	delPod(t, dstId)
	deleted, err := s.podRemove(dstPod)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(deleted))

	// Remove pod and policy
	delPod(t, srcId)
	deleted, err = s.podRemove(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(deleted))

	zombieSet, updateSet, err := s.recordsFromPolicyRemoval(netpol)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(zombieSet))
	assert.Equal(t, 0, len(updateSet))
}

func TestPolicySet(t *testing.T) {
	s := NewPolicyState()
	SetRealizedState(s)
	name := "netpol"
	srcId := nextId()
	dstId := nextId()

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	netpol := testMatchDstLabelsDenyPolicy(name, srcPodLabels, dstPodLabels, "allow")
	netpolSet := []*types.TetragonNetworkPolicy{netpol}
	AddPolicies(netpolSet)
	// add dst pod first which does not match a subject for any policy8
	addPod(t, dstId, dstPodName, dstPodLabels)
	dstPod := testPod(t, "3", "testNamespace", dstPodName, "testPod", dstPodLabels)
	s = GetRealizedState()
	rDst, err := s.objectAdd(dstPod)
	assert.NoError(t, err)
	assert.Zero(t, len(rDst))

	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "2", "testNamespace", srcPodName, "testPod", srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 4, len(r1)) // program datapath now for subject->dst

	// Remove pod and policy
	delPod(t, dstId)
	deleted, err := s.podRemove(dstPod)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(deleted))

	// Remove pod and policy
	delPod(t, srcId)
	deleted, err = s.podRemove(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(deleted))

	err = RemovePolicies(netpolSet)
	assert.NoError(t, err)
}

func cntRecordsEPTypes(records []record.DatapathRecord) (int, int, int, int) {
	cntDnsType := 0
	cntPodType := 0
	cntCIDRType := 0
	cntNilType := 0
	for _, r := range records {
		if r.Endpoint.EP == nil {
			cntNilType++
			continue
		}
		if r.Endpoint.EP.Type == tetragon.EndpointType_ENDPOINT_TYPE_DNS {
			cntDnsType++
			continue
		}
		if r.Endpoint.EP.Type == tetragon.EndpointType_ENDPOINT_TYPE_POD {
			cntPodType++
			continue
		}
		if r.Endpoint.EP.Type == tetragon.EndpointType_ENDPOINT_TYPE_CIDR {
			cntCIDRType++
			continue
		}

	}

	return cntDnsType, cntPodType, cntCIDRType, cntNilType
}

func TestPolicySetWithPods(t *testing.T) {
	s := NewPolicyState()
	SetRealizedState(s)
	name := "netpol"
	srcId := nextId()
	dstId := nextId()

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	// Add src pod and dest pod while no policy is in play
	addPod(t, dstId, dstPodName, dstPodLabels)
	dstPod := testPod(t, "3", "testNamespace", dstPodName, "testPod", dstPodLabels)
	s = GetRealizedState()
	rDst, err := s.objectAdd(dstPod)
	assert.NoError(t, err)
	assert.Zero(t, len(rDst))

	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "2", "testNamespace", srcPodName, "testPod", srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(r1))

	// Add policy and ensure we generate rules
	netpol := testMatchDstLabelsDenyPolicy(name, srcPodLabels, dstPodLabels, "allow")
	netpolSet := []*types.TetragonNetworkPolicy{netpol}
	newState, addSet, removeSet, errSet := recordsFromPoliciesAddition(netpolSet)
	assert.NoError(t, errSet)
	assert.Equal(t, 4, len(addSet))
	assert.Zero(t, len(removeSet))
	cntDnsType, cntPodType, _, cntNilType := cntRecordsEPTypes(addSet)
	assert.Equal(t, cntDnsType, 2)
	assert.Equal(t, cntPodType, 1)
	assert.Equal(t, cntNilType, 1)

	// Remove pod and policy
	delPod(t, dstId)
	deleted, err := newState.podRemove(dstPod)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(deleted))

	// Remove pod and policy
	delPod(t, srcId)
	deleted, err = newState.podRemove(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(deleted))

	err = RemovePolicies(netpolSet)
	assert.NoError(t, err)
}

func TestPolicyOverlapping(t *testing.T) {
	s := NewPolicyState()
	SetRealizedState(s)

	srcId := nextId()
	dstId := nextId()
	indId := nextId()

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	indPodName := "testNamePodIndependent"
	indPodLabels := "C=c"

	// Add src pod and dest pod while no policy is in play
	addPod(t, dstId, dstPodName, dstPodLabels)
	dstPod := testPod(t, "3", "testNamespace", dstPodName, "testKind", dstPodLabels)
	s = GetRealizedState()
	rDst, err := s.objectAdd(dstPod)
	assert.NoError(t, err)
	assert.Zero(t, len(rDst))

	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "2", "testNamespace", srcPodName, "testKind", srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(r1))

	addPod(t, indId, indPodName, indPodLabels)
	indPod := testPod(t, "4", "testNamespace", indPodName, "testKind", indPodLabels)
	rind, err := s.objectAdd(indPod)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(rind))

	// Add policy and ensure we generate rules
	netpolA := testMatchDstLabelsDenyPolicy("netpolA", "A=a", dstPodLabels, "allow")
	netpolASet := []*types.TetragonNetworkPolicy{netpolA}
	aState, addASet, removeASet, err := recordsFromPoliciesAddition(netpolASet)
	assert.NoError(t, err)
	assert.Equal(t, 4, len(addASet))
	assert.Zero(t, len(removeASet))

	dns, pod, _, n := cntRecordsEPTypes(addASet)
	assert.Equal(t, dns, 2)
	assert.Equal(t, pod, 1)
	assert.Equal(t, n, 1)
	SetRealizedState(aState)

	// netpol B overlaps with netpol A except actoins are reversed.
	netpolB := testMatchDstLabelsDenyPolicy("netpolB", "B=b", dstPodLabels, "deny")
	netpolBSet := []*types.TetragonNetworkPolicy{netpolB}
	bState, addBSet, removeBSet, err := recordsFromPoliciesAddition(netpolBSet)
	assert.NoError(t, err)
	assert.Zero(t, len(removeBSet))
	assert.Equal(t, 8, len(addBSet))

	dns, pod, _, n = cntRecordsEPTypes(addBSet)
	assert.Equal(t, 4, dns)
	assert.Equal(t, 2, pod)
	assert.Equal(t, 2, n)
	SetRealizedState(bState)

	// Remove independent pod there should be no rules associated with this pod
	delPod(t, indId)
	deleted, err := bState.podRemove(indPod)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(deleted))

	// Remove destinatoin pod, should delete records from source->destination
	delPod(t, dstId)
	deleted, err = bState.podRemove(dstPod)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(deleted))

	// Remove source pod should delete remaining records for FQDN and defaults
	delPod(t, srcId)
	deleted, err = bState.podRemove(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 6, len(deleted)) // delete entries from both policy sources

	netpolSet := []*types.TetragonNetworkPolicy{netpolB, netpolA}
	err = RemovePolicies(netpolSet)
	assert.NoError(t, err)
	err = RemovePolicies(netpolSet)
	assert.NoError(t, err)
}

func TestPolicyOverlappingPolicyDelete(t *testing.T) {
	s := NewPolicyState()
	SetRealizedState(s)

	srcId := nextId()
	dstId := nextId()
	indId := nextId()

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	indPodName := "testNamePodIndependent"
	indPodLabels := "C=c"

	// Add src, dst, and ind pods while no policy is in play
	addPod(t, indId, indPodName, indPodLabels)
	indPod := testPod(t, "4", "testNamespace", indPodName, "testKind", indPodLabels)
	rind, err := s.objectAdd(indPod)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(rind))

	addPod(t, dstId, dstPodName, dstPodLabels)
	dstPod := testPod(t, "3", "testNamespace", dstPodName, "testKind", dstPodLabels)
	s = GetRealizedState()
	rDst, err := s.objectAdd(dstPod)
	assert.NoError(t, err)
	assert.Zero(t, len(rDst))

	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "2", "testNamespace", srcPodName, "testKind", srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(r1))

	// Add policy and ensure we generate rules
	netpolA := testMatchDstLabelsDenyPolicy("netpolA", "A=a", dstPodLabels, "allow")
	netpolASet := []*types.TetragonNetworkPolicy{netpolA}
	aState, addASet, removeASet, errSet := recordsFromPoliciesAddition(netpolASet)

	assert.NoError(t, errSet)
	assert.Equal(t, 4, len(addASet))
	assert.Zero(t, len(removeASet))

	dns, pod, _, n := cntRecordsEPTypes(addASet)
	assert.Equal(t, dns, 2)
	assert.Equal(t, pod, 1)
	assert.Equal(t, n, 1)
	SetRealizedState(aState)

	// netpol B overlaps with netpol A except actions are reversed.
	netpolB := testMatchDstLabelsDenyPolicy("netpolB", "B=b", dstPodLabels, "deny")
	netpolBSet := []*types.TetragonNetworkPolicy{netpolB}
	bState, addBSet, removeBSet, errSet := recordsFromPoliciesAddition(netpolBSet)
	assert.NoError(t, errSet)
	assert.Zero(t, len(removeBSet))
	assert.Equal(t, 8, len(addBSet))

	dns, pod, _, n = cntRecordsEPTypes(addBSet)
	assert.Equal(t, 4, dns)
	assert.Equal(t, 2, pod)
	assert.Equal(t, 2, n)
	SetRealizedState(bState)

	// netpol C does not overlap with A or B subjects.
	netpolC := testMatchDstLabelsDenyPolicy("netpolC", "C=c", dstPodLabels, "deny")
	netpolCSet := []*types.TetragonNetworkPolicy{netpolC}
	cState, addCSet, removeCSet, err := recordsFromPoliciesAddition(netpolCSet)
	assert.NoError(t, err)
	assert.Zero(t, len(removeCSet))
	assert.Equal(t, 12, len(addCSet))

	dns, pod, _, n = cntRecordsEPTypes(addCSet)
	assert.Equal(t, 6, dns)
	assert.Equal(t, 3, pod)
	assert.Equal(t, 3, n)
	SetRealizedState(cState)

	// netpol C does not overlap with netpol A remove it.
	cRemove, cUpdate, err := cState.recordsFromPolicyRemoval(netpolC)
	assert.NoError(t, err)
	// because these are entirely masked by policy A we do not remove anything
	assert.Equal(t, 4, len(cRemove))
	// however we need to update the rules to the new state.
	assert.Equal(t, 8, len(cUpdate))

	// netpol B overlaps with netpol A remove it.
	bRemove, bUpdate, err := cState.recordsFromPolicyRemoval(netpolB)
	assert.NoError(t, err)
	// because these are entirely masked by policy A we do not remove anything
	assert.Equal(t, 0, len(bRemove))
	// however we need to update the rules to the new state.
	assert.Equal(t, 4, len(bUpdate))

	// netpol A remains, remove it.
	aRemove, aUpdate, err := cState.recordsFromPolicyRemoval(netpolA)
	assert.NoError(t, err)
	assert.Equal(t, 4, len(aRemove))
	assert.Equal(t, 0, len(aUpdate))

	// Remove source pod there should be no more records
	delPod(t, srcId)
	deleted, err := cState.podRemove(srcPod)
	assert.NoError(t, err)
	assert.Zero(t, len(deleted))

	// Remove destination pod, should not be any records remaining
	delPod(t, dstId)
	deleted, err = cState.podRemove(dstPod)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(deleted))

	// Remove other pod, should not be any records remaining
	delPod(t, indId)
	deleted, err = cState.podRemove(indPod)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(deleted))
}

func TestDestSrcProcessPolicy(t *testing.T) {
	s := NewPolicyState()
	SetRealizedState(s)

	srcId := nextId()
	dstId := nextId()

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	// Add src pod and dest pod while no policy is in play
	addPod(t, dstId, dstPodName, dstPodLabels)
	dstPod := testPod(t, "3", "testNamespace", dstPodName, "testPod", dstPodLabels)

	s = GetRealizedState()
	rDst, err := s.objectAdd(dstPod)
	assert.NoError(t, err)
	assert.Zero(t, len(rDst))

	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "2", "testNamespace", srcPodName, "testPod", srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(r1))

	// Add policy and ensure we generate rules
	netpolA := testMatchDstProcessLabelsDenyPolicy("netpolA", "A=a", dstPodLabels, "allow")
	netpolASet := []*types.TetragonNetworkPolicy{netpolA}
	aState, addASet, removeASet, errSet := recordsFromPoliciesAddition(netpolASet)

	assert.NoError(t, errSet)
	// 3 records for /usr/bin/curl
	// 3 records for /usr/sbin/curl
	// 1 record for default pod
	assert.Equal(t, 7, len(addASet))
	assert.Zero(t, len(removeASet))

	dns, pod, _, n := cntRecordsEPTypes(addASet)
	// record entry for /usr/bin/curl -> {fqdn1, fqdn2}
	// record entry for /usr/sbin/curl -> {fqdn1, fqdn2}
	assert.Equal(t, dns, 4)
	// record entry for /usr/bin/curl  -> ep
	// record entry for /usr/sbin/curl -> ep
	assert.Equal(t, pod, 2)
	assert.Equal(t, n, 1)
	SetRealizedState(aState)

	// netpol A remains, remove it.
	aRemove, aUpdate, err := aState.recordsFromPolicyRemoval(netpolA)
	assert.NoError(t, err)
	assert.Equal(t, 7, len(aRemove))
	assert.Zero(t, len(aUpdate))

	// Remove source pod there should be no more records
	delPod(t, srcId)
	deleted, err := aState.podRemove(srcPod)
	assert.NoError(t, err)
	assert.Zero(t, len(deleted))

	// Remove destination pod, should not be any records remaining
	delPod(t, dstId)
	deleted, err = aState.podRemove(dstPod)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(deleted))
}

func TestSrcDestProcessPolicy(t *testing.T) {
	s := NewPolicyState()
	SetRealizedState(s)

	srcId := nextId()
	dstId := nextId()

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "2", "testNamespace", srcPodName, "testPod", srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(r1))

	// Add src pod and dest pod while no policy is in play
	addPod(t, dstId, dstPodName, dstPodLabels)
	dstPod := testPod(t, "3", "testNamespace", dstPodName, "testPod", dstPodLabels)

	s = GetRealizedState()
	rDst, err := s.objectAdd(dstPod)
	assert.NoError(t, err)
	assert.Zero(t, len(rDst))

	// Add policy and ensure we generate rules
	netpolA := testMatchDstProcessLabelsDenyPolicy("netpolA", "A=a", dstPodLabels, "allow")
	netpolASet := []*types.TetragonNetworkPolicy{netpolA}
	aState, addASet, removeASet, errSet := recordsFromPoliciesAddition(netpolASet)

	assert.NoError(t, errSet)
	// 3 records for /usr/bin/curl
	// 3 records for /usr/sbin/curl
	// 1 record for default pod
	assert.Equal(t, 7, len(addASet))
	assert.Zero(t, len(removeASet))

	dns, pod, _, n := cntRecordsEPTypes(addASet)
	// record entry for /usr/bin/curl -> {fqdn1, fqdn2}
	// record entry for /usr/sbin/curl -> {fqdn1, fqdn2}
	assert.Equal(t, dns, 4)
	// record entry for /usr/bin/curl  -> ep
	// record entry for /usr/sbin/curl -> ep
	assert.Equal(t, pod, 2)
	assert.Equal(t, n, 1)
	SetRealizedState(aState)

	// netpol A remains, remove it.
	aRemove, aUpdate, err := aState.recordsFromPolicyRemoval(netpolA)
	assert.NoError(t, err)
	assert.Equal(t, 7, len(aRemove))
	assert.Zero(t, len(aUpdate))

	// Remove source pod there should be no more records
	delPod(t, srcId)
	deleted, err := aState.podRemove(srcPod)
	assert.NoError(t, err)
	assert.Zero(t, len(deleted))

	// Remove destination pod, should not be any records remaining
	delPod(t, dstId)
	deleted, err = aState.podRemove(dstPod)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(deleted))
}

func TestProcessPolicySrcDest(t *testing.T) {
	s := NewPolicyState()
	SetRealizedState(s)

	srcId := nextId()
	dstId := nextId()

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	// Add policy and ensure we generate rules
	netpolA := testMatchDstProcessLabelsDenyPolicy("netpolZ", "A=a", dstPodLabels, "allow")
	netpolASet := []*types.TetragonNetworkPolicy{netpolA}
	aState, addASet, removeASet, errSet := recordsFromPoliciesAddition(netpolASet)

	assert.NoError(t, errSet)
	assert.Zero(t, len(addASet))
	assert.Zero(t, len(removeASet))

	// Add src pod and dest pod while no policy is in play
	addPod(t, dstId, dstPodName, dstPodLabels)
	dstPod := testPod(t, "3", "testNamespace", dstPodName, "testPod", dstPodLabels)
	SetRealizedState(aState)

	s = GetRealizedState()
	rDst, err := s.objectAdd(dstPod)
	assert.NoError(t, err)
	assert.Zero(t, len(rDst))

	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "2", "testNamespace", srcPodName, "testPod", srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 7, len(r1))

	dns, pod, _, n := cntRecordsEPTypes(r1)
	assert.Equal(t, 4, dns)
	assert.Equal(t, 2, pod)
	assert.Equal(t, 1, n)

	// netpol A remains, remove it.
	aRemove, aUpdate, err := aState.recordsFromPolicyRemoval(netpolA)
	assert.NoError(t, err)
	assert.Equal(t, 7, len(aRemove))
	assert.Zero(t, len(aUpdate))

	// Remove source pod there should be no more records
	delPod(t, srcId)
	deleted, err := aState.podRemove(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(deleted))

	// Remove destination pod, should not be any records remaining
	delPod(t, dstId)
	deleted, err = aState.podRemove(dstPod)
	assert.NoError(t, err)
	assert.Zero(t, len(deleted))
}

func TestProcessPolicyDestSrc(t *testing.T) {
	s := NewPolicyState()
	SetRealizedState(s)

	srcId := nextId()
	dstId := nextId()

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	// Add policy and ensure we generate rules
	netpolA := testMatchDstProcessLabelsDenyPolicy("netpolZ", "A=a", dstPodLabels, "allow")
	netpolASet := []*types.TetragonNetworkPolicy{netpolA}
	aState, addASet, removeASet, errSet := recordsFromPoliciesAddition(netpolASet)

	assert.NoError(t, errSet)
	assert.Zero(t, len(addASet))
	assert.Zero(t, len(removeASet))

	// Add dst pod and then src pod while no policy is in play
	SetRealizedState(aState)
	s = GetRealizedState()

	addPod(t, dstId, dstPodName, dstPodLabels)
	dstPod := testPod(t, "3", "testNamespace", dstPodName, "testPod", dstPodLabels)
	rDst, err := s.objectAdd(dstPod)
	assert.NoError(t, err)
	assert.Zero(t, len(rDst))

	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "2", "testNamespace", srcPodName, "testPod", srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 7, len(r1))

	dns, pod, _, n := cntRecordsEPTypes(r1)
	assert.Equal(t, 4, dns)
	assert.Equal(t, 2, pod)
	assert.Equal(t, 1, n)

	// netpol A remains, remove it.
	aRemove, aUpdate, err := aState.recordsFromPolicyRemoval(netpolA)
	assert.NoError(t, err)
	assert.Equal(t, 7, len(aRemove))
	assert.Zero(t, len(aUpdate))

	// Remove source pod there should be no more records
	delPod(t, srcId)
	deleted, err := aState.podRemove(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(deleted))

	// Remove destination pod, should not be any records remaining
	delPod(t, dstId)
	deleted, err = aState.podRemove(dstPod)
	assert.NoError(t, err)
	assert.Zero(t, len(deleted))
}

func TestProcessPortPolicyDestSrc(t *testing.T) {
	s := NewPolicyState()
	SetRealizedState(s)

	srcId := nextId()
	dstId := nextId()

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	// Add policy and ensure we generate rules
	netpolA := testMatchPortDstProcessLabelsDenyPolicy("netpolZ", "A=a", dstPodLabels, "allow")
	netpolASet := []*types.TetragonNetworkPolicy{netpolA}
	aState, addASet, removeASet, errSet := recordsFromPoliciesAddition(netpolASet)

	assert.NoError(t, errSet)
	assert.Zero(t, len(addASet))
	assert.Zero(t, len(removeASet))

	// Add dst pod and then src pod while no policy is in play
	SetRealizedState(aState)
	s = GetRealizedState()

	addPod(t, dstId, dstPodName, dstPodLabels)
	dstPod := testPod(t, "3", "testNamespace", dstPodName, "testPod", dstPodLabels)
	rDst, err := s.objectAdd(dstPod)
	assert.NoError(t, err)
	assert.Zero(t, len(rDst))

	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "2", "testNamespace", srcPodName, "testPod", srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 13, len(r1))

	port80 := 0
	port81 := 0
	for _, r := range r1 {
		if r.Endpoint.EP == nil {
			continue
		}
		if r.Endpoint.EP.Type == tetragon.EndpointType_ENDPOINT_TYPE_DNS {
			switch r.Endpoint.Port {
			case 80:
				port80++
			case 81:
				port81++
			}
			continue
		}
		if r.Endpoint.EP.Type == tetragon.EndpointType_ENDPOINT_TYPE_POD {
			switch r.Endpoint.Port {
			case 80:
				port80++
			case 81:
				port81++
			}
			continue
		}
	}
	assert.Equal(t, 6, port80)
	assert.Equal(t, 6, port81)

	dns, pod, _, n := cntRecordsEPTypes(r1)
	assert.Equal(t, 8, dns)
	assert.Equal(t, 4, pod)
	assert.Equal(t, 1, n)

	// netpol A remains, remove it.
	aRemove, aUpdate, err := aState.recordsFromPolicyRemoval(netpolA)
	assert.NoError(t, err)
	assert.Equal(t, 13, len(aRemove))
	assert.Zero(t, len(aUpdate))

	// Remove source pod there should be no more records
	delPod(t, srcId)
	deleted, err := aState.podRemove(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(deleted))

	// Remove destination pod, should not be any records remaining
	delPod(t, dstId)
	deleted, err = aState.podRemove(dstPod)
	assert.NoError(t, err)
	assert.Zero(t, len(deleted))
}

func countPorts(records []record.DatapathRecord, port uint32) int {
	cnt := 0

	for _, r := range records {
		if r.Endpoint.EP == nil {
			continue
		}
		if r.Endpoint.EP.Type == tetragon.EndpointType_ENDPOINT_TYPE_DNS {
			if r.Endpoint.Port == port {
				cnt++
			}
			continue
		}
		if r.Endpoint.EP.Type == tetragon.EndpointType_ENDPOINT_TYPE_POD {
			if r.Endpoint.Port == port {
				cnt++
			}
			continue
		}
	}
	return cnt
}

func TestProcessPortPolicySrcDest(t *testing.T) {
	s := NewPolicyState()
	SetRealizedState(s)

	srcId := nextId()
	dstId := nextId()

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	// Add policy and ensure we generate rules
	netpolA := testMatchPortDstProcessLabelsDenyPolicy("netpolZ", "A=a", dstPodLabels, "allow")
	netpolASet := []*types.TetragonNetworkPolicy{netpolA}
	aState, addASet, removeASet, errSet := recordsFromPoliciesAddition(netpolASet)

	assert.NoError(t, errSet)
	assert.Zero(t, len(addASet))
	assert.Zero(t, len(removeASet))

	// Add dst pod and then src pod while no policy is in play
	SetRealizedState(aState)
	s = GetRealizedState()

	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "2", "testNamespace", srcPodName, "testPod", srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 9, len(r1))

	dns, pod, _, n := cntRecordsEPTypes(r1)
	assert.Equal(t, 8, dns)
	assert.Equal(t, 0, pod)
	assert.Equal(t, 1, n)

	port80 := countPorts(r1, 80)
	port81 := countPorts(r1, 81)

	assert.Equal(t, 4, port80)
	assert.Equal(t, 4, port81)

	addPod(t, dstId, dstPodName, dstPodLabels)
	dstPod := testPod(t, "3", "testNamespace", dstPodName, "testPod", dstPodLabels)
	rDst, err := s.objectAdd(dstPod)
	assert.NoError(t, err)
	assert.Equal(t, 4, len(rDst))

	port80 = countPorts(rDst, 80)
	port81 = countPorts(rDst, 81)
	assert.Equal(t, 2, port80)
	assert.Equal(t, 2, port81)

	dns, pod, _, n = cntRecordsEPTypes(rDst)
	assert.Equal(t, 0, dns)
	assert.Equal(t, 4, pod)
	assert.Equal(t, 0, n)

	// netpol A remains, remove it.
	aRemove, aUpdate, err := aState.recordsFromPolicyRemoval(netpolA)
	assert.NoError(t, err)
	assert.Equal(t, 13, len(aRemove))
	assert.Zero(t, len(aUpdate))

	dns, pod, _, n = cntRecordsEPTypes(aRemove)
	assert.Equal(t, 8, dns)
	assert.Equal(t, 4, pod)
	assert.Equal(t, 1, n)

	port80 = countPorts(aRemove, 80)
	port81 = countPorts(aRemove, 81)
	assert.Equal(t, 6, port80)
	assert.Equal(t, 6, port81)

	// Remove source pod there should be no more records
	delPod(t, srcId)
	deleted, err := aState.podRemove(srcPod)
	assert.NoError(t, err)
	assert.Zero(t, len(deleted))

	// Remove destination pod, should not be any records remaining
	delPod(t, dstId)
	deleted, err = aState.podRemove(dstPod)
	assert.NoError(t, err)
	assert.Zero(t, len(deleted))
}

func TestProcessCIDRPolicySrcDest(t *testing.T) {
	s := NewPolicyState()
	SetRealizedState(s)

	srcId := nextId()
	dstId := nextId()

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	// Add policy and ensure we generate rules
	netpolA := testMatchPortCIDRDstProcessLabelsDenyPolicy("netpolZ", "A=a", dstPodLabels, "allow", "10.0.0.1/16")
	netpolASet := []*types.TetragonNetworkPolicy{netpolA}
	aState, addASet, removeASet, errSet := recordsFromPoliciesAddition(netpolASet)

	assert.NoError(t, errSet)
	assert.Zero(t, len(addASet))
	assert.Zero(t, len(removeASet))

	// Add dst pod and then src pod while no policy is in play
	SetRealizedState(aState)
	s = GetRealizedState()

	addPod(t, srcId, srcPodName, srcPodLabels)
	srcPod := testPod(t, "2", "testNamespace", srcPodName, "testPod", srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	assert.NoError(t, err)
	assert.Equal(t, 13, len(r1))

	dns, pod, cidr, n := cntRecordsEPTypes(r1)
	assert.Equal(t, 8, dns)
	assert.Equal(t, 0, pod)
	assert.Equal(t, 4, cidr)
	assert.Equal(t, 1, n)

	port80 := countPorts(r1, 80)
	port81 := countPorts(r1, 81)

	assert.Equal(t, 4, port80)
	assert.Equal(t, 4, port81)

	addPod(t, dstId, dstPodName, dstPodLabels)
	dstPod := testPod(t, "3", "testNamespace", dstPodName, "testPod", dstPodLabels)
	rDst, err := s.objectAdd(dstPod)
	assert.NoError(t, err)
	assert.Equal(t, 4, len(rDst))

	port80 = countPorts(rDst, 80)
	port81 = countPorts(rDst, 81)
	assert.Equal(t, 2, port80)
	assert.Equal(t, 2, port81)

	dns, pod, cidr, n = cntRecordsEPTypes(rDst)
	assert.Equal(t, 0, dns)
	assert.Equal(t, 4, pod)
	assert.Equal(t, 0, cidr)
	assert.Equal(t, 0, n)

	// netpol A remains, remove it.
	aRemove, aUpdate, err := aState.recordsFromPolicyRemoval(netpolA)
	assert.NoError(t, err)
	assert.Equal(t, 17, len(aRemove))
	assert.Zero(t, len(aUpdate))

	dns, pod, cidr, n = cntRecordsEPTypes(aRemove)
	assert.Equal(t, 8, dns)
	assert.Equal(t, 4, pod)
	assert.Equal(t, 4, cidr)
	assert.Equal(t, 1, n)

	port80 = countPorts(aRemove, 80)
	port81 = countPorts(aRemove, 81)
	assert.Equal(t, 6, port80)
	assert.Equal(t, 6, port81)

	// Remove source pod there should be no more records
	delPod(t, srcId)
	deleted, err := aState.podRemove(srcPod)
	assert.NoError(t, err)
	assert.Zero(t, len(deleted))

	// Remove destination pod, should not be any records remaining
	delPod(t, dstId)
	deleted, err = aState.podRemove(dstPod)
	assert.NoError(t, err)
	assert.Zero(t, len(deleted))
}
