// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !nok8s && sudo_tests

package netpolstate

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stype "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/model/datapath"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/workloadid"
)

const (
	testNamespace = "testNamespace"
	testKind      = "testKind"
)

// This was useful when using the policy filter, this could be cleaned up
// eventually
func delPod(t *testing.T) {
	t.Helper()

	// Shouldn't do anything as the workloadid can never delete entries for now
}

// registerWorkloadID registers the workload in the cgroup ID to workload ID
// mapping like we would on the event of a creation of a new Pod from cluster.
func registerWorkloadID(t *testing.T, s *PolicyState, ns, name, kind string) {
	t.Helper()
	err := s.deps.workloadID.Update(
		workloadid.WorkloadMeta{
			Namespace: ns,
			Workload:  name,
			Kind:      kind,
		},
		workloadid.CgroupID(0x2),
	)
	require.NoError(t, err)
}

// newPodFromCluster creates a new fake Pod like we would receive from the API,
// it also registers the workload fake workload ID.
func newPodFromCluster(t *testing.T, s *PolicyState, ns, name, kind, matchLabels string) *v1alpha1.PodInfo {
	t.Helper()

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

	registerWorkloadID(t, s, ns, name, kind)

	return &v1alpha1.PodInfo{
		WorkloadType:   ty,
		WorkloadObject: wl,
		ObjectMeta:     meta,
	}
}

// fakeK8sReader is a mock implementation of client.Reader for testing
type fakeK8sReader struct{}

func (f *fakeK8sReader) Get(_ context.Context, key client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
	// For namespace lookups, return a basic namespace object
	if ns, ok := obj.(*corev1.Namespace); ok {
		ns.Name = key.Name
		ns.Labels = map[string]string{
			"kubernetes.io/metadata.name": key.Name,
		}
		return nil
	}
	return nil
}

func (f *fakeK8sReader) List(_ context.Context, _ client.ObjectList, _ ...client.ListOption) error {
	return nil
}

func newFakeExternalDeps(t *testing.T) externalDeps {
	t.Helper()
	return externalDeps{
		prog:       &datapath.DummyBpfProgrammer{},
		workloadID: workloadid.NewFakeState(t),
		k8sReader:  &fakeK8sReader{},
	}
}

func newTestPolicyState(t *testing.T) *PolicyState {
	t.Helper()
	s := NewPolicyState()
	s.deps = newFakeExternalDeps(t)
	return s
}

// This tests assumes WorkloadID space is incrementing every addPolicyFilter
// which allows us to check cgroupID
func TestSrcKeyLookup(t *testing.T) {
	s := newTestPolicyState(t)

	registerWorkloadID(t, s, testNamespace, "test1", testKind)
	registerWorkloadID(t, s, testNamespace, "test2", testKind)

	key, err := s.deps.createSrcKey(testNamespace, "test1", testKind)
	require.NoError(t, err)
	assert.NotNil(t, key)
	assert.NotZero(t, key.WLID)

	key, err = s.deps.createSrcKey(testNamespace, "test2", testKind)
	require.NoError(t, err)
	assert.NotNil(t, key)
	assert.NotZero(t, key.WLID)

	delPod(t)
	delPod(t)
}

func TestCheckMatchLabelsPolicy(t *testing.T) {
	s := newTestPolicyState(t)
	name := "netpol"

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	dstPodNameKeep := "testNamePodDstKeep"

	netpol := testMatchDstLabelsPolicy(name, srcPodLabels, dstPodLabels)
	err := s.CreateMatchLabelsPolicy(netpol)
	require.NoError(t, err)
	assert.Equal(t, 1, len(s.Src))
	assert.Equal(t, 1, len(s.Dst))

	// srcPod matches subject labels so will be granted to records one for FQDN name.
	srcPod := newPodFromCluster(t, s, testNamespace, srcPodName, testKind, srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	require.NoError(t, err)
	assert.Equal(t, 3, len(r1))
	assert.NotZero(t, r1[0].Src.WLID)
	assert.Equal(t, tetragon.EndpointType_ENDPOINT_TYPE_DNS, r1[0].Endpoint.EP.Type)
	assert.Equal(t, "test.io", r1[0].Endpoint.EP.Dns)
	assert.Equal(t, tetragon.EndpointType_ENDPOINT_TYPE_DNS, r1[1].Endpoint.EP.Type)
	assert.Equal(t, "test.com", r1[1].Endpoint.EP.Dns)

	// dstPod does not match subject so will have no FQDN records but will match endpoint
	// labels and srcPod needs to be given a record for the srcPod->dstPod pair.
	dstPod := newPodFromCluster(t, s, testNamespace, dstPodName, testKind, dstPodLabels)
	r2, err := s.objectAdd(dstPod)
	require.NoError(t, err)
	assert.Equal(t, 1, len(r2))
	assert.Equal(t, r1[0].Src.WLID, r2[0].Src.WLID)
	assert.Equal(t, tetragon.EndpointType_ENDPOINT_TYPE_POD, r2[0].Endpoint.EP.Type)
	assert.Equal(t, dstPodName, r2[0].Endpoint.EP.Name)

	dstPodKeep := newPodFromCluster(t, s, testNamespace, dstPodNameKeep, testKind, dstPodLabels)
	r3, err := s.objectAdd(dstPodKeep)
	require.NoError(t, err)
	assert.Equal(t, 1, len(r3))
	assert.Equal(t, r1[0].Src.WLID, r3[0].Src.WLID)
	assert.Equal(t, tetragon.EndpointType_ENDPOINT_TYPE_POD, r3[0].Endpoint.EP.Type)
	assert.Equal(t, dstPodNameKeep, r3[0].Endpoint.EP.Name)

	// Test matchLabels keys are tracking the subjects
	src := s.Src[netpol.PolicyUID]
	assert.NotNil(t, src)
	assert.Equal(t, 1, len(src.Subjects))
	assert.Equal(t, r1[0].Src.WLID, src.Subjects[0].WLID)

	// Test matchLAbelsDstPolicy is tracking endpoints
	dst := s.Dst[netpol.PolicyUID]
	assert.NotNil(t, dst)
	assert.Equal(t, 2, len(dst.Endpoints))
	assert.Equal(t, tetragon.EndpointType_ENDPOINT_TYPE_POD, dst.Endpoints[0].Type)
	assert.Equal(t, dstPodName, dst.Endpoints[0].Name)
	assert.Equal(t, testNamespace, dst.Endpoints[0].Namespace)
	assert.Equal(t, testKind, dst.Endpoints[0].Kind)

	// Deleting dstId pod will remove the Endpoints but because
	// its a subjects no change that will not change.
	delPod(t)
	deleted, err := s.podRemove(dstPod)
	require.NoError(t, err)
	assert.Equal(t, 1, len(dst.Endpoints))
	assert.Equal(t, 1, len(src.Subjects))
	assert.Equal(t, 1, len(deleted))

	// Interesting artifact is deleting duplicate twice
	// will build same endpoint recordSet.
	deleted, err = s.podRemove(dstPod)
	require.NoError(t, err)
	assert.Equal(t, 1, len(dst.Endpoints))
	assert.Equal(t, 1, len(src.Subjects))
	assert.Equal(t, 1, len(deleted))

	delPod(t)
	deleted, err = s.podRemove(dstPodKeep)
	require.NoError(t, err)
	assert.Equal(t, 0, len(dst.Endpoints))
	assert.Equal(t, 1, len(src.Subjects))
	assert.Equal(t, 1, len(deleted))

	delPod(t)
	deleted, err = s.podRemove(srcPod)
	require.NoError(t, err)
	assert.Equal(t, 0, len(dst.Endpoints))
	assert.Equal(t, 0, len(src.Subjects))
	assert.Equal(t, 2, len(deleted))

	zombieSet, updateSet, err := s.recordsFromPolicyRemoval(netpol)
	require.NoError(t, err)
	assert.Equal(t, 0, len(zombieSet))
	assert.Equal(t, 0, len(updateSet))
}

func TestSrcPolicyAddsDefaultAction(t *testing.T) {
	s := newTestPolicyState(t)
	name := "netpol"

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	netpol := testMatchDstLabelsDenyPolicy(name, srcPodLabels, dstPodLabels, "deny")
	err := s.CreateMatchLabelsPolicy(netpol)
	require.NoError(t, err)
	assert.Equal(t, 1, len(s.Src))
	assert.Equal(t, 1, len(s.Dst))

	// srcPod matches subject labels so will be granted to records one for default action
	srcPod := newPodFromCluster(t, s, testNamespace, srcPodName, testKind, srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	require.NoError(t, err)
	assert.Equal(t, 3, len(r1))

	assert.NotZero(t, r1[0].Src.WLID)
	assert.Equal(t, tetragon.EndpointType_ENDPOINT_TYPE_DNS, r1[0].Endpoint.EP.Type)
	assert.Equal(t, "test.io", r1[0].Endpoint.EP.Dns)
	assert.Equal(t, r1[0].Action.Action, record.PolicyDeny)

	assert.NotZero(t, r1[1].Src.WLID)
	assert.Equal(t, tetragon.EndpointType_ENDPOINT_TYPE_DNS, r1[1].Endpoint.EP.Type)
	assert.Equal(t, "test.com", r1[1].Endpoint.EP.Dns)
	assert.Equal(t, r1[1].Action.Action, record.PolicyDeny)

	assert.NotZero(t, r1[2].Src.WLID)
	assert.Nil(t, r1[2].Endpoint.EP)
	assert.Equal(t, r1[2].Action.Action, record.PolicyAllow)

	// Remove pod and policy
	delPod(t)
	deleted, err := s.podRemove(srcPod)
	require.NoError(t, err)
	assert.Equal(t, 3, len(deleted))

	zombieSet, updateSet, err := s.recordsFromPolicyRemoval(netpol)
	require.NoError(t, err)
	assert.Equal(t, 0, len(zombieSet))
	assert.Equal(t, 0, len(updateSet))
}

// Test addPod again, but bring up subject after destinations are already loaded
func TestSrcPolicyAddsDefaultActionDstFirst(t *testing.T) {
	s := newTestPolicyState(t)
	name := "netpol"

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	netpol := testMatchDstLabelsDenyPolicy(name, srcPodLabels, dstPodLabels, "allow")
	err := s.CreateMatchLabelsPolicy(netpol)
	require.NoError(t, err)
	assert.Equal(t, 1, len(s.Src))
	assert.Equal(t, 1, len(s.Dst))

	// add dst pod first which does not match a subject for any policy8
	dstPod := newPodFromCluster(t, s, testNamespace, dstPodName, testKind, dstPodLabels)
	rDst, err := s.objectAdd(dstPod)
	require.NoError(t, err)
	assert.Equal(t, 0, len(rDst)) // no records to program datapath bc not a subject

	// add src pod next and ensure we build correct policy
	srcPod := newPodFromCluster(t, s, testNamespace, srcPodName, testKind, srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	require.NoError(t, err)
	assert.Equal(t, 4, len(r1)) // program datapath now for subject->dst

	assert.NotZero(t, r1[0].Src.WLID)
	assert.Equal(t, tetragon.EndpointType_ENDPOINT_TYPE_DNS, r1[0].Endpoint.EP.Type)
	assert.Equal(t, "test.io", r1[0].Endpoint.EP.Dns)
	assert.Equal(t, r1[0].Action.Action, record.PolicyAllow)

	assert.NotZero(t, r1[1].Src.WLID)
	assert.Equal(t, tetragon.EndpointType_ENDPOINT_TYPE_DNS, r1[1].Endpoint.EP.Type)
	assert.Equal(t, "test.com", r1[1].Endpoint.EP.Dns)
	assert.Equal(t, r1[1].Action.Action, record.PolicyAllow)

	assert.NotZero(t, r1[2].Src.WLID)
	assert.Equal(t, tetragon.EndpointType_ENDPOINT_TYPE_POD, r1[2].Endpoint.EP.Type)
	assert.Equal(t, r1[2].Action.Action, record.PolicyAllow)

	assert.NotZero(t, r1[3].Src.WLID)
	assert.Nil(t, r1[3].Endpoint.EP)
	assert.Equal(t, r1[3].Action.Action, record.PolicyDeny)

	// Remove pod and policy
	delPod(t)
	deleted, err := s.podRemove(dstPod)
	require.NoError(t, err)
	assert.Equal(t, 1, len(deleted))

	// Remove pod and policy
	delPod(t)
	deleted, err = s.podRemove(srcPod)
	require.NoError(t, err)
	assert.Equal(t, 3, len(deleted))

	zombieSet, updateSet, err := s.recordsFromPolicyRemoval(netpol)
	require.NoError(t, err)
	assert.Equal(t, 0, len(zombieSet))
	assert.Equal(t, 0, len(updateSet))
}

func TestPolicySet(t *testing.T) {
	s := newTestPolicyState(t)
	name := "netpol"

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	netpol := testMatchDstLabelsDenyPolicy(name, srcPodLabels, dstPodLabels, "allow")
	netpolSet := []*types.TetragonNetworkPolicy{netpol}
	err := s.AddPolicies(netpolSet)
	require.NoError(t, err)
	// add dst pod first which does not match a subject for any policy8
	dstPod := newPodFromCluster(t, s, testNamespace, dstPodName, testKind, dstPodLabels)
	rDst, err := s.objectAdd(dstPod)
	require.NoError(t, err)
	assert.Zero(t, len(rDst))

	srcPod := newPodFromCluster(t, s, testNamespace, srcPodName, testKind, srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	require.NoError(t, err)
	assert.Equal(t, 4, len(r1)) // program datapath now for subject->dst

	// Remove pod and policy
	delPod(t)
	deleted, err := s.podRemove(dstPod)
	require.NoError(t, err)
	assert.Equal(t, 1, len(deleted))

	// Remove pod and policy
	delPod(t)
	deleted, err = s.podRemove(srcPod)
	require.NoError(t, err)
	assert.Equal(t, 3, len(deleted))

	err = s.RemovePolicies(netpolSet)
	require.NoError(t, err)
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
	s := newTestPolicyState(t)
	name := "netpol"

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	// Add src pod and dest pod while no policy is in play
	dstPod := newPodFromCluster(t, s, testNamespace, dstPodName, testKind, dstPodLabels)
	rDst, err := s.objectAdd(dstPod)
	require.NoError(t, err)
	assert.Zero(t, len(rDst))

	srcPod := newPodFromCluster(t, s, testNamespace, srcPodName, testKind, srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	require.NoError(t, err)
	assert.Equal(t, 0, len(r1))

	// Add policy and ensure we generate rules
	netpol := testMatchDstLabelsDenyPolicy(name, srcPodLabels, dstPodLabels, "allow")
	netpolSet := []*types.TetragonNetworkPolicy{netpol}
	newState, addSet, removeSet, errSet := s.recordsFromPoliciesAddition(netpolSet)
	require.NoError(t, errSet)
	assert.Equal(t, 4, len(addSet))
	assert.Zero(t, len(removeSet))
	cntDnsType, cntPodType, _, cntNilType := cntRecordsEPTypes(addSet)
	assert.Equal(t, cntDnsType, 2)
	assert.Equal(t, cntPodType, 1)
	assert.Equal(t, cntNilType, 1)

	// Remove pod and policy
	delPod(t)
	deleted, err := newState.podRemove(dstPod)
	require.NoError(t, err)
	assert.Equal(t, 1, len(deleted))

	// Remove pod and policy
	delPod(t)
	deleted, err = newState.podRemove(srcPod)
	require.NoError(t, err)
	assert.Equal(t, 3, len(deleted))

	err = newState.RemovePolicies(netpolSet)
	require.NoError(t, err)
}

func TestPolicyOverlapping(t *testing.T) {
	s := newTestPolicyState(t)

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	indPodName := "testNamePodIndependent"
	indPodLabels := "C=c"

	// Add src pod and dest pod while no policy is in play
	dstPod := newPodFromCluster(t, s, testNamespace, dstPodName, testKind, dstPodLabels)
	rDst, err := s.objectAdd(dstPod)
	require.NoError(t, err)
	assert.Zero(t, len(rDst))

	srcPod := newPodFromCluster(t, s, testNamespace, srcPodName, testKind, srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	require.NoError(t, err)
	assert.Equal(t, 0, len(r1))

	indPod := newPodFromCluster(t, s, testNamespace, indPodName, testKind, indPodLabels)
	rind, err := s.objectAdd(indPod)
	require.NoError(t, err)
	assert.Equal(t, 0, len(rind))

	// Add policy and ensure we generate rules
	netpolA := testMatchDstLabelsDenyPolicy("netpolA", "A=a", dstPodLabels, "allow")
	netpolASet := []*types.TetragonNetworkPolicy{netpolA}
	aState, addASet, removeASet, err := s.recordsFromPoliciesAddition(netpolASet)
	require.NoError(t, err)
	assert.Equal(t, 4, len(addASet))
	assert.Zero(t, len(removeASet))

	dns, pod, _, n := cntRecordsEPTypes(addASet)
	assert.Equal(t, dns, 2)
	assert.Equal(t, pod, 1)
	assert.Equal(t, n, 1)

	// netpol B overlaps with netpol A except actoins are reversed.
	netpolB := testMatchDstLabelsDenyPolicy("netpolB", "B=b", dstPodLabels, "deny")
	netpolBSet := []*types.TetragonNetworkPolicy{netpolB}
	bState, addBSet, removeBSet, err := aState.recordsFromPoliciesAddition(netpolBSet)
	require.NoError(t, err)
	assert.Zero(t, len(removeBSet))
	assert.Equal(t, 8, len(addBSet))

	dns, pod, _, n = cntRecordsEPTypes(addBSet)
	assert.Equal(t, 4, dns)
	assert.Equal(t, 2, pod)
	assert.Equal(t, 2, n)

	// Remove independent pod there should be no rules associated with this pod
	delPod(t)
	deleted, err := bState.podRemove(indPod)
	require.NoError(t, err)
	assert.Equal(t, 0, len(deleted))

	// Remove destinatoin pod, should delete records from source->destination
	delPod(t)
	deleted, err = bState.podRemove(dstPod)
	require.NoError(t, err)
	assert.Equal(t, 2, len(deleted))

	// Remove source pod should delete remaining records for FQDN and defaults
	delPod(t)
	deleted, err = bState.podRemove(srcPod)
	require.NoError(t, err)
	assert.Equal(t, 6, len(deleted)) // delete entries from both policy sources

	netpolSet := []*types.TetragonNetworkPolicy{netpolB, netpolA}
	err = s.RemovePolicies(netpolSet)
	require.NoError(t, err)
	err = s.RemovePolicies(netpolSet)
	require.NoError(t, err)
}

func TestPolicyOverlappingPolicyDelete(t *testing.T) {
	s := newTestPolicyState(t)

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	indPodName := "testNamePodIndependent"
	indPodLabels := "C=c"

	// Add src, dst, and ind pods while no policy is in play
	indPod := newPodFromCluster(t, s, testNamespace, indPodName, testKind, indPodLabels)
	rind, err := s.objectAdd(indPod)
	require.NoError(t, err)
	assert.Equal(t, 0, len(rind))

	dstPod := newPodFromCluster(t, s, testNamespace, dstPodName, testKind, dstPodLabels)
	rDst, err := s.objectAdd(dstPod)
	require.NoError(t, err)
	assert.Zero(t, len(rDst))

	srcPod := newPodFromCluster(t, s, testNamespace, srcPodName, testKind, srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	require.NoError(t, err)
	assert.Equal(t, 0, len(r1))

	// Add policy and ensure we generate rules
	netpolA := testMatchDstLabelsDenyPolicy("netpolA", "A=a", dstPodLabels, "allow")
	netpolASet := []*types.TetragonNetworkPolicy{netpolA}
	aState, addASet, removeASet, errSet := s.recordsFromPoliciesAddition(netpolASet)

	require.NoError(t, errSet)
	assert.Equal(t, 4, len(addASet))
	assert.Zero(t, len(removeASet))

	dns, pod, _, n := cntRecordsEPTypes(addASet)
	assert.Equal(t, dns, 2)
	assert.Equal(t, pod, 1)
	assert.Equal(t, n, 1)

	// netpol B overlaps with netpol A except actions are reversed.
	netpolB := testMatchDstLabelsDenyPolicy("netpolB", "B=b", dstPodLabels, "deny")
	netpolBSet := []*types.TetragonNetworkPolicy{netpolB}
	bState, addBSet, removeBSet, errSet := aState.recordsFromPoliciesAddition(netpolBSet)
	require.NoError(t, errSet)
	assert.Zero(t, len(removeBSet))
	assert.Equal(t, 8, len(addBSet))

	dns, pod, _, n = cntRecordsEPTypes(addBSet)
	assert.Equal(t, 4, dns)
	assert.Equal(t, 2, pod)
	assert.Equal(t, 2, n)

	// netpol C does not overlap with A or B subjects.
	netpolC := testMatchDstLabelsDenyPolicy("netpolC", "C=c", dstPodLabels, "deny")
	netpolCSet := []*types.TetragonNetworkPolicy{netpolC}
	cState, addCSet, removeCSet, err := bState.recordsFromPoliciesAddition(netpolCSet)
	require.NoError(t, err)
	assert.Zero(t, len(removeCSet))
	assert.Equal(t, 12, len(addCSet))

	dns, pod, _, n = cntRecordsEPTypes(addCSet)
	assert.Equal(t, 6, dns)
	assert.Equal(t, 3, pod)
	assert.Equal(t, 3, n)

	// netpol C does not overlap with netpol A remove it.
	cRemove, cUpdate, err := cState.recordsFromPolicyRemoval(netpolC)
	require.NoError(t, err)
	// because these are entirely masked by policy A we do not remove anything
	assert.Equal(t, 4, len(cRemove))
	// however we need to update the rules to the new state.
	assert.Equal(t, 8, len(cUpdate))

	// netpol B overlaps with netpol A remove it.
	bRemove, bUpdate, err := cState.recordsFromPolicyRemoval(netpolB)
	require.NoError(t, err)
	// because these are entirely masked by policy A we do not remove anything
	assert.Equal(t, 0, len(bRemove))
	// however we need to update the rules to the new state.
	assert.Equal(t, 4, len(bUpdate))

	// netpol A remains, remove it.
	aRemove, aUpdate, err := cState.recordsFromPolicyRemoval(netpolA)
	require.NoError(t, err)
	assert.Equal(t, 4, len(aRemove))
	assert.Equal(t, 0, len(aUpdate))

	// Remove source pod there should be no more records
	delPod(t)
	deleted, err := cState.podRemove(srcPod)
	require.NoError(t, err)
	assert.Zero(t, len(deleted))

	// Remove destination pod, should not be any records remaining
	delPod(t)
	deleted, err = cState.podRemove(dstPod)
	require.NoError(t, err)
	assert.Equal(t, 0, len(deleted))

	// Remove other pod, should not be any records remaining
	delPod(t)
	deleted, err = cState.podRemove(indPod)
	require.NoError(t, err)
	assert.Equal(t, 0, len(deleted))
}

func TestDestSrcProcessPolicy(t *testing.T) {
	s := newTestPolicyState(t)

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	// Add src pod and dest pod while no policy is in play
	dstPod := newPodFromCluster(t, s, testNamespace, dstPodName, testKind, dstPodLabels)

	rDst, err := s.objectAdd(dstPod)
	require.NoError(t, err)
	assert.Zero(t, len(rDst))

	srcPod := newPodFromCluster(t, s, testNamespace, srcPodName, testKind, srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	require.NoError(t, err)
	assert.Equal(t, 0, len(r1))

	// Add policy and ensure we generate rules
	netpolA := testMatchDstProcessLabelsDenyPolicy("netpolA", "A=a", dstPodLabels, "allow")
	netpolASet := []*types.TetragonNetworkPolicy{netpolA}
	aState, addASet, removeASet, errSet := s.recordsFromPoliciesAddition(netpolASet)

	require.NoError(t, errSet)
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

	// netpol A remains, remove it.
	aRemove, aUpdate, err := aState.recordsFromPolicyRemoval(netpolA)
	require.NoError(t, err)
	assert.Equal(t, 7, len(aRemove))
	assert.Zero(t, len(aUpdate))

	// Remove source pod there should be no more records
	delPod(t)
	deleted, err := aState.podRemove(srcPod)
	require.NoError(t, err)
	assert.Zero(t, len(deleted))

	// Remove destination pod, should not be any records remaining
	delPod(t)
	deleted, err = aState.podRemove(dstPod)
	require.NoError(t, err)
	assert.Equal(t, 0, len(deleted))
}

func TestSrcDestProcessPolicy(t *testing.T) {
	s := newTestPolicyState(t)

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	srcPod := newPodFromCluster(t, s, testNamespace, srcPodName, testKind, srcPodLabels)
	r1, err := s.objectAdd(srcPod)
	require.NoError(t, err)
	assert.Equal(t, 0, len(r1))

	// Add src pod and dest pod while no policy is in play
	dstPod := newPodFromCluster(t, s, testNamespace, dstPodName, testKind, dstPodLabels)

	rDst, err := s.objectAdd(dstPod)
	require.NoError(t, err)
	assert.Zero(t, len(rDst))

	// Add policy and ensure we generate rules
	netpolA := testMatchDstProcessLabelsDenyPolicy("netpolA", "A=a", dstPodLabels, "allow")
	netpolASet := []*types.TetragonNetworkPolicy{netpolA}
	aState, addASet, removeASet, errSet := s.recordsFromPoliciesAddition(netpolASet)

	require.NoError(t, errSet)
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

	// netpol A remains, remove it.
	aRemove, aUpdate, err := aState.recordsFromPolicyRemoval(netpolA)
	require.NoError(t, err)
	assert.Equal(t, 7, len(aRemove))
	assert.Zero(t, len(aUpdate))

	// Remove source pod there should be no more records
	delPod(t)
	deleted, err := aState.podRemove(srcPod)
	require.NoError(t, err)
	assert.Zero(t, len(deleted))

	// Remove destination pod, should not be any records remaining
	delPod(t)
	deleted, err = aState.podRemove(dstPod)
	require.NoError(t, err)
	assert.Equal(t, 0, len(deleted))
}

func TestProcessPolicySrcDest(t *testing.T) {
	s := newTestPolicyState(t)

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	// Add policy and ensure we generate rules
	netpolA := testMatchDstProcessLabelsDenyPolicy("netpolZ", "A=a", dstPodLabels, "allow")
	netpolASet := []*types.TetragonNetworkPolicy{netpolA}
	aState, addASet, removeASet, errSet := s.recordsFromPoliciesAddition(netpolASet)

	require.NoError(t, errSet)
	assert.Zero(t, len(addASet))
	assert.Zero(t, len(removeASet))

	// Add src pod and dest pod while no policy is in play
	dstPod := newPodFromCluster(t, aState, testNamespace, dstPodName, testKind, dstPodLabels)

	rDst, err := aState.objectAdd(dstPod)
	require.NoError(t, err)
	assert.Zero(t, len(rDst))

	srcPod := newPodFromCluster(t, aState, testNamespace, srcPodName, testKind, srcPodLabels)
	r1, err := aState.objectAdd(srcPod)
	require.NoError(t, err)
	assert.Equal(t, 7, len(r1))

	dns, pod, _, n := cntRecordsEPTypes(r1)
	assert.Equal(t, 4, dns)
	assert.Equal(t, 2, pod)
	assert.Equal(t, 1, n)

	// netpol A remains, remove it.
	aRemove, aUpdate, err := aState.recordsFromPolicyRemoval(netpolA)
	require.NoError(t, err)
	assert.Equal(t, 7, len(aRemove))
	assert.Zero(t, len(aUpdate))

	// Remove source pod there should be no more records
	delPod(t)
	deleted, err := aState.podRemove(srcPod)
	require.NoError(t, err)
	assert.Equal(t, 0, len(deleted))

	// Remove destination pod, should not be any records remaining
	delPod(t)
	deleted, err = aState.podRemove(dstPod)
	require.NoError(t, err)
	assert.Zero(t, len(deleted))
}

func TestProcessPolicyDestSrc(t *testing.T) {
	s := newTestPolicyState(t)

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	// Add policy and ensure we generate rules
	netpolA := testMatchDstProcessLabelsDenyPolicy("netpolZ", "A=a", dstPodLabels, "allow")
	netpolASet := []*types.TetragonNetworkPolicy{netpolA}
	aState, addASet, removeASet, errSet := s.recordsFromPoliciesAddition(netpolASet)

	require.NoError(t, errSet)
	assert.Zero(t, len(addASet))
	assert.Zero(t, len(removeASet))

	// Add dst pod and then src pod while no policy is in play

	dstPod := newPodFromCluster(t, s, testNamespace, dstPodName, testKind, dstPodLabels)
	rDst, err := aState.objectAdd(dstPod)
	require.NoError(t, err)
	assert.Zero(t, len(rDst))

	srcPod := newPodFromCluster(t, s, testNamespace, srcPodName, testKind, srcPodLabels)
	r1, err := aState.objectAdd(srcPod)
	require.NoError(t, err)
	assert.Equal(t, 7, len(r1))

	dns, pod, _, n := cntRecordsEPTypes(r1)
	assert.Equal(t, 4, dns)
	assert.Equal(t, 2, pod)
	assert.Equal(t, 1, n)

	// netpol A remains, remove it.
	aRemove, aUpdate, err := aState.recordsFromPolicyRemoval(netpolA)
	require.NoError(t, err)
	assert.Equal(t, 7, len(aRemove))
	assert.Zero(t, len(aUpdate))

	// Remove source pod there should be no more records
	delPod(t)
	deleted, err := aState.podRemove(srcPod)
	require.NoError(t, err)
	assert.Equal(t, 0, len(deleted))

	// Remove destination pod, should not be any records remaining
	delPod(t)
	deleted, err = aState.podRemove(dstPod)
	require.NoError(t, err)
	assert.Zero(t, len(deleted))
}

func TestProcessPortPolicyDestSrc(t *testing.T) {
	s := newTestPolicyState(t)

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	// Add policy and ensure we generate rules
	netpolA := testMatchPortDstProcessLabelsDenyPolicy("netpolZ", "A=a", dstPodLabels, "allow")
	netpolASet := []*types.TetragonNetworkPolicy{netpolA}
	aState, addASet, removeASet, errSet := s.recordsFromPoliciesAddition(netpolASet)

	require.NoError(t, errSet)
	assert.Zero(t, len(addASet))
	assert.Zero(t, len(removeASet))

	// Add dst pod and then src pod while no policy is in play

	dstPod := newPodFromCluster(t, s, testNamespace, dstPodName, testKind, dstPodLabels)
	rDst, err := aState.objectAdd(dstPod)
	require.NoError(t, err)
	assert.Zero(t, len(rDst))

	srcPod := newPodFromCluster(t, s, testNamespace, srcPodName, testKind, srcPodLabels)
	r1, err := aState.objectAdd(srcPod)
	require.NoError(t, err)
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
	require.NoError(t, err)
	assert.Equal(t, 13, len(aRemove))
	assert.Zero(t, len(aUpdate))

	// Remove source pod there should be no more records
	delPod(t)
	deleted, err := aState.podRemove(srcPod)
	require.NoError(t, err)
	assert.Equal(t, 0, len(deleted))

	// Remove destination pod, should not be any records remaining
	delPod(t)
	deleted, err = aState.podRemove(dstPod)
	require.NoError(t, err)
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
	s := newTestPolicyState(t)

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	// Add policy and ensure we generate rules
	netpolA := testMatchPortDstProcessLabelsDenyPolicy("netpolZ", "A=a", dstPodLabels, "allow")
	netpolASet := []*types.TetragonNetworkPolicy{netpolA}
	aState, addASet, removeASet, errSet := s.recordsFromPoliciesAddition(netpolASet)

	require.NoError(t, errSet)
	assert.Zero(t, len(addASet))
	assert.Zero(t, len(removeASet))

	// Add dst pod and then src pod while no policy is in play

	srcPod := newPodFromCluster(t, s, testNamespace, srcPodName, testKind, srcPodLabels)
	r1, err := aState.objectAdd(srcPod)
	require.NoError(t, err)
	assert.Equal(t, 9, len(r1))

	dns, pod, _, n := cntRecordsEPTypes(r1)
	assert.Equal(t, 8, dns)
	assert.Equal(t, 0, pod)
	assert.Equal(t, 1, n)

	port80 := countPorts(r1, 80)
	port81 := countPorts(r1, 81)

	assert.Equal(t, 4, port80)
	assert.Equal(t, 4, port81)

	dstPod := newPodFromCluster(t, s, testNamespace, dstPodName, testKind, dstPodLabels)
	rDst, err := aState.objectAdd(dstPod)
	require.NoError(t, err)
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
	require.NoError(t, err)
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
	delPod(t)
	deleted, err := aState.podRemove(srcPod)
	require.NoError(t, err)
	assert.Zero(t, len(deleted))

	// Remove destination pod, should not be any records remaining
	delPod(t)
	deleted, err = aState.podRemove(dstPod)
	require.NoError(t, err)
	assert.Zero(t, len(deleted))
}

func TestProcessCIDRPolicySrcDest(t *testing.T) {
	s := newTestPolicyState(t)

	srcPodName := "testNamePodSrc"
	srcPodLabels := "A=a,B=b"

	dstPodName := "testNamePodDst"
	dstPodLabels := "D1=d1,D2=d2,D3=d3"

	// Add policy and ensure we generate rules
	netpolA := testMatchPortCIDRDstProcessLabelsDenyPolicy("netpolZ", "A=a", dstPodLabels, "allow", "10.0.0.1/16")
	netpolASet := []*types.TetragonNetworkPolicy{netpolA}
	aState, addASet, removeASet, errSet := s.recordsFromPoliciesAddition(netpolASet)

	require.NoError(t, errSet)
	assert.Zero(t, len(addASet))
	assert.Zero(t, len(removeASet))

	// Add dst pod and then src pod while no policy is in play

	srcPod := newPodFromCluster(t, s, testNamespace, srcPodName, testKind, srcPodLabels)
	r1, err := aState.objectAdd(srcPod)
	require.NoError(t, err)
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

	dstPod := newPodFromCluster(t, s, testNamespace, dstPodName, testKind, dstPodLabels)
	rDst, err := aState.objectAdd(dstPod)
	require.NoError(t, err)
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
	require.NoError(t, err)
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
	delPod(t)
	deleted, err := aState.podRemove(srcPod)
	require.NoError(t, err)
	assert.Zero(t, len(deleted))

	// Remove destination pod, should not be any records remaining
	delPod(t)
	deleted, err = aState.podRemove(dstPod)
	require.NoError(t, err)
	assert.Zero(t, len(deleted))
}

// This is a regression test for a bug that was introduced with objectAdd
// mutating the labels of the original Pod object from the cache. This could
// have happened at the same time as another go routine was iterating the Pod's
// labels (in our situation it was during pkg/workloadid Reconcile loop).
//
// This test simulates the race condition by:
// 1. Creating a Pod with labels (simulating cached object)
// 2. Running objectAdd in one goroutine (which adds namespace labels)
// 3. Running DeepCopy in another goroutine (which iterates labels)
//
// Without the patch, running this test with the Go race detector:
//
//	go test -race ./pkg/netpolstate -run TestObjectAddConcurrentPodLabelAccess
//
// should fail with:
//
//	FAIL: TestObjectAddConcurrentPodLabelAccess (0.00s)
//	testing.go:1712: race detected during execution of test
func TestObjectAddConcurrentPodLabelAccess(t *testing.T) {
	// Create a Pod with labels that will be shared (like in controller-runtime cache)
	sharedPod := &v1alpha1.PodInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			UID:       "test-uid-123",
			Labels: map[string]string{
				"app":     "test",
				"version": "v1",
				"tier":    "backend",
			},
		},
		WorkloadObject: v1alpha1.WorkloadObjectMeta{
			Name:      "test-deployment",
			Namespace: "default",
		},
		WorkloadType: metav1.TypeMeta{
			Kind: "Deployment",
		},
	}

	state := newTestPolicyState(t)

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: Call objectAdd which would modify labels (adds _tnp_* keys)
	// This simulates the netpolstate processing a pod add event
	go func() {
		defer wg.Done()
		state.objectAdd(sharedPod)
	}()

	// Goroutine 2: Simulate controller-runtime cache DeepCopy during Get()
	// This is what happens when the workloadid reconciler calls Get() on the pod
	go func() {
		defer wg.Done()
		// DeepCopy iterates over the Labels map
		sharedPod.DeepCopy()
	}()

	wg.Wait()
}

// This is a regression test to make sure objectAdd is not mutating the Pod's labels
func TestObjectAddPodLabelsNotModified(t *testing.T) {
	originalLabels := map[string]string{
		"app":     "test",
		"version": "v1",
	}
	originalLen := len(originalLabels)
	pod := &v1alpha1.PodInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			UID:       "test-uid-999",
			Labels:    originalLabels,
		},
		WorkloadObject: v1alpha1.WorkloadObjectMeta{
			Name:      "test-deployment",
			Namespace: "default",
		},
		WorkloadType: metav1.TypeMeta{
			Kind: "Deployment",
		},
	}

	state := newTestPolicyState(t)
	// Call objectAdd which should not modify the original labels
	_, err := state.objectAdd(pod)
	require.NoError(t, err)
	require.Equal(t, originalLen, len(pod.Labels), "original pod labels should not be modified")
	require.Equal(t, "test", pod.Labels["app"])
	require.Equal(t, "v1", pod.Labels["version"])
	for k := range pod.Labels {
		require.NotContains(t, k, "_tnp_", "namespace labels should not be added to original pod labels")
	}
}
