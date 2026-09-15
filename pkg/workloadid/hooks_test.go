// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package workloadid

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type mockCgroupIDResolver struct {
	mock.Mock
}

func (m *mockCgroupIDResolver) GetPodCgroupID(uid types.UID) (uint64, error) {
	args := m.Called(uid)
	return args.Get(0).(uint64), args.Error(1)
}

func (m *mockCgroupIDResolver) GetContainersCgroupIDs(uid types.UID) ([]uint64, error) {
	args := m.Called(uid)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]uint64), args.Error(1)
}

func getClientBuilder() *fake.ClientBuilder {
	scheme := runtime.NewScheme()
	utilruntime.Must(corev1.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme)
}

func newTestPod(name, namespace, uid string, ownerRefs []metav1.OwnerReference) *corev1.Pod {
	pod := &corev1.Pod{
		Name:            name,
		Namespace:       namespace,
		UID:             types.UID(uid),
		OwnerReferences: ownerRefs,
		GenerateName:    name + "-",
		Labels:          make(map[string]string),
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "test-container"},
			},
		},
	}

	// Add pod-template-hash label for ReplicaSet owners so GetWorkloadMetaFromPod
	// can extract the Deployment name
	for _, ref := range ownerRefs {
		if ref.Kind == "ReplicaSet" && strings.Contains(ref.Name, "-") {
			// Extract hash from ReplicaSet name (e.g., "nginx-7d8b9c" -> "7d8b9c")
			parts := strings.Split(ref.Name, "-")
			if len(parts) > 1 {
				hash := parts[len(parts)-1]
				pod.Labels["pod-template-hash"] = hash
			}
		}
	}

	return pod
}

func newReplicaSetOwnerRef(name string) metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion: "apps/v1",
		Kind:       "ReplicaSet",
		Name:       name,
		Controller: new(true),
	}
}

func TestCreateContainerHookMapNotInitialized(t *testing.T) {
	state := newTestState()
	state.cgroupIDToWorkloadIDMap = nil

	arg := &rthooks.CreateContainerArg{}

	err := state.CreateContainerHook(context.Background(), arg)
	require.NoError(t, err, "should return nil when map is not initialized")
}

func TestReconcilePodCreated(t *testing.T) {
	pod := newTestPod("nginx-abc123", "default", "test-uid-123", []metav1.OwnerReference{
		newReplicaSetOwnerRef("nginx-7d8b9c"),
	})

	client := getClientBuilder().WithObjects(pod).Build()
	resolver := new(mockCgroupIDResolver)
	resolver.On("GetPodCgroupID", types.UID("test-uid-123")).Return(uint64(12345), nil).Once()
	resolver.On("GetContainersCgroupIDs", types.UID("test-uid-123")).Return([]uint64{12346, 12347}, nil).Once()

	state := newTestState()
	state.Client = client
	state.cgroupIDResolver = resolver

	req := ctrl.Request{
		Namespace: "default",
		Name:      "nginx-abc123",
	}

	result, err := state.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// With pod-template-hash label, GetWorkloadMetaFromPod should extract Deployment name
	workload := WorkloadMeta{
		Namespace: "default",
		Workload:  "nginx",
		Kind:      "Deployment",
	}

	id, ok := state.LookupID(workload.WorkloadKey)
	assert.True(t, ok, "workload should be found in metaToID map")
	assert.Equal(t, WorkloadID(1), id)

	// Verify pod-level cgroup ID maps to workload
	var cgidResult WorkloadID
	err = state.cgroupIDToWorkloadIDMap.Lookup(CgroupID(12345), &cgidResult)
	require.NoError(t, err)
	assert.Equal(t, WorkloadID(1), cgidResult)

	// Verify container-level cgroup IDs also map to the same workload
	err = state.cgroupIDToWorkloadIDMap.Lookup(CgroupID(12346), &cgidResult)
	require.NoError(t, err)
	assert.Equal(t, WorkloadID(1), cgidResult)

	err = state.cgroupIDToWorkloadIDMap.Lookup(CgroupID(12347), &cgidResult)
	require.NoError(t, err)
	assert.Equal(t, WorkloadID(1), cgidResult)

	resolver.AssertExpectations(t)
}

func TestReconcilePodDeleted(t *testing.T) {
	pod := newTestPod("nginx-abc123", "default", "test-uid-123", []metav1.OwnerReference{
		newReplicaSetOwnerRef("nginx-7d8b9c"),
	})

	// Start with the pod in the cluster
	client := getClientBuilder().WithObjects(pod).Build()
	resolver := new(mockCgroupIDResolver)
	// Called once during first reconcile, not called on second reconcile (pod deleted)
	resolver.On("GetPodCgroupID", types.UID("test-uid-123")).Return(uint64(12345), nil).Once()
	resolver.On("GetContainersCgroupIDs", types.UID("test-uid-123")).Return([]uint64{12346}, nil).Once()

	state := newTestState()
	state.Client = client
	state.cgroupIDResolver = resolver

	req := ctrl.Request{
		Namespace: "default",
		Name:      "nginx-abc123",
	}

	// First reconcile - pod exists
	result, err := state.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	workload := WorkloadMeta{
		Namespace: "default",
		Workload:  "nginx",
		Kind:      "Deployment",
	}

	// Verify the workload was added
	id, ok := state.LookupID(workload.WorkloadKey)
	require.True(t, ok, "workload should be added")
	assert.Equal(t, WorkloadID(1), id)

	// Now delete the pod from the cluster
	err = client.Delete(context.Background(), pod)
	require.NoError(t, err)

	// Second reconcile - pod is deleted
	result, err = state.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// Verify the workload metadata is still preserved (not removed on deletion)
	id, ok = state.LookupID(workload.WorkloadKey)
	assert.True(t, ok, "workload should still exist after pod deletion")
	assert.Equal(t, WorkloadID(1), id, "workload ID should remain the same")

	// Verify both pod and container cgroup ID mappings still exist
	var cgidResult WorkloadID
	err = state.cgroupIDToWorkloadIDMap.Lookup(CgroupID(12345), &cgidResult)
	require.NoError(t, err, "pod cgroup ID mapping should still exist")
	assert.Equal(t, WorkloadID(1), cgidResult)

	err = state.cgroupIDToWorkloadIDMap.Lookup(CgroupID(12346), &cgidResult)
	require.NoError(t, err, "container cgroup ID mapping should still exist")
	assert.Equal(t, WorkloadID(1), cgidResult)

	resolver.AssertExpectations(t)
}

func TestReconcileGetCgroupIDError(t *testing.T) {
	pod := newTestPod("nginx-abc123", "default", "test-uid-123", []metav1.OwnerReference{
		newReplicaSetOwnerRef("nginx-7d8b9c"),
	})

	client := getClientBuilder().WithObjects(pod).Build()
	resolver := new(mockCgroupIDResolver)
	resolver.On("GetPodCgroupID", types.UID("test-uid-123")).Return(uint64(0), fmt.Errorf("cgroup not found")).Once()

	state := newTestState()
	state.Client = client
	state.cgroupIDResolver = resolver

	req := ctrl.Request{
		Namespace: "default",
		Name:      "nginx-abc123",
	}

	result, err := state.Reconcile(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get cgroup ID from Pod")
	assert.Equal(t, ctrl.Result{}, result)

	resolver.AssertExpectations(t)
}

func TestReconcileGetContainersCgroupIDsError(t *testing.T) {
	pod := newTestPod("nginx-abc123", "default", "test-uid-123", []metav1.OwnerReference{
		newReplicaSetOwnerRef("nginx-7d8b9c"),
	})

	client := getClientBuilder().WithObjects(pod).Build()
	resolver := new(mockCgroupIDResolver)
	resolver.On("GetPodCgroupID", types.UID("test-uid-123")).Return(uint64(12345), nil).Once()
	resolver.On("GetContainersCgroupIDs", types.UID("test-uid-123")).Return([]uint64(nil), fmt.Errorf("failed to read containers")).Once()

	state := newTestState()
	state.Client = client
	state.cgroupIDResolver = resolver

	req := ctrl.Request{
		Namespace: "default",
		Name:      "nginx-abc123",
	}

	result, err := state.Reconcile(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get cgroup ID from containers")
	assert.Equal(t, ctrl.Result{}, result)

	resolver.AssertExpectations(t)
}

func TestReconcileMultiplePods(t *testing.T) {
	pod1 := newTestPod("nginx-abc123", "default", "uid-1", []metav1.OwnerReference{
		newReplicaSetOwnerRef("nginx-7d8b9c"),
	})
	pod2 := newTestPod("redis-xyz789", "default", "uid-2", []metav1.OwnerReference{
		{
			APIVersion: "apps/v1",
			Kind:       "StatefulSet",
			Name:       "redis",
			Controller: new(true),
		},
	})

	client := getClientBuilder().WithObjects(pod1, pod2).Build()
	resolver := new(mockCgroupIDResolver)
	resolver.On("GetPodCgroupID", types.UID("uid-1")).Return(uint64(11111), nil).Once()
	resolver.On("GetContainersCgroupIDs", types.UID("uid-1")).Return([]uint64{11112}, nil).Once()
	resolver.On("GetPodCgroupID", types.UID("uid-2")).Return(uint64(22222), nil).Once()
	resolver.On("GetContainersCgroupIDs", types.UID("uid-2")).Return([]uint64{22223}, nil).Once()

	state := newTestState()
	state.Client = client
	state.cgroupIDResolver = resolver

	_, err := state.Reconcile(context.Background(), ctrl.Request{
		Namespace: "default", Name: "nginx-abc123",
	})
	require.NoError(t, err)

	_, err = state.Reconcile(context.Background(), ctrl.Request{
		Namespace: "default", Name: "redis-xyz789",
	})
	require.NoError(t, err)

	assert.Len(t, state.metaToID, 2)
	assert.Len(t, state.idToMeta, 2)

	nginxWorkload := WorkloadMeta{Namespace: "default", Workload: "nginx", Kind: "Deployment"}
	redisWorkload := WorkloadMeta{Namespace: "default", Workload: "redis", Kind: "StatefulSet"}

	nginxID, ok := state.LookupID(nginxWorkload.WorkloadKey)
	assert.True(t, ok)
	assert.Equal(t, WorkloadID(1), nginxID)

	redisID, ok := state.LookupID(redisWorkload.WorkloadKey)
	assert.True(t, ok)
	assert.Equal(t, WorkloadID(2), redisID)

	resolver.AssertExpectations(t)
}

func TestReconcileSamePodMultipleTimes(t *testing.T) {
	pod := newTestPod("nginx-abc123", "default", "test-uid-123", []metav1.OwnerReference{
		newReplicaSetOwnerRef("nginx-7d8b9c"),
	})

	client := getClientBuilder().WithObjects(pod).Build()
	resolver := new(mockCgroupIDResolver)
	// Reconcile is called twice, so GetPodCgroupID will be called twice
	resolver.On("GetPodCgroupID", types.UID("test-uid-123")).Return(uint64(12345), nil).Times(2)
	resolver.On("GetContainersCgroupIDs", types.UID("test-uid-123")).Return([]uint64{12346}, nil).Times(2)

	state := newTestState()
	state.Client = client
	state.cgroupIDResolver = resolver

	req := ctrl.Request{
		Namespace: "default", Name: "nginx-abc123",
	}

	_, err := state.Reconcile(context.Background(), req)
	require.NoError(t, err)

	_, err = state.Reconcile(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, WorkloadID(2), state.workloadIDCounter, "counter should only increment once")
	assert.Len(t, state.metaToID, 1)
	assert.Len(t, state.idToMeta, 1)

	// Verify both pod and container cgroup IDs map to the same workload
	var cgidResult WorkloadID
	err = state.cgroupIDToWorkloadIDMap.Lookup(CgroupID(12345), &cgidResult)
	require.NoError(t, err)
	assert.Equal(t, WorkloadID(1), cgidResult)

	err = state.cgroupIDToWorkloadIDMap.Lookup(CgroupID(12346), &cgidResult)
	require.NoError(t, err)
	assert.Equal(t, WorkloadID(1), cgidResult)

	resolver.AssertExpectations(t)
}

func TestReconcileWithDifferentOwnerTypes(t *testing.T) {
	tests := []struct {
		name         string
		ownerRef     metav1.OwnerReference
		expectedKind string
		expectedName string
	}{
		{
			name: "deployment via replicaset",
			ownerRef: metav1.OwnerReference{
				APIVersion: "apps/v1",
				Kind:       "ReplicaSet",
				Name:       "nginx-7d8b9c",
				Controller: new(true),
			},
			expectedKind: "Deployment",
			expectedName: "nginx",
		},
		{
			name: "statefulset",
			ownerRef: metav1.OwnerReference{
				APIVersion: "apps/v1",
				Kind:       "StatefulSet",
				Name:       "redis",
				Controller: new(true),
			},
			expectedKind: "StatefulSet",
			expectedName: "redis",
		},
		{
			name: "daemonset",
			ownerRef: metav1.OwnerReference{
				APIVersion: "apps/v1",
				Kind:       "DaemonSet",
				Name:       "fluentd",
				Controller: new(true),
			},
			expectedKind: "DaemonSet",
			expectedName: "fluentd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := newTestPod("test-pod", "default", "test-uid", []metav1.OwnerReference{tt.ownerRef})

			client := getClientBuilder().WithObjects(pod).Build()
			resolver := new(mockCgroupIDResolver)
			resolver.On("GetPodCgroupID", types.UID("test-uid")).Return(uint64(12345), nil).Once()
			resolver.On("GetContainersCgroupIDs", types.UID("test-uid")).Return([]uint64{12346}, nil).Once()

			state := newTestState()
			state.Client = client
			state.cgroupIDResolver = resolver

			req := ctrl.Request{
				Namespace: "default", Name: "test-pod",
			}

			_, err := state.Reconcile(context.Background(), req)
			require.NoError(t, err)

			workload := WorkloadMeta{
				Namespace: "default",
				Workload:  tt.expectedName,
				Kind:      tt.expectedKind,
			}

			id, ok := state.LookupID(workload.WorkloadKey)
			assert.True(t, ok)
			assert.Equal(t, WorkloadID(1), id)

			resolver.AssertExpectations(t)
		})
	}
}
