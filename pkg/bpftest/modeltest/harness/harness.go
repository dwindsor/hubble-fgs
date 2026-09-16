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

package harness

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode"
	"uuid"

	"github.com/cilium/tetragon/pkg/cgidmap"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/cgroups/fsscan"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/podhelpers"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/watcher"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/third_party/kind"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/image"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/model"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/workloadid"
)

const clientCreateTimeout = 5 * time.Minute
const cleanupTimeout = 30 * time.Second

type Harness struct {
	cluster        *kind.Cluster
	client         klient.Client
	clusterName    string
	kubeconfig     string
	fsscanner      fsscan.FsScanner
	cgmap          cgidmap.Map
	fakeK8sWatcher *watcher.FakeK8sWatcher

	// Maps from "namespace name:pod name:container name" to the number of times
	// the container has restarted. This is used to determine if a container has
	// restarted since the last time we checked.
	restartCounts map[string]int32
}

func New(tb testing.TB) Harness {
	image.FixDockerAPIVersion()

	clusterName := fixupClusterName(tb.Name())

	// Set timeout for cluster/client setup
	ctx, cancel := context.WithTimeout(tb.Context(), clientCreateTimeout)
	defer cancel()

	// Create a new kind cluster for this test
	cluster := kind.NewCluster(clusterName)
	kubeconfig, err := cluster.Create(ctx)
	if err != nil {
		tb.Fatalf("failed to create kind cluster: %v", err)
	}

	// Register a hook to clean up the cluster
	tb.Cleanup(func() {
		err := cluster.Destroy(context.Background())
		if err != nil {
			tb.Fatalf("failed to destroy kind cluster: %v", err)
		}
	})

	// Create kube client
	client, err := klient.NewWithKubeConfigFile(kubeconfig)
	if err != nil {
		tb.Fatalf("failed to create kubernetes client")
	}
	// Wait for control plane
	err = cluster.WaitForControlPlane(ctx, client)
	if err != nil {
		tb.Fatalf("failed to wait for control plane")
	}

	option.Config.EnableCgIDmap = true

	cgmap, err := cgidmap.GlobalMap()
	if err != nil {
		tb.Fatalf("failed to get global cgroup id map: %v", err)
	}

	watcher := watcher.NewFakeK8sWatcher(nil)

	if err := process.InitCache(watcher, 65536, defaults.DefaultProcessCacheGCInterval); err != nil {
		tb.Fatalf("failed to call process.InitCache %s", err)
	}

	return Harness{
		cluster:        cluster,
		kubeconfig:     kubeconfig,
		client:         client,
		clusterName:    clusterName,
		fsscanner:      fsscan.New(),
		cgmap:          cgmap,
		fakeK8sWatcher: watcher,
	}
}

func (harness *Harness) AddPod(tb testing.TB, podName string, namespace string,
	policy corev1.RestartPolicy, containers model.Containers) {
	ctx := tb.Context()

	restartPolicy := corev1.RestartPolicyNever
	if policy != "" {
		restartPolicy = policy
	}

	// Check if namespace exists, and create it if it doesn't
	ns := &corev1.Namespace{
		Name: namespace,
	}
	err := harness.client.Resources().Get(ctx, namespace, "", ns)
	if err != nil {
		// If namespace doesn't exist, create it
		if k8sErrors.IsNotFound(err) {
			err = harness.client.Resources().Create(ctx, ns)
			if err != nil {
				tb.Fatalf("failed to create namespace %q", namespace)
			}

			// Register cleanup to delete the namespace when the test completes
			tb.Cleanup(func() {
				deleteCtx, deleteCancel := context.WithTimeout(context.Background(), cleanupTimeout)
				defer deleteCancel()

				// Delete the namespace
				err := harness.client.Resources().Delete(deleteCtx, ns)
				if err != nil {
					tb.Fatalf("failed to delete namespace %q: %v", namespace, err)
				}
			})
		} else {
			tb.Logf("warning: failed to check if namespace %q exists: %v", namespace, err)
		}
	}

	var k8sContainers []corev1.Container
	for name, spec := range containers {
		tag, err := spec.ImageSource(ctx)
		if err != nil {
			tb.Fatalf("failed to acquire image %q: %v", tag, err)
		}

		// Best effort to load the image into the cluster
		// See https://github.com/kubernetes-sigs/kind/issues/3795
		err = harness.cluster.LoadImage(ctx, tag)
		if err != nil {
			tb.Logf("warning: failed to load image %q: %v", tag, err)
		}

		k8sContainers = append(k8sContainers, corev1.Container{
			Name:            name,
			Image:           tag,
			ImagePullPolicy: corev1.PullIfNotPresent,
			Command:         append([]string{spec.Cmd.Cmd}, spec.Cmd.Args...),
		})
	}

	// Create the podInfo object
	podInfo := &corev1.Pod{
		Name:      podName,
		Namespace: namespace,
		Spec: corev1.PodSpec{
			Containers:    k8sContainers,
			RestartPolicy: restartPolicy,
		},
	}

	// Create the pod in the cluster
	err = harness.client.Resources().Create(ctx, podInfo)
	if err != nil {
		tb.Fatalf("failed to create pod: %v", err)
	}

	// Register cleanup to delete the pod when the test completes
	tb.Cleanup(func() {
		deleteCtx, deleteCancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer deleteCancel()

		// Delete the pod
		err := harness.client.Resources().Delete(deleteCtx, podInfo)
		if err != nil && !k8sErrors.IsNotFound(err) {
			tb.Fatalf("failed to delete pod %q in namespace %q: %v", podName, namespace, err)
		}
	})

	resources := harness.client.Resources(namespace)
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	wait.For(conditions.New(resources).PodReady(podInfo), wait.WithContext(waitCtx))

	err = harness.client.Resources().Get(ctx, podName, namespace, podInfo)
	if err != nil {
		tb.Fatalf("failed to get pod info: %v", err)
	}
	harness.addPodState(tb, podInfo)
	tb.Cleanup(func() {
		harness.clearPodState(tb, podInfo)
	})
}

func GetClusterName(harness *Harness) string {
	return harness.clusterName
}

// PodExec executes a command in the specified container of the specified pod.
func (harness *Harness) PodExec(ctx context.Context, namespace, podName, containerName string, command []string, timeout time.Duration) (string, string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	err := harness.client.Resources().ExecInPod(execCtx, namespace, podName, containerName, command, &stdout, &stderr)
	return stdout.String(), stderr.String(), err
}

func (harness *Harness) GetPod(ctx context.Context, tb testing.TB, namespace, podName string) *corev1.Pod {
	tb.Helper()

	pod := &corev1.Pod{}
	err := harness.client.Resources().Get(ctx, podName, namespace, pod)
	require.NoError(tb, err)
	return pod
}

func (harness *Harness) DeletePod(ctx context.Context, tb testing.TB, namespace, podName string) {
	tb.Helper()

	podInfo := &corev1.Pod{
		Name:      podName,
		Namespace: namespace,
	}

	err := harness.client.Resources().Get(ctx, podName, namespace, podInfo)
	if err != nil && !k8sErrors.IsNotFound(err) {
		require.NoError(tb, err, "failed to get pod %q in namespace %q", podName, namespace)
		return
	}

	err = harness.client.Resources().Delete(ctx, podInfo)
	if err != nil && !k8sErrors.IsNotFound(err) {
		require.NoError(tb, err, "failed to delete pod %q in namespace %q", podName, namespace)
	}

	if err == nil {
		harness.clearPodState(tb, podInfo)
	}
}

func (harness *Harness) WaitForPodExit(ctx context.Context, tb testing.TB, namespace, podName string, timeout time.Duration) {
	tb.Helper()

	resources := harness.client.Resources(namespace)
	podInfo := &corev1.Pod{
		Name:      podName,
		Namespace: namespace,
	}

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	err := wait.For(conditions.New(resources).ResourceDeleted(podInfo), wait.WithContext(waitCtx))
	require.NoError(tb, err, "failed waiting for pod %q/%q to be deleted", namespace, podName)
}

func (harness *Harness) WaitForContainerExit(ctx context.Context, tb testing.TB, namespace, podName, containerName string, timeout time.Duration) {
	tb.Helper()

	resources := harness.client.Resources(namespace)
	podInfo := &corev1.Pod{
		Name:      podName,
		Namespace: namespace,
	}

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	err := wait.For(conditions.New(resources).ResourceMatch(podInfo, func(object k8s.Object) bool {
		pod, ok := object.(*corev1.Pod)
		if !ok {
			return false
		}

		for _, status := range pod.Status.ContainerStatuses {
			if status.Name == containerName {
				return status.State.Terminated != nil
			}
		}

		return false
	}), wait.WithContext(waitCtx))
	require.NoError(tb, err, "failed waiting for container %q in pod %q/%q to exit", containerName, namespace, podName)
}

func (harness *Harness) WaitForContainerRestart(ctx context.Context, tb testing.TB, namespace, podName, containerName string, timeout time.Duration) {
	tb.Helper()

	resources := harness.client.Resources(namespace)
	podInfo := &corev1.Pod{
		Name:      podName,
		Namespace: namespace,
	}

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if harness.restartCounts == nil {
		harness.restartCounts = make(map[string]int32)
	}

	key := namespace + ":" + podName + ":" + containerName
	_, exists := harness.restartCounts[key]
	if !exists {
		harness.restartCounts[key] = 0
	}

	err := wait.For(conditions.New(resources).ResourceMatch(podInfo, func(object k8s.Object) bool {
		pod, ok := object.(*corev1.Pod)
		if !ok {
			return false
		}

		for _, status := range pod.Status.ContainerStatuses {
			if status.Name != containerName {
				continue
			}
			if status.State.Running != nil && status.RestartCount > harness.restartCounts[key] {
				harness.restartCounts[key] = status.RestartCount
				return true
			}
		}

		return false

	}), wait.WithContext(waitCtx))
	require.NoError(tb, err, "failed waiting for container %q in pod %q/%q to restart", containerName, namespace, podName)

	// Now that the container has restarted, we need to update the container
	// info in the watcher and various maps. In a non-test environment, the
	// informer would be doing this.
	harness.clearPodState(tb, podInfo)
	harness.addPodState(tb, podInfo)
}

func fixupClusterName(name string) string {
	name = strings.ReplaceAll(name, "/", ".")

	res := strings.Builder{}
	for i, r := range name {
		if unicode.IsUpper(r) {
			if i != 0 {
				res.WriteRune('-')
			}
			res.WriteRune(unicode.ToLower(r))
		} else {
			res.WriteRune(r)
		}
	}

	return "tetragon-" + res.String()
}

func (harness *Harness) addPodState(tb testing.TB, podInfo *corev1.Pod) {
	var podIPs []v1alpha1.PodIP
	for _, ip := range podInfo.Status.PodIPs {
		podIPs = append(podIPs, v1alpha1.PodIP(ip))
	}
	workloadMeta, workloadType := podhelpers.GetWorkloadMetaFromPod(podInfo)

	endpoint.MustGet().AddIpPodMap(&v1alpha1.PodInfo{
		TypeMeta:   podInfo.TypeMeta,
		ObjectMeta: podInfo.ObjectMeta,
		Spec: v1alpha1.PodInfoSpec{
			HostNetwork: podInfo.Spec.HostNetwork,
			NodeName:    podInfo.Spec.NodeName,
		},
		Status: v1alpha1.PodInfoStatus{
			PodIP:  podInfo.Status.PodIP,
			PodIPs: podIPs,
		},
		WorkloadType:   workloadType,
		WorkloadObject: workloadMeta,
	})

	containerIDs := podhelpers.PodContainersIDs(podInfo)
	podID, err := uuid.Parse(string(podInfo.UID))
	require.NoError(tb, err)

	for _, containerID := range containerIDs {
		harness.addCgroupIDForPodAndContainer(tb, podInfo, podID, containerID)
	}

	harness.fakeK8sWatcher.AddPod(podInfo)
}

// Unfortunately, this duplicates a lot of code in policyfilter/state.go, but
// none of the methods used in policyfilter expose a way to look up a cgroup id
// from a container id (and other than this test, they probably shouldn't).
func (harness *Harness) addCgroupIDForPodAndContainer(tb testing.TB, podInfo *corev1.Pod, podID uuid.UUID, containerID string) {
	path, err := harness.fsscanner.FindContainerPath(types.UID(podID.String()), containerID)
	if errors.Is(err, fsscan.ErrContainerPathWithoutMatchingPodID) {
		tb.Logf("warning: FindCgroupID: found path without matching pod id, continuing. pod-id=%s container-id=%s", podID, containerID)
	} else if err != nil {
		tb.Fatalf("FindContainerPath failed: pod-id=%s container-id=%s: %v", podID, containerID, err)
	}

	cgid, err := cgroups.GetCgroupIDFromSubCgroup(path)
	require.NoError(tb, err)

	harness.cgmap.Add(podID, containerID, cgid)

	// Populate the workloadid state so the application model can resolve
	// cgroup IDs to namespace/workload metadata.
	workloadMeta, workloadType := podhelpers.GetWorkloadMetaFromPod(podInfo)
	err = workloadid.GetState().Update(workloadid.WorkloadMeta{
		Workload:  workloadMeta.Name,
		Namespace: podInfo.Namespace,
		Kind:      workloadType.Kind,
		UID:       string(podInfo.UID),
	}, workloadid.CgroupID(cgid))
	require.NoError(tb, err)
}

func (harness *Harness) clearPodState(tb testing.TB, podInfo *corev1.Pod) {
	podID, err := uuid.Parse(string(podInfo.UID))
	require.NoError(tb, err)

	harness.cgmap.Update(podID, []string{})
	harness.cgmap.UpdatePodSandbox(podID, "")

	harness.fakeK8sWatcher.RemovePod(podInfo)
}
