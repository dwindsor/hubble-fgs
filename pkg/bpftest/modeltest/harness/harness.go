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
	"context"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/cilium/tetragon/pkg/podhelpers"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/third_party/kind"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/image"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/model"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
)

const clientCreateTimeout = 1 * time.Minute
const cleanupTimeout = 30 * time.Second

type Harness struct {
	cluster     *kind.Cluster
	client      klient.Client
	clusterName string
	kubeconfig  string
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

	return Harness{
		cluster:     cluster,
		kubeconfig:  kubeconfig,
		client:      client,
		clusterName: clusterName,
	}
}

func (harness *Harness) AddPod(tb testing.TB, podName string, namespace string, containers model.Containers) {
	ctx := tb.Context()

	// Check if namespace exists, and create it if it doesn't
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}
	err := harness.client.Resources().Get(ctx, namespace, "", ns)
	if err != nil {
		// If namespace doesn't exist, create it
		if errors.IsNotFound(err) {
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
		err = harness.cluster.LoadImage(ctx, tag)
		if err != nil {
			tb.Fatalf("failed to load image %q: %v", tag, err)
		}
		k8sContainers = append(k8sContainers, corev1.Container{
			Name:            name,
			Image:           tag,
			ImagePullPolicy: corev1.PullNever,
			Command:         append([]string{spec.Cmd.Cmd}, spec.Cmd.Args...),
		})
	}

	// Create the podInfo object
	podInfo := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
		},
		Spec: corev1.PodSpec{
			Containers:    k8sContainers,
			RestartPolicy: corev1.RestartPolicyNever,
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
		if err != nil {
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
	addPodState(tb, podInfo)
	tb.Cleanup(func() {
		clearPodState(tb, podInfo)
	})
}

func GetClusterName(harness *Harness) string {
	return harness.clusterName
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

func addPodState(tb testing.TB, podInfo *corev1.Pod) {
	var podIPs []v1alpha1.PodIP
	for _, ip := range podInfo.Status.PodIPs {
		podIPs = append(podIPs, v1alpha1.PodIP(ip))
	}

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
		WorkloadType:   podInfo.TypeMeta,
		WorkloadObject: v1alpha1.WorkloadObjectMeta{},
	})

	state, err := policyfilter.GetState()
	require.NoError(tb, err)

	containerIDs := podhelpers.PodContainersIDs(podInfo)
	containerInfo := podhelpers.PodContainersInfo(podInfo)
	podID, err := uuid.Parse(string(podInfo.UID))
	require.NoError(tb, err)

	workloadMeta, kindMeta := podhelpers.GetWorkloadMetaFromPod(podInfo)
	workload := workloadMeta.Name
	kind := kindMeta.Kind

	err = state.UpdatePod(policyfilter.PodID(podID), podInfo.Namespace, workload, kind, podInfo.Labels, containerIDs, containerInfo)
	require.NoError(tb, err)
}

func clearPodState(tb testing.TB, podInfo *corev1.Pod) {
	state, err := policyfilter.GetState()
	require.NoError(tb, err)

	podID, err := uuid.Parse(string(podInfo.UID))
	require.NoError(tb, err)

	err = state.DelPod(policyfilter.PodID(podID))
	require.NoError(tb, err)
}
