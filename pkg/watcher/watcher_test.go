// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package watcher

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	fakeTetragon "github.com/cilium/tetragon/pkg/k8s/client/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestFindServiceByIP(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset()
	watcher, err := NewK8sWatcher(k8sClient, 60*time.Second)
	require.NoError(t, err)
	watcher.Start()
	svc1 := v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc1"},
		Spec:       v1.ServiceSpec{ClusterIPs: []string{"1.1.1.1"}},
	}
	svc2 := v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc2"},
		Spec:       v1.ServiceSpec{ClusterIPs: []string{"2.2.2.2"}},
	}
	svc3 := v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc3"},
		Spec:       v1.ServiceSpec{ClusterIPs: []string{"3.3.3.3", "4.4.4.4"}},
	}
	_, err = k8sClient.CoreV1().Services("my-ns").Create(ctx, &svc1, metav1.CreateOptions{})
	assert.NoError(t, err)
	_, err = k8sClient.CoreV1().Services("my-ns").Create(ctx, &svc2, metav1.CreateOptions{})
	assert.NoError(t, err)
	_, err = k8sClient.CoreV1().Services("my-ns").Create(ctx, &svc3, metav1.CreateOptions{})
	assert.NoError(t, err)
	assert.Eventually(t, func() bool {
		return len(watcher.GetInformer(serviceInformerName).GetStore().List()) == 3
	}, 10*time.Second, 1*time.Second)
	res, err := FindServiceByIP(watcher, "1.1.1.1")
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, "svc1", res[0].Name)
	res, err = FindServiceByIP(watcher, "4.4.4.4")
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, "svc3", res[0].Name)
}

func TestPodInfoByIP(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset()
	tetragonClient := fakeTetragon.NewSimpleClientset()
	watcher, err := NewK8sWatcherWithTetragonClient(k8sClient, tetragonClient, 0)
	require.NoError(t, err)
	watcher.Start()
	pod1 := v1alpha1.PodInfo{
		ObjectMeta: metav1.ObjectMeta{Name: "pod1"},
		Status:     v1alpha1.PodInfoStatus{PodIPs: []v1alpha1.PodIP{{IP: "1.1.1.1"}}},
	}
	pod2 := v1alpha1.PodInfo{
		ObjectMeta: metav1.ObjectMeta{Name: "pod2"},
		Status:     v1alpha1.PodInfoStatus{PodIPs: []v1alpha1.PodIP{{IP: "2.2.2.2"}}},
	}
	pod3 := v1alpha1.PodInfo{
		ObjectMeta: metav1.ObjectMeta{Name: "pod3"},
		Status:     v1alpha1.PodInfoStatus{PodIPs: []v1alpha1.PodIP{{IP: "3.3.3.3"}, {IP: "4.4.4.4"}}},
	}
	_, err = tetragonClient.CiliumV1alpha1().PodInfo("my-ns").Create(ctx, &pod1, metav1.CreateOptions{})
	assert.NoError(t, err)
	_, err = tetragonClient.CiliumV1alpha1().PodInfo("my-ns").Create(ctx, &pod2, metav1.CreateOptions{})
	assert.NoError(t, err)
	_, err = tetragonClient.CiliumV1alpha1().PodInfo("my-ns").Create(ctx, &pod3, metav1.CreateOptions{})
	assert.NoError(t, err)
	assert.Eventually(t, func() bool {
		return len(watcher.GetInformer(podInfoInformerName).GetStore().List()) == 3
	}, 10*time.Second, 1*time.Second)
	res, err := FindPodInfoByIP(watcher, "1.1.1.1")
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, "pod1", res[0].Name)
	res, err = FindPodInfoByIP(watcher, "4.4.4.4")
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, "pod3", res[0].Name)
	_, err = FindPodInfoByIP(watcher, "5.5.5.5")
	assert.Error(t, err)
}
