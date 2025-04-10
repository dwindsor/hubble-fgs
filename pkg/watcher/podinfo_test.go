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

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	fakeTetragon "github.com/cilium/tetragon/pkg/k8s/client/clientset/versioned/fake"
	"github.com/cilium/tetragon/pkg/watcher"
)

func TestPodInfoByIP(t *testing.T) {
	ctx := context.Background()
	tetragonClient := fakeTetragon.NewSimpleClientset()
	k8sWatcher := watcher.NewK8sWatcher(nil, tetragonClient, 60*time.Second)
	err := AddPodInfoInformer(k8sWatcher, false)
	assert.NoError(t, err)
	k8sWatcher.Start()
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
		return len(k8sWatcher.GetInformer(podInfoInformerName).GetStore().List()) == 3
	}, 10*time.Second, 1*time.Second)
	res, err := FindPodInfoByIP(k8sWatcher, "1.1.1.1")
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, "pod1", res[0].Name)
	res, err = FindPodInfoByIP(k8sWatcher, "4.4.4.4")
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, "pod3", res[0].Name)
	_, err = FindPodInfoByIP(k8sWatcher, "5.5.5.5")
	assert.Error(t, err)
}
