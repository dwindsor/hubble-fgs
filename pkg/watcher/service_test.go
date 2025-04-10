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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cilium/tetragon/pkg/watcher"
)

func TestFindServiceByIP(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset()
	k8sWatcher := watcher.NewK8sWatcher(k8sClient, nil, 60*time.Second)
	err := AddServiceInformer(k8sWatcher, false)
	assert.NoError(t, err)
	k8sWatcher.Start()
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
		return len(k8sWatcher.GetInformer(serviceInformerName).GetStore().List()) == 3
	}, 10*time.Second, 1*time.Second)
	res, err := FindServiceByIP(k8sWatcher, "1.1.1.1")
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, "svc1", res[0].Name)
	res, err = FindServiceByIP(k8sWatcher, "4.4.4.4")
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, "svc3", res[0].Name)
}
