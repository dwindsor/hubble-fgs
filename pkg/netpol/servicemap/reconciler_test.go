// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !nok8s

package servicemap

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func svcRequest(namespace, name string) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}}
}

func clusterIPService(name, ip string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels:    map[string]string{"app": name},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:  ip,
			ClusterIPs: []string{ip},
			Selector:   map[string]string{"app": name},
		},
	}
}

func reconcileService(t *testing.T, sm *ServiceMap, req ctrl.Request, objs ...client.Object) {
	t.Helper()
	r := &ServiceReconciler{
		Client: fake.NewClientBuilder().WithObjects(objs...).Build(),
		Map:    sm,
	}
	_, err := r.Reconcile(context.Background(), req)
	require.NoError(t, err)
}

func TestServiceReconciler(t *testing.T) {
	t.Run("found service is tracked", func(t *testing.T) {
		sm := NewServiceMap(nil)
		reconcileService(t, sm, svcRequest("default", "web"), clusterIPService("web", "10.0.0.10"))

		info := sm.GetByName("default", "web")
		require.NotNil(t, info)
		require.Equal(t, "10.0.0.10", info.ClusterIP.String())
		require.Equal(t, map[string]string{"app": "web"}, info.Labels)
	})

	t.Run("missing service is removed", func(t *testing.T) {
		sm := NewServiceMap(nil)
		reconcileService(t, sm, svcRequest("default", "web"), clusterIPService("web", "10.0.0.10"))
		require.NotNil(t, sm.GetByName("default", "web"))

		reconcileService(t, sm, svcRequest("default", "web"))
		require.Nil(t, sm.GetByName("default", "web"))
	})

	t.Run("service update preserves discovered endpoints", func(t *testing.T) {
		sm := NewServiceMap(nil)
		reconcileService(t, sm, svcRequest("default", "web"), clusterIPService("web", "10.0.0.10"))
		reconcileSlice(t, sm, svcRequest("default", "web-abc"),
			endpointSlice("web-abc", "web", "192.168.1.5", true))
		require.Len(t, sm.GetByName("default", "web").Endpoints, 1)

		relabeled := clusterIPService("web", "10.0.0.10")
		relabeled.Labels["tier"] = "frontend"
		reconcileService(t, sm, svcRequest("default", "web"), relabeled)
		require.Len(t, sm.GetByName("default", "web").Endpoints, 1,
			"service reconcile must not drop endpoints tracked from slices")
	})

	t.Run("service turned headless is removed", func(t *testing.T) {
		sm := NewServiceMap(nil)
		reconcileService(t, sm, svcRequest("default", "web"), clusterIPService("web", "10.0.0.10"))
		require.NotNil(t, sm.GetByName("default", "web"))

		headless := clusterIPService("web", corev1.ClusterIPNone)
		headless.Spec.ClusterIPs = nil
		reconcileService(t, sm, svcRequest("default", "web"), headless)
		require.Nil(t, sm.GetByName("default", "web"),
			"a service that switched to headless must drop its stale entry")
	})
}

func endpointSlice(name, svcName, ip string, ready bool) *discoveryv1.EndpointSlice {
	port := int32(8080)
	protocol := corev1.ProtocolTCP
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels:    map[string]string{discoveryv1.LabelServiceName: svcName},
		},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{ip},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
			TargetRef:  &corev1.ObjectReference{Kind: "Pod", Name: name + "-pod"},
		}},
		Ports: []discoveryv1.EndpointPort{{Port: &port, Protocol: &protocol}},
	}
}

func reconcileSlice(t *testing.T, sm *ServiceMap, req ctrl.Request, objs ...client.Object) {
	t.Helper()
	r := &EndpointSliceReconciler{
		Client: fake.NewClientBuilder().WithObjects(objs...).Build(),
		Map:    sm,
	}
	_, err := r.Reconcile(context.Background(), req)
	require.NoError(t, err)
}

func TestEndpointSliceReconciler(t *testing.T) {
	t.Run("ready endpoints are mirrored onto the service", func(t *testing.T) {
		sm := NewServiceMap(nil)
		reconcileService(t, sm, svcRequest("default", "web"), clusterIPService("web", "10.0.0.10"))

		reconcileSlice(t, sm, svcRequest("default", "web-abc"),
			endpointSlice("web-abc", "web", "192.168.1.5", true))

		info := sm.GetByName("default", "web")
		require.NotNil(t, info)
		require.Len(t, info.Endpoints, 1)
		require.Equal(t, "192.168.1.5", info.Endpoints[0].IP.String())
		require.Equal(t, int32(8080), info.Endpoints[0].Port)
		require.Equal(t, "web-abc-pod", info.Endpoints[0].PodName)
	})

	t.Run("not-ready endpoints are filtered out", func(t *testing.T) {
		sm := NewServiceMap(nil)
		reconcileService(t, sm, svcRequest("default", "web"), clusterIPService("web", "10.0.0.10"))

		reconcileSlice(t, sm, svcRequest("default", "web-abc"),
			endpointSlice("web-abc", "web", "192.168.1.5", false))

		info := sm.GetByName("default", "web")
		require.NotNil(t, info)
		require.Empty(t, info.Endpoints)
	})

	t.Run("missing slice is a no-op", func(t *testing.T) {
		sm := NewServiceMap(nil)
		reconcileService(t, sm, svcRequest("default", "web"), clusterIPService("web", "10.0.0.10"))
		reconcileSlice(t, sm, svcRequest("default", "web-abc"),
			endpointSlice("web-abc", "web", "192.168.1.5", true))

		reconcileSlice(t, sm, svcRequest("default", "web-abc"))
		info := sm.GetByName("default", "web")
		require.NotNil(t, info)
		require.Len(t, info.Endpoints, 1)
	})

	t.Run("slice without service-name label is ignored", func(t *testing.T) {
		sm := NewServiceMap(nil)
		eps := endpointSlice("orphan", "web", "192.168.1.5", true)
		eps.Labels = nil
		reconcileSlice(t, sm, svcRequest("default", "orphan"), eps)
		require.Nil(t, sm.GetByName("default", "web"))
	})
}
