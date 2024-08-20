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
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/tetragon/pkg/k8s/client/clientset/versioned/fake"
	"github.com/cilium/tetragon/pkg/k8s/client/informers/externalversions"
	"github.com/cilium/tetragon/pkg/logger"
	oss "github.com/cilium/tetragon/pkg/watcher"

	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model"
)

const (
	serviceIPsIdx       = "service-ips"
	podInfoIPsIdx       = "pod-info-ips"
	serviceInformerName = "service"
	podInfoInformerName = "podInfo"
)

var (
	errNoService = errors.New("object is not a *corev1.Service")
	errNoPodInfo = errors.New("object is not a *PodInfo")
)

// serviceIPIndexFunc indexes services by their IP addresses
func serviceIPIndexFunc(obj interface{}) ([]string, error) {
	switch t := obj.(type) {
	case *corev1.Service:
		return t.Spec.ClusterIPs, nil
	}
	return nil, fmt.Errorf("%w - found %T", errNoService, obj)
}

// podInfoIPIndexFunc indexes services by their IP addresses
func podInfoIPIndexFunc(obj interface{}) ([]string, error) {
	switch t := obj.(type) {
	case *v1alpha1.PodInfo:
		var ips []string
		for _, ip := range t.Status.PodIPs {
			ips = append(ips, ip.IP)
		}
		return ips, nil
	}
	return nil, fmt.Errorf("%w - found %T", errNoPodInfo, obj)
}

// NewK8sWatcher returns a pointer to an initialized K8sWatcher struct.
func NewK8sWatcher(k8sClient kubernetes.Interface, stateSyncIntervalSec time.Duration) *oss.K8sWatcher {
	return NewK8sWatcherWithTetragonClient(k8sClient, fake.NewSimpleClientset(), stateSyncIntervalSec)
}

// NewK8sWatcherWithTetragonClient returns a pointer to an initialized K8sWatcher struct.
func NewK8sWatcherWithTetragonClient(k8sClient kubernetes.Interface, tetragonClient versioned.Interface, stateSyncIntervalSec time.Duration) *oss.K8sWatcher {
	k8sWatcher := oss.NewK8sWatcher(k8sClient, stateSyncIntervalSec)

	serviceInformerFactory := informers.NewSharedInformerFactory(k8sClient, stateSyncIntervalSec)
	serviceInformer := serviceInformerFactory.Core().V1().Services().Informer()
	k8sWatcher.AddInformers(serviceInformerFactory, &oss.InternalInformer{
		Name:     serviceInformerName,
		Informer: serviceInformer,
		Indexers: map[string]cache.IndexFunc{
			serviceIPsIdx: serviceIPIndexFunc,
		},
	})

	podInfoInformerFactory := externalversions.NewSharedInformerFactory(tetragonClient, stateSyncIntervalSec)
	podInfoInformer := podInfoInformerFactory.Cilium().V1alpha1().PodInfo().Informer()

	// Init endpoint outside event handler to ensure we have maps and
	// caches configured. But, more importantly avoid racing with sensor
	// coming online. Because NewK8sWatcher is serialized with Sensor
	// loads we avoid having to consider a Mutex. Get() may return nil
	// if feature is not enabled.
	c := endpoint.Get()
	if c != nil {
		podInfoInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				switch t := obj.(type) {
				case *v1alpha1.PodInfo:
					c := endpoint.Get()
					logger.GetLogger().Debug("Add Pod: %v", t)
					c.AddIpPodMap(t)
					model.CheckWorkloadQuotaPolicy(t)
				}
			},
			UpdateFunc: func(old interface{}, _ interface{}) {
				switch t := old.(type) {
				case *v1alpha1.PodInfo:
					logger.GetLogger().Debug("Update Pod: %v", t)
				}
			},
			DeleteFunc: func(old interface{}) {
				switch t := old.(type) {
				case *v1alpha1.PodInfo:
					logger.GetLogger().Debug("Delete Pod: %v", t)
				}
			},
		})
	}

	k8sWatcher.AddInformers(podInfoInformerFactory, &oss.InternalInformer{
		Name:     podInfoInformerName,
		Informer: podInfoInformer,
		Indexers: map[string]cache.IndexFunc{
			podInfoIPsIdx: podInfoIPIndexFunc,
		},
	})

	return k8sWatcher
}

func FindServiceByIP(watcher oss.K8sResourceWatcher, ip string) ([]*corev1.Service, error) {
	serviceInformer := watcher.GetInformer(serviceInformerName)
	if serviceInformer == nil {
		return nil, fmt.Errorf("service informer not initialized")
	}
	objs, err := serviceInformer.GetIndexer().ByIndex(serviceIPsIdx, ip)
	if err != nil {
		return nil, fmt.Errorf("watcher returned: %w", err)
	}
	if len(objs) == 0 {
		return nil, fmt.Errorf("service with IP %s not found", ip)
	}
	var services []*corev1.Service
	for _, obj := range objs {
		service, ok := obj.(*corev1.Service)
		if !ok {
			return nil, fmt.Errorf("unexpected type %t", objs[0])
		}
		services = append(services, service)
	}
	return services, nil
}

func FindPodInfoByIP(watcher oss.K8sResourceWatcher, ip string) ([]*v1alpha1.PodInfo, error) {
	podInfoInformer := watcher.GetInformer(podInfoInformerName)
	if podInfoInformer == nil {
		return nil, fmt.Errorf("podInfo informer not initialized")
	}
	objs, err := podInfoInformer.GetIndexer().ByIndex(podInfoIPsIdx, ip)
	if err != nil {
		return nil, fmt.Errorf("pod info watcher returned: %w", err)
	}
	if len(objs) == 0 {
		return nil, fmt.Errorf("PodInfo with IP %s not found", ip)
	}
	var podInfo []*v1alpha1.PodInfo
	for _, obj := range objs {
		service, ok := obj.(*v1alpha1.PodInfo)
		if !ok {
			return nil, fmt.Errorf("unexpected type %t", objs[0])
		}
		podInfo = append(podInfo, service)
	}
	return podInfo, nil
}
