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

	"k8s.io/client-go/tools/cache"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	oss "github.com/cilium/tetragon/pkg/watcher"

	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/dns"
)

const (
	podInfoIPsIdx       = "pod-info-ips"
	podInfoInformerName = "podInfo"
)

var (
	errNoPodInfo = errors.New("object is not a *PodInfo")
)

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

func AddPodInfoInformer(w oss.Watcher) error {
	if w == nil {
		return fmt.Errorf("k8s watcher not initialized")
	}
	factory := w.GetCRDInformerFactory()
	if factory == nil {
		return fmt.Errorf("CRD informer factory not initialized")
	}

	// add informer to the watcher
	informer := factory.Cilium().V1alpha1().PodInfo().Informer()
	w.AddInformer(podInfoInformerName, informer, map[string]cache.IndexFunc{
		podInfoIPsIdx: podInfoIPIndexFunc,
	})

	// The endpoint cache will be initialized here if it wasn't before. This
	// has to happen before the event handler is started and sensors are
	// loaded, to ensure we have maps and caches configured, and avoid racing
	// with sensor coming online. Get() returns nil if feature is not enabled.
	c := endpoint.Get()
	if c != nil {
		informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				switch t := obj.(type) {
				case *v1alpha1.PodInfo:
					c := endpoint.Get()
					logger.GetLogger().Debug("Add Pod: %v", t)
					c.AddIpPodMap(t)
					dns.CheckPodAdd(t)
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

	return nil
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

func FindPodInfoByNS(watcher oss.K8sResourceWatcher, ns string) ([]*v1alpha1.PodInfo, error) {
	var nsPods []*v1alpha1.PodInfo

	podInfoInformer := watcher.GetInformer(podInfoInformerName)
	if podInfoInformer == nil {
		return nil, fmt.Errorf("pod informer not initialized")
	}
	allPods := podInfoInformer.GetStore().List()
	for i := range allPods {
		if pod, ok := allPods[i].(*v1alpha1.PodInfo); ok {
			if pod.ObjectMeta.Namespace == ns {
				nsPods = append(nsPods, pod)
			}
		}
	}
	return nsPods, nil
}
