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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/tetragon/pkg/logger"
	oss "github.com/cilium/tetragon/pkg/watcher"

	"github.com/isovalent/hubble-fgs/pkg/endpoint"
)

const (
	serviceIPsIdx       = "service-ips"
	serviceInformerName = "service"
)

var (
	errNoService = errors.New("object is not a *corev1.Service")
)

// serviceIPIndexFunc indexes services by their IP addresses
func serviceIPIndexFunc(obj interface{}) ([]string, error) {
	switch t := obj.(type) {
	case *corev1.Service:
		return t.Spec.ClusterIPs, nil
	}
	return nil, fmt.Errorf("%w - found %T", errNoService, obj)
}

func AddServiceInformer(w oss.Watcher, enableProcessTree bool) error {
	if w == nil {
		return fmt.Errorf("k8s watcher not initialized")
	}
	factory := w.GetK8sInformerFactory()
	if factory == nil {
		return fmt.Errorf("k8s informer factory not initialized")
	}

	// add informer to the watcher
	informer := factory.Core().V1().Services().Informer()
	w.AddInformer(serviceInformerName, informer, map[string]cache.IndexFunc{
		serviceIPsIdx: serviceIPIndexFunc,
	})
	if !enableProcessTree {
		return nil
	}

	// The endpoint cache will be initialized here if it wasn't before. This
	// has to happen before the event handler is started and sensors are
	// loaded, to ensure we have maps and caches configured, and avoid racing
	// with sensor coming online.
	c := endpoint.MustGet()
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			switch s := obj.(type) {
			case *corev1.Service:
				logger.GetLogger().Debug("Add Service: %v", s)
				c.AddIpServiceMap(s)
			}
		},
		UpdateFunc: func(old interface{}, _ interface{}) {
			switch s := old.(type) {
			case *corev1.Service:
				logger.GetLogger().Debug("Update Service: %v", s)
			}
		},
		DeleteFunc: func(old interface{}) {
			switch s := old.(type) {
			case *corev1.Service:
				logger.GetLogger().Debug("Delete Service: %v", s)
			}
		},
	})
	return nil
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
