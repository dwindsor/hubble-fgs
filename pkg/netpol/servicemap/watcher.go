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
	"net/netip"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/manager"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/client-go/tools/cache"
)

// AddServiceInformer sets up informers to watch Services and EndpointSlices.
// The provided ServiceMap will be updated when services or endpoints change.
func AddServiceInformer(ctx context.Context, m *manager.ControllerManager, sm *ServiceMap) error {
	log := logger.GetLogger().With("component", "service-watcher")

	log.Info("Initializing ServiceMap watcher for TNP serviceSelector support")

	// Watch Services
	svcInformer, err := m.Manager.GetCache().GetInformer(ctx, &corev1.Service{})
	if err != nil {
		return err
	}

	_, err = svcInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			svc, ok := obj.(*corev1.Service)
			if !ok {
				return
			}
			addService(sm, svc)
			log.Debug("ServiceMap: Service added", "name", svc.Name, "namespace", svc.Namespace, "clusterIP", svc.Spec.ClusterIP)
		},
		UpdateFunc: func(_, newObj interface{}) {
			svc, ok := newObj.(*corev1.Service)
			if !ok {
				return
			}
			addService(sm, svc)
			log.Debug("Service updated", "name", svc.Name, "namespace", svc.Namespace, "clusterIP", svc.Spec.ClusterIP)
		},
		DeleteFunc: func(obj interface{}) {
			if dfsu, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				obj = dfsu.Obj
			}
			svc, ok := obj.(*corev1.Service)
			if !ok {
				return
			}
			sm.Delete(svc.Namespace, svc.Name)
			log.Debug("Service deleted", "name", svc.Name, "namespace", svc.Namespace)
		},
	})
	if err != nil {
		return err
	}

	// Watch EndpointSlices for endpoint updates
	epsInformer, err := m.Manager.GetCache().GetInformer(ctx, &discoveryv1.EndpointSlice{})
	if err != nil {
		log.Warn("Failed to create EndpointSlice informer, endpoint tracking disabled", "error", err)
		return nil // Non-fatal, service matching will still work without endpoint details
	}

	_, err = epsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			eps, ok := obj.(*discoveryv1.EndpointSlice)
			if !ok {
				return
			}
			updateEndpointsFromSlice(sm, eps)
		},
		UpdateFunc: func(_, newObj interface{}) {
			eps, ok := newObj.(*discoveryv1.EndpointSlice)
			if !ok {
				return
			}
			updateEndpointsFromSlice(sm, eps)
		},
		DeleteFunc: func(_ interface{}) {
			// EndpointSlice deletion - would need to track which endpoints came from which slice
			// For now, endpoints will be refreshed on next EndpointSlice update
		},
	})

	return err
}

func addService(sm *ServiceMap, svc *corev1.Service) {
	// Skip headless services (ClusterIP = "None")
	if svc.Spec.ClusterIP == "None" || svc.Spec.ClusterIP == "" {
		return
	}

	clusterIP, err := netip.ParseAddr(svc.Spec.ClusterIP)
	if err != nil {
		return // Invalid IP, skip
	}

	var clusterIPs []netip.Addr
	for _, ipStr := range svc.Spec.ClusterIPs {
		if ip, err := netip.ParseAddr(ipStr); err == nil {
			clusterIPs = append(clusterIPs, ip)
		}
	}

	info := &ServiceInfo{
		Name:       svc.Name,
		Namespace:  svc.Namespace,
		ClusterIP:  clusterIP,
		ClusterIPs: clusterIPs,
		Labels:     svc.Labels,
		Selector:   svc.Spec.Selector,
	}

	sm.AddOrUpdate(info)
}

func updateEndpointsFromSlice(sm *ServiceMap, eps *discoveryv1.EndpointSlice) {
	// Get service name from the owner label
	svcName, ok := eps.Labels[discoveryv1.LabelServiceName]
	if !ok {
		return
	}

	var endpoints []EndpointInfo
	for _, ep := range eps.Endpoints {
		if ep.Conditions.Ready == nil || !*ep.Conditions.Ready {
			continue
		}
		for _, addr := range ep.Addresses {
			ip, err := netip.ParseAddr(addr)
			if err != nil {
				continue // Skip invalid IPs
			}
			for _, port := range eps.Ports {
				if port.Port == nil {
					continue
				}
				protocol := "TCP"
				if port.Protocol != nil {
					protocol = string(*port.Protocol)
				}
				podName := ""
				if ep.TargetRef != nil && ep.TargetRef.Kind == "Pod" {
					podName = ep.TargetRef.Name
				}
				endpoints = append(endpoints, EndpointInfo{
					IP:       ip,
					Port:     *port.Port,
					Protocol: protocol,
					PodName:  podName,
				})
			}
		}
	}

	sm.UpdateEndpoints(eps.Namespace, svcName, endpoints)
}
