// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package servicemap

import (
	"net/netip"
	"sync"

	"k8s.io/apimachinery/pkg/types"
)

// ServiceInfo contains information about a Kubernetes Service
type ServiceInfo struct {
	Name       string
	Namespace  string
	ClusterIP  netip.Addr
	ClusterIPs []netip.Addr
	Labels     map[string]string
	Selector   map[string]string
	Endpoints  []EndpointInfo
}

// EndpointInfo contains information about a Service endpoint (backend pod)
type EndpointInfo struct {
	IP       netip.Addr
	Port     int32
	Protocol string
	PodName  string
}

type EventHandler interface {
	HandleEndpointChange(namespace, name string, oldEndpoints, newEndpoints []EndpointInfo)
	HandleServiceDelete(namespace, name string, endpoints []EndpointInfo)
}

// ServiceMap tracks Kubernetes Services and provides ClusterIP -> Service lookup
type ServiceMap struct {
	mu sync.RWMutex
	// byClusterIP maps ClusterIP -> ServiceInfo
	byClusterIP map[netip.Addr]*ServiceInfo
	// byName maps namespace/name -> ServiceInfo
	byName  map[types.NamespacedName]*ServiceInfo
	handler EventHandler
}

// NewServiceMap creates a new ServiceMap
func NewServiceMap(handler EventHandler) *ServiceMap {
	return &ServiceMap{
		byClusterIP: make(map[netip.Addr]*ServiceInfo),
		byName:      make(map[types.NamespacedName]*ServiceInfo),
		handler:     handler,
	}
}

// AddOrUpdate adds or updates a service in the map
func (sm *ServiceMap) AddOrUpdate(svc *ServiceInfo) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	key := types.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}

	// Remove old ClusterIP mappings if service exists
	if old, ok := sm.byName[key]; ok {
		if old.ClusterIP.IsValid() {
			delete(sm.byClusterIP, old.ClusterIP)
		}
		for _, ip := range old.ClusterIPs {
			if ip.IsValid() {
				delete(sm.byClusterIP, ip)
			}
		}
	}

	// Add new mappings
	sm.byName[key] = svc
	if svc.ClusterIP.IsValid() {
		sm.byClusterIP[svc.ClusterIP] = svc
	}
	for _, ip := range svc.ClusterIPs {
		if ip.IsValid() {
			sm.byClusterIP[ip] = svc
		}
	}
}

// Delete removes a service from the map
func (sm *ServiceMap) Delete(namespace, name string) {
	sm.mu.Lock()
	var endpoints []EndpointInfo
	key := types.NamespacedName{Namespace: namespace, Name: name}
	if svc, ok := sm.byName[key]; ok {
		endpoints = svc.Endpoints
		if svc.ClusterIP.IsValid() {
			delete(sm.byClusterIP, svc.ClusterIP)
		}
		for _, ip := range svc.ClusterIPs {
			if ip.IsValid() {
				delete(sm.byClusterIP, ip)
			}
		}
		delete(sm.byName, key)
	}
	sm.mu.Unlock()

	// Notify handler to remove endpoint CIDR records
	if sm.handler != nil && len(endpoints) > 0 {
		sm.handler.HandleServiceDelete(namespace, name, endpoints)
	}
}

// GetByClusterIP looks up a service by its ClusterIP
func (sm *ServiceMap) GetByClusterIP(ip netip.Addr) *ServiceInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.byClusterIP[ip]
}

// GetByName looks up a service by namespace and name
func (sm *ServiceMap) GetByName(namespace, name string) *ServiceInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.byName[types.NamespacedName{Namespace: namespace, Name: name}]
}

// UpdateEndpoints updates the endpoints for a service
func (sm *ServiceMap) UpdateEndpoints(namespace, name string, endpoints []EndpointInfo) {
	sm.mu.Lock()
	var oldEndpoints []EndpointInfo
	key := types.NamespacedName{Namespace: namespace, Name: name}
	svcExists := false
	if svc, ok := sm.byName[key]; ok {
		svcExists = true
		oldEndpoints = svc.Endpoints
		svc.Endpoints = endpoints
	}
	sm.mu.Unlock()

	// Notify handler of endpoint changes
	if sm.handler != nil {
		sm.handler.HandleEndpointChange(namespace, name, oldEndpoints, endpoints)
	} else if svcExists {
		// Log warning if callback not set but service exists
		// This would indicate initialization order issue
		println("WARNING: servicemap.OnEndpointChange is nil, endpoint changes won't update policies")
	}
}

// GetAllServices returns all tracked services
func (sm *ServiceMap) GetAllServices() []*ServiceInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	services := make([]*ServiceInfo, 0, len(sm.byName))
	for _, svc := range sm.byName {
		services = append(services, svc)
	}
	return services
}

// IsServiceClusterIP returns true if the given IP is a known Service ClusterIP
func (sm *ServiceMap) IsServiceClusterIP(ip netip.Addr) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	_, ok := sm.byClusterIP[ip]
	return ok
}
