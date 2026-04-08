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
	"testing"
)

func TestServiceMap_AddAndGet(t *testing.T) {
	sm := NewServiceMap(nil)

	clusterIP := netip.MustParseAddr("10.96.0.100")
	svc := &ServiceInfo{
		Name:       "test-svc",
		Namespace:  "default",
		ClusterIP:  clusterIP,
		ClusterIPs: []netip.Addr{clusterIP},
		Labels:     map[string]string{"app": "test"},
		Selector:   map[string]string{"app": "test-pod"},
	}

	sm.AddOrUpdate(svc)

	// Test GetByName
	got := sm.GetByName("default", "test-svc")
	if got == nil {
		t.Fatal("GetByName returned nil")
	}
	if got.ClusterIP != clusterIP {
		t.Errorf("GetByName ClusterIP = %v, want %v", got.ClusterIP, clusterIP)
	}

	// Test GetByClusterIP
	got = sm.GetByClusterIP(clusterIP)
	if got == nil {
		t.Fatal("GetByClusterIP returned nil")
	}
	if got.Name != "test-svc" {
		t.Errorf("GetByClusterIP Name = %q, want %q", got.Name, "test-svc")
	}

	// Test IsServiceClusterIP
	if !sm.IsServiceClusterIP(clusterIP) {
		t.Error("IsServiceClusterIP returned false, want true")
	}
	if sm.IsServiceClusterIP(netip.MustParseAddr("10.96.0.101")) {
		t.Error("IsServiceClusterIP returned true for unknown IP, want false")
	}
}

func TestServiceMap_Update(t *testing.T) {
	sm := NewServiceMap(nil)

	oldIP := netip.MustParseAddr("10.96.0.100")
	newIP := netip.MustParseAddr("10.96.0.200")

	svc := &ServiceInfo{
		Name:      "test-svc",
		Namespace: "default",
		ClusterIP: oldIP,
	}
	sm.AddOrUpdate(svc)

	// Update with new ClusterIP
	svc2 := &ServiceInfo{
		Name:      "test-svc",
		Namespace: "default",
		ClusterIP: newIP,
	}
	sm.AddOrUpdate(svc2)

	// Old IP should not exist
	if sm.IsServiceClusterIP(oldIP) {
		t.Error("Old ClusterIP should be removed after update")
	}

	// New IP should exist
	if !sm.IsServiceClusterIP(newIP) {
		t.Error("New ClusterIP should exist after update")
	}
}

func TestServiceMap_Delete(t *testing.T) {
	sm := NewServiceMap(nil)

	clusterIP := netip.MustParseAddr("10.96.0.100")
	svc := &ServiceInfo{
		Name:      "test-svc",
		Namespace: "default",
		ClusterIP: clusterIP,
	}
	sm.AddOrUpdate(svc)

	sm.Delete("default", "test-svc")

	if sm.GetByName("default", "test-svc") != nil {
		t.Error("GetByName should return nil after delete")
	}
	if sm.IsServiceClusterIP(clusterIP) {
		t.Error("ClusterIP should not exist after delete")
	}
}

func TestServiceMap_UpdateEndpoints(t *testing.T) {
	sm := NewServiceMap(nil)

	svc := &ServiceInfo{
		Name:      "test-svc",
		Namespace: "default",
		ClusterIP: netip.MustParseAddr("10.96.0.100"),
	}
	sm.AddOrUpdate(svc)

	endpoints := []EndpointInfo{
		{IP: netip.MustParseAddr("10.0.0.1"), Port: 80, Protocol: "TCP", PodName: "pod-1"},
		{IP: netip.MustParseAddr("10.0.0.2"), Port: 80, Protocol: "TCP", PodName: "pod-2"},
	}
	sm.UpdateEndpoints("default", "test-svc", endpoints)

	got := sm.GetByName("default", "test-svc")
	if got == nil {
		t.Fatal("GetByName returned nil")
	}
	if len(got.Endpoints) != 2 {
		t.Errorf("Endpoints count = %d, want 2", len(got.Endpoints))
	}
}

func TestServiceMap_GetAllServices(t *testing.T) {
	sm := NewServiceMap(nil)

	sm.AddOrUpdate(&ServiceInfo{Name: "svc-1", Namespace: "ns-1", ClusterIP: netip.MustParseAddr("10.96.0.1")})
	sm.AddOrUpdate(&ServiceInfo{Name: "svc-2", Namespace: "ns-1", ClusterIP: netip.MustParseAddr("10.96.0.2")})
	sm.AddOrUpdate(&ServiceInfo{Name: "svc-3", Namespace: "ns-2", ClusterIP: netip.MustParseAddr("10.96.0.3")})

	all := sm.GetAllServices()
	if len(all) != 3 {
		t.Errorf("GetAllServices count = %d, want 3", len(all))
	}
}

func TestServiceMap_HeadlessService(t *testing.T) {
	sm := NewServiceMap(nil)

	// Headless services have no valid ClusterIP (zero value)
	svc := &ServiceInfo{
		Name:      "headless-svc",
		Namespace: "default",
		ClusterIP: netip.Addr{}, // Zero value = invalid, simulating "None"
	}
	sm.AddOrUpdate(svc)

	// Should not be indexed by ClusterIP (invalid addr)
	if sm.IsServiceClusterIP(netip.Addr{}) {
		t.Error("Headless service with invalid ClusterIP should not be indexed")
	}

	// But should still be retrievable by name
	got := sm.GetByName("default", "headless-svc")
	if got == nil {
		t.Fatal("GetByName should still work for headless services")
	}
}
