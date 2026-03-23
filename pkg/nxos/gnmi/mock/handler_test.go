// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package mock

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
)

// compile-time check that normalizePath is accessible (used in tests)
var _ = normalizePath

// TestMockHandler_RegisterAndRoute verifies that RegisterHandler stores handlers
// and Route dispatches notifications to matching handlers.
func TestMockHandler_RegisterAndRoute(t *testing.T) {
	h := NewHandlerBuilder().Build()

	var callCount int32
	var receivedPath string
	var mu sync.Mutex

	h.RegisterHandler(func(path string, update *gnmiproto.Update, isDelete bool) {
		atomic.AddInt32(&callCount, 1)
		mu.Lock()
		receivedPath = path
		mu.Unlock()
	}, paths.DPUStoreInitState, paths.DPUStoreNumDPUs)

	// Route a matching path
	h.Route(paths.DPUStoreInitState, makeStringUpdate("inventory-done"), false)

	if atomic.LoadInt32(&callCount) != 1 {
		t.Errorf("expected handler called 1 time, got %d", atomic.LoadInt32(&callCount))
	}
	mu.Lock()
	if receivedPath != paths.DPUStoreInitState {
		t.Errorf("expected path %q, got %q", paths.DPUStoreInitState, receivedPath)
	}
	mu.Unlock()

	// Route a non-matching path — handler should not be called
	h.Route(paths.VrfStoreGlobalVrf, makeStringUpdate("default"), false)
	if atomic.LoadInt32(&callCount) != 1 {
		t.Errorf("expected handler still called 1 time after non-matching route, got %d", atomic.LoadInt32(&callCount))
	}
}

// TestMockHandler_StartSubscriptions_PopulatesDPUs verifies that StartSubscriptions
// fires DPU notifications so DPU handlers receive the expected data.
func TestMockHandler_StartSubscriptions_PopulatesDPUs(t *testing.T) {
	numDPUs := 2
	h := NewHandlerBuilder().WithTree(DPUTree(numDPUs)).Build()

	type dpuNotif struct {
		path  string
		value string
	}
	var mu sync.Mutex
	var notifs []dpuNotif

	collectHandler := func(path string, update *gnmiproto.Update, isDelete bool) {
		if val, ok := extractString(update); ok {
			mu.Lock()
			notifs = append(notifs, dpuNotif{path: path, value: val})
			mu.Unlock()
		}
	}

	h.RegisterHandler(collectHandler,
		paths.DPUStoreInitState,
		paths.DPUStoreNumDPUs,
		paths.DPUStoreIP,
		paths.DPUStoreState,
		paths.DPUStoreVersion,
	)

	h.StartSubscriptions(context.Background())

	// Verify initState notification was fired
	mu.Lock()
	defer mu.Unlock()

	foundInitState := false
	ipCount := 0
	for _, n := range notifs {
		if paths.PathMatches(n.path, paths.DPUStoreInitState) {
			if n.value != "inventory-done" {
				t.Errorf("expected initState=inventory-done, got %q", n.value)
			}
			foundInitState = true
		}
		if paths.PathMatches(n.path, paths.DPUStoreIP) {
			ipCount++
		}
	}

	if !foundInitState {
		t.Error("expected DPUStoreInitState notification, got none")
	}
	if ipCount != numDPUs {
		t.Errorf("expected %d IP notifications, got %d", numDPUs, ipCount)
	}
}

// TestMockHandler_StartSubscriptions_PopulatesVRFs verifies that StartSubscriptions
// fires VRF notifications (global, service, affinity) so VRF handlers receive the
// expected VRF names and affinity values.
func TestMockHandler_StartSubscriptions_PopulatesVRFs(t *testing.T) {
	vrfs := []VRFEntry{
		{Name: "default", Affinity: 0},
		{Name: "management", Affinity: 1},
	}
	h := NewHandlerBuilder().WithTree(VRFTree(vrfs...)).Build()

	var mu sync.Mutex
	receivedVRFs := make(map[string]bool)
	receivedAffinities := make(map[string]uint64)

	h.RegisterHandler(func(path string, update *gnmiproto.Update, isDelete bool) {
		if val, ok := extractString(update); ok {
			mu.Lock()
			receivedVRFs[val] = true
			mu.Unlock()
		}
	}, paths.VrfStoreGlobalVrf)

	h.RegisterHandler(func(path string, update *gnmiproto.Update, isDelete bool) {
		if update != nil && update.Val != nil {
			if uv, ok := update.Val.Value.(*gnmiproto.TypedValue_UintVal); ok {
				mu.Lock()
				receivedAffinities[path] = uv.UintVal
				mu.Unlock()
			}
		}
	}, paths.VrfStoreServiceVrfAffinity)

	h.StartSubscriptions(context.Background())

	mu.Lock()
	defer mu.Unlock()

	for _, vrf := range vrfs {
		if !receivedVRFs[vrf.Name] {
			t.Errorf("expected VRF %q notification, but did not receive it", vrf.Name)
		}
		affinityPath := "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/ipvrf-items/dom-items/Dom-list[name=" + vrf.Name + "]/affinity"
		if got, ok := receivedAffinities[affinityPath]; !ok {
			t.Errorf("expected affinity notification for VRF %q, but did not receive it", vrf.Name)
		} else if got != uint64(vrf.Affinity) {
			t.Errorf("VRF %q: expected affinity %d, got %d", vrf.Name, vrf.Affinity, got)
		}
	}
}

// extractString is a test helper that pulls the string value from a gNMI Update.
func extractString(update *gnmiproto.Update) (string, bool) {
	if update == nil || update.Val == nil {
		return "", false
	}
	sv, ok := update.Val.Value.(*gnmiproto.TypedValue_StringVal)
	if !ok {
		return "", false
	}
	return sv.StringVal, true
}

// TestMockHandler_GetAllData verifies that GetAllData returns a shallow copy of all stored data.
func TestMockHandler_GetAllData(t *testing.T) {
	h := NewHandlerBuilder().Build()
	h.data["System/foo"] = "bar"
	h.data["System/baz"] = "qux"

	all := h.GetAllData()
	// The handler is pre-populated by the builder; we just verify our keys are present.
	if all["System/foo"] != "bar" {
		t.Errorf("expected System/foo=bar, got %v", all["System/foo"])
	}
	if all["System/baz"] != "qux" {
		t.Errorf("expected System/baz=qux, got %v", all["System/baz"])
	}

	// Mutations to the copy must not affect the handler.
	sizeBefore := len(h.GetAllData())
	all["System/new-copy-only"] = "value"
	if len(h.GetAllData()) != sizeBefore {
		t.Error("mutation of returned copy should not affect handler data")
	}
}

// TestMockHandler_GetData verifies GetData returns values by path with normalization.
func TestMockHandler_GetData(t *testing.T) {
	h := NewHandlerBuilder().Build()
	h.data["System/foo"] = "bar"

	// Exact normalized path
	val, ok := h.GetData("device:/System/foo")
	if !ok {
		t.Error("expected GetData to find path after normalization")
	}
	if val != "bar" {
		t.Errorf("expected bar, got %v", val)
	}

	// Non-existent path
	_, ok = h.GetData("device:/System/nonexistent")
	if ok {
		t.Error("expected GetData to return false for nonexistent path")
	}
}

// TestMockHandler_SetAndNotify verifies SetAndNotify stores the value and routes notifications.
func TestMockHandler_SetAndNotify(t *testing.T) {
	ctx := context.Background()

	t.Run("stores value", func(t *testing.T) {
		h := NewHandlerBuilder().Build()
		if err := h.SetAndNotify(ctx, "device:/System/foo", `"test"`); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		val, ok := h.GetData("device:/System/foo")
		if !ok {
			t.Error("expected value to be stored after SetAndNotify")
		}
		if val != `"test"` {
			t.Errorf("expected %q, got %v", `"test"`, val)
		}
	})

	t.Run("fires Route notification", func(t *testing.T) {
		h := NewHandlerBuilder().Build()

		var notified bool
		h.RegisterHandler(func(path string, update *gnmiproto.Update, isDelete bool) {
			notified = true
		}, paths.VrfStoreGlobalVrf)

		// Use a path matching VrfStoreGlobalVrf
		if err := h.SetAndNotify(ctx, paths.VrfStoreGlobalVrf, "default"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !notified {
			t.Error("expected subscriber to be notified after SetAndNotify")
		}
	})

	t.Run("isDelete is false in notification", func(t *testing.T) {
		h := NewHandlerBuilder().Build()

		var gotDelete bool
		h.RegisterHandler(func(_ string, _ *gnmiproto.Update, isDelete bool) {
			gotDelete = isDelete
		}, paths.VrfStoreGlobalVrf)

		if err := h.SetAndNotify(ctx, paths.VrfStoreGlobalVrf, "default"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gotDelete {
			t.Error("expected isDelete=false in SetAndNotify notification")
		}
	})
}

// TestMockHandler_DeleteAndNotify verifies DeleteAndNotify removes the value and routes notifications.
func TestMockHandler_DeleteAndNotify(t *testing.T) {
	ctx := context.Background()

	t.Run("removes value", func(t *testing.T) {
		h := NewHandlerBuilder().Build()
		h.data["System/foo"] = "bar"
		if err := h.DeleteAndNotify(ctx, "device:/System/foo"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_, ok := h.GetData("device:/System/foo")
		if ok {
			t.Error("expected value to be removed after DeleteAndNotify")
		}
	})

	t.Run("fires Route notification with isDelete=true", func(t *testing.T) {
		h := NewHandlerBuilder().Build()
		h.data[normalizePath(paths.VrfStoreGlobalVrf)] = "default"

		var notified bool
		var gotDelete bool
		h.RegisterHandler(func(_ string, _ *gnmiproto.Update, isDelete bool) {
			notified = true
			gotDelete = isDelete
		}, paths.VrfStoreGlobalVrf)

		if err := h.DeleteAndNotify(ctx, paths.VrfStoreGlobalVrf); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !notified {
			t.Error("expected subscriber to be notified after DeleteAndNotify")
		}
		if !gotDelete {
			t.Error("expected isDelete=true in DeleteAndNotify notification")
		}
	})

	t.Run("delete nonexistent path is a no-op", func(t *testing.T) {
		h := NewHandlerBuilder().Build()
		if err := h.DeleteAndNotify(ctx, "device:/System/nonexistent"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// TestMockHandler_UnregisterHandler verifies that UnregisterHandler is a no-op
// (the interface requires the method to exist, but the mock doesn't need to
// track unregistrations in the test context).
func TestMockHandler_UnregisterHandler(t *testing.T) {
	h := NewHandlerBuilder().Build()

	var callCount int32
	cb := gnmi.SubscriptionCallback(func(path string, update *gnmiproto.Update, isDelete bool) {
		atomic.AddInt32(&callCount, 1)
	})

	h.RegisterHandler(cb, paths.DPUStoreInitState)
	h.UnregisterHandler(cb)

	// Route — whether called or not depends on implementation, just verify no panic
	h.Route(paths.DPUStoreInitState, makeStringUpdate("test"), false)
	// No assertion on count since UnregisterHandler is a no-op for mock
}

// TestMockHandler_Persistence verifies that SetAndNotify persists data and a new
// handler with the same persist path loads it.
func TestMockHandler_Persistence(t *testing.T) {
	ctx := context.Background()
	persistFile := filepath.Join(t.TempDir(), "mock_gnmi.json")

	// Create handler with persistence, set a value
	h1 := NewHandlerBuilder().WithPersistPath(persistFile).Build()
	if err := h1.SetAndNotify(ctx, "device:/System/test/key", "hello"); err != nil {
		t.Fatalf("SetAndNotify failed: %v", err)
	}

	// Verify file was written
	if _, err := os.Stat(persistFile); err != nil {
		t.Fatalf("persist file not created: %v", err)
	}

	// Create a new handler with same persist path — should load the value
	h2 := NewHandlerBuilder().WithPersistPath(persistFile).Build()
	val, ok := h2.GetData("device:/System/test/key")
	if !ok {
		t.Fatal("expected persisted value to be loaded in new handler")
	}
	if val != "hello" {
		t.Errorf("expected %q, got %v", "hello", val)
	}
}

// TestMockHandler_Persistence_Delete verifies that DeleteAndNotify updates the persisted file.
func TestMockHandler_Persistence_Delete(t *testing.T) {
	ctx := context.Background()
	persistFile := filepath.Join(t.TempDir(), "mock_gnmi.json")

	h1 := NewHandlerBuilder().WithPersistPath(persistFile).Build()
	if err := h1.SetAndNotify(ctx, "device:/System/test/key", "hello"); err != nil {
		t.Fatalf("SetAndNotify failed: %v", err)
	}
	if err := h1.DeleteAndNotify(ctx, "device:/System/test/key"); err != nil {
		t.Fatalf("DeleteAndNotify failed: %v", err)
	}

	// New handler should not have the deleted key
	h2 := NewHandlerBuilder().WithPersistPath(persistFile).Build()
	_, ok := h2.GetData("device:/System/test/key")
	if ok {
		t.Error("expected deleted value to not be present in new handler")
	}
}

// TestMockHandler_Persistence_NoPersistPath verifies no-op when no persist path is set.
func TestMockHandler_Persistence_NoPersistPath(t *testing.T) {
	ctx := context.Background()
	h := NewHandlerBuilder().Build()
	// Should not panic or error
	if err := h.SetAndNotify(ctx, "device:/System/test/key", "hello"); err != nil {
		t.Fatalf("SetAndNotify failed: %v", err)
	}
}

// TestTreeToFlat verifies the tree-to-flat-paths conversion.
func TestTreeToFlat(t *testing.T) {
	tree := map[string]interface{}{
		"System": map[string]interface{}{
			"ch-items": map[string]interface{}{
				"spbp-items": map[string]interface{}{
					"spcmn-items": map[string]interface{}{
						"serialNum": "MOCK-SERIAL-001",
					},
				},
			},
			"sas-items": map[string]interface{}{
				"globalpol-items": map[string]interface{}{
					"lbMode": "symmetric_hash",
				},
			},
		},
	}

	flat := TreeToFlat(tree)

	expected := map[string]string{
		"System/ch-items/spbp-items/spcmn-items/serialNum": "MOCK-SERIAL-001",
		"System/sas-items/globalpol-items/lbMode":          "symmetric_hash",
	}

	if len(flat) != len(expected) {
		t.Errorf("expected %d entries, got %d: %v", len(expected), len(flat), flat)
	}
	for k, v := range expected {
		if flat[k] != v {
			t.Errorf("expected %q=%q, got %q", k, v, flat[k])
		}
	}
}

// TestTreeToFlat_ArrayLeaf verifies arrays are treated as leaf values.
func TestTreeToFlat_ArrayLeaf(t *testing.T) {
	tree := map[string]interface{}{
		"items": map[string]interface{}{
			"list": []interface{}{"a", "b", "c"},
		},
	}

	flat := TreeToFlat(tree)
	val, ok := flat["items/list"]
	if !ok {
		t.Fatal("expected items/list in flat map")
	}
	if val != `["a","b","c"]` {
		t.Errorf("expected JSON array, got %q", val)
	}
}
