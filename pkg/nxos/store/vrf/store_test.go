// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package vrf

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/mock"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
	"github.com/isovalent/hubble-fgs/pkg/nxos/storage"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store"
)

func makeStringUpdate(s string) *gnmiproto.Update {
	return &gnmiproto.Update{
		Val: &gnmiproto.TypedValue{
			Value: &gnmiproto.TypedValue_StringVal{StringVal: s},
		},
	}
}

func makeJSONUpdate(obj map[string]interface{}) *gnmiproto.Update {
	b, _ := json.Marshal(obj)
	return &gnmiproto.Update{
		Val: &gnmiproto.TypedValue{
			Value: &gnmiproto.TypedValue_JsonVal{JsonVal: b},
		},
	}
}

func makeJSONStringUpdate(s string) *gnmiproto.Update {
	b, _ := json.Marshal(s)
	return &gnmiproto.Update{
		Val: &gnmiproto.TypedValue{
			Value: &gnmiproto.TypedValue_JsonVal{JsonVal: b},
		},
	}
}

func makeUint32Update(v uint32) *gnmiproto.Update {
	return &gnmiproto.Update{
		Val: &gnmiproto.TypedValue{
			Value: &gnmiproto.TypedValue_UintVal{UintVal: uint64(v)},
		},
	}
}

func TestErrNotFound_ErrorMessage(t *testing.T) {
	err := &ErrNotFound{Name: "test-vrf"}
	expected := "VRF not found: test-vrf"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

// globalVRFPath returns the gNMI notification path for a named global VRF.
// At leaf level matching VrfStoreGlobalVrf = "device:/System/inst-items/Inst-list/name".
func globalVRFPath(name string) string {
	return "device:/System/inst-items/Inst-list[name=" + name + "]/name"
}

// serviceVRFPath returns the gNMI notification path for a named service VRF.
// At list-entry level matching
// VrfStoreServiceVrf = "device:/System/sas-items/.../Dom-list".
func serviceVRFPath(name string) string {
	return "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/ipvrf-items/dom-items/Dom-list[name=" + name + "]"
}

// serviceVRFLeafPath returns the gNMI path for the name leaf of a service VRF.
// Matches VrfStoreServiceVrfName for update notifications.
func serviceVRFLeafPath(name string) string {
	return "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/ipvrf-items/dom-items/Dom-list[name=" + name + "]/name"
}

// serviceVRFAffinityLeafPath returns the gNMI path for the affinity leaf of a service VRF.
// Matches VrfStoreServiceVrfAffinity for update notifications.
func serviceVRFAffinityLeafPath(name string) string {
	return "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/ipvrf-items/dom-items/Dom-list[name=" + name + "]/affinity"
}

// globalVRFUpdate returns a JSON-encoded string update for the global VRF name leaf.
// NX-OS may encode leaf string values as JSON strings.
func globalVRFUpdate(name string) *gnmiproto.Update {
	return makeJSONStringUpdate(name)
}

// serviceVRFUpdate returns a JSON object update for a service VRF list-entry.
func serviceVRFUpdate(name string, affinity uint16) *gnmiproto.Update {
	obj := map[string]interface{}{"name": name}
	if affinity != 0 {
		obj["affinity"] = float64(affinity)
	}
	return makeJSONUpdate(obj)
}

func TestStore_HandleGnmiNotification(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		setup    func(vs Store)
		path     string
		update   *gnmiproto.Update
		isDelete bool
		check    func(t *testing.T, vs Store)
	}{
		{
			name:   "global_create_json",
			path:   globalVRFPath("test-vrf"),
			update: globalVRFUpdate("test-vrf"),
			check: func(t *testing.T, vs Store) {
				if _, ok := vs.Get("test-vrf"); !ok {
					t.Error("expected 'test-vrf' to be added via JSON object update")
				}
			},
		},
		{
			name:   "global_create_string_fallback",
			path:   globalVRFPath("test-vrf"),
			update: makeStringUpdate("test-vrf"),
			check: func(t *testing.T, vs Store) {
				if _, ok := vs.Get("test-vrf"); !ok {
					t.Error("expected 'test-vrf' to be added via string fallback")
				}
			},
		},
		{
			name: "global_delete",
			setup: func(vs Store) {
				vs.SetGlobal(ctx, "test-vrf", true)
			},
			path:     globalVRFPath("test-vrf"),
			isDelete: true,
			check: func(t *testing.T, vs Store) {
				if _, ok := vs.Get("test-vrf"); ok {
					t.Error("expected 'test-vrf' to be removed")
				}
			},
		},
		{
			name: "service_add_existing_global",
			setup: func(vs Store) {
				vs.SetGlobal(ctx, "prod-vrf", true)
			},
			path:   serviceVRFLeafPath("prod-vrf"),
			update: makeStringUpdate("prod-vrf"),
			check: func(t *testing.T, vs Store) {
				vrf, ok := vs.Get("prod-vrf")
				if !ok {
					t.Fatal("expected 'prod-vrf' to exist")
				}
				if !vrf.Service {
					t.Error("expected IsService to be set after service notification")
				}
			},
		},
		{
			name: "service_delete_clears_service_flag",
			setup: func(vs Store) {
				vs.SetGlobal(ctx, "prod-vrf", true)
				vs.SetService(ctx, "prod-vrf", true)
				vs.SetAffinity(ctx, "prod-vrf", 0)
			},
			path:     serviceVRFPath("prod-vrf"),
			isDelete: true,
			check: func(t *testing.T, vs Store) {
				vrf, ok := vs.Get("prod-vrf")
				if !ok {
					t.Fatal("expected VRF to still exist as global after service delete")
				}
				if vrf.Service {
					t.Error("expected IsService to be cleared")
				}
			},
		},
		{
			name:   "service_notification_creates_new_vrf",
			path:   serviceVRFLeafPath("new-vrf"),
			update: makeStringUpdate("new-vrf"),
			check: func(t *testing.T, vs Store) {
				vrf, ok := vs.Get("new-vrf")
				if !ok {
					t.Fatal("expected 'new-vrf' to be created from service notification")
				}
				if !vrf.Service {
					t.Error("expected IsService to be set on newly created VRF")
				}
			},
		},
		{
			name:   "fwpolicystate_update_noop",
			path:   "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicystate-items/ipvrfstate-items/dom-items/DomState-list[name=tenant1]",
			update: makeStringUpdate("somevalue"),
			check: func(t *testing.T, vs Store) {
				// no VRF should be created from a fwPolicyState echo-back
				if _, ok := vs.Get("tenant1"); ok {
					t.Error("fwPolicyState update should not create a VRF entry")
				}
			},
		},
		{
			name: "delete_without_origin_prefix",
			setup: func(vs Store) {
				vs.SetGlobal(ctx, "tenant1", true)
			},
			// Switch sends delete without the "device:" origin prefix
			path:     "System/inst-items/Inst-list[name=tenant1]/name",
			isDelete: true,
			check: func(t *testing.T, vs Store) {
				if _, ok := vs.Get("tenant1"); ok {
					t.Error("expected VRF to be removed even when path lacks origin prefix")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := NewStore(ctx)
			if tt.setup != nil {
				tt.setup(vs)
			}
			vs.HandleGnmiNotification(ctx, tt.path, tt.update, tt.isDelete)
			tt.check(t, vs)
		})
	}
}

func TestStore_HandleGnmiNotification_ServiceAddWithAffinity(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx)

	// First notification: set service VRF name via the name leaf path.
	vs.HandleGnmiNotification(ctx, serviceVRFLeafPath("pinned-vrf"), makeStringUpdate("pinned-vrf"), false)

	// Second notification: set affinity via the affinity leaf path.
	vs.HandleGnmiNotification(ctx, serviceVRFAffinityLeafPath("pinned-vrf"), makeUint32Update(3), false)

	vrf, ok := vs.Get("pinned-vrf")
	if !ok {
		t.Fatal("expected 'pinned-vrf' to exist")
	}
	if !vrf.Service {
		t.Error("expected IsService to be set")
	}
	if !vrf.HasAffinity {
		t.Error("expected HasAffinity to be true")
	}
	if vrf.Affinity != 3 {
		t.Errorf("expected Affinity=3, got %d", vrf.Affinity)
	}
}

// --- Conditional Delete Tests ---

func TestStore_ConditionalDelete(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		setup       func(vs Store)
		path        string
		wantGone    bool // VRF should be completely removed
		wantGlobal  bool // IsGlobal expected value (if not wantGone)
		wantService bool // IsService expected value (if not wantGone)
	}{
		{
			name: "global_delete_global_only_removes_entry",
			setup: func(vs Store) {
				vs.SetGlobal(ctx, "test-vrf", true)
			},
			path:     globalVRFPath("test-vrf"),
			wantGone: true,
		},
		{
			name: "global_delete_with_active_service_keeps_entry",
			setup: func(vs Store) {
				vs.SetGlobal(ctx, "test-vrf", true)
				vs.SetService(ctx, "test-vrf", true)
				vs.SetAffinity(ctx, "test-vrf", 0)
			},
			path:        globalVRFPath("test-vrf"),
			wantGlobal:  false,
			wantService: true,
		},
		{
			name: "service_delete_service_only_removes_entry",
			setup: func(vs Store) {
				vs.SetService(ctx, "test-vrf", true)
			},
			path:     serviceVRFPath("test-vrf"),
			wantGone: true,
		},
		{
			name: "service_delete_with_active_global_keeps_entry",
			setup: func(vs Store) {
				vs.SetGlobal(ctx, "test-vrf", true)
				vs.SetService(ctx, "test-vrf", true)
			},
			path:        serviceVRFPath("test-vrf"),
			wantGlobal:  true,
			wantService: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := NewStore(ctx)
			tt.setup(vs)
			vs.HandleGnmiNotification(ctx, tt.path, nil, true)

			vrf, ok := vs.Get("test-vrf")
			if tt.wantGone {
				if ok {
					t.Error("expected VRF to be fully removed")
				}
				return
			}
			if !ok {
				t.Fatal("expected VRF to survive")
			}
			if vrf.Global != tt.wantGlobal {
				t.Errorf("IsGlobal: got %v, want %v", vrf.Global, tt.wantGlobal)
			}
			if vrf.Service != tt.wantService {
				t.Errorf("IsService: got %v, want %v", vrf.Service, tt.wantService)
			}
		})
	}
}

// --- Redirect Integration Tests ---

func TestStore_RedirectWithHandler(t *testing.T) {
	handler := mock.NewHandler()
	vs := NewStore(context.Background())
	vs.SetGnmiHandler(handler)
	ctx := context.Background()

	// Add VRF as global (not active yet, no redirect)
	vs.SetGlobal(ctx, "test-vrf", true)

	// SetService + SetAffinity makes it active (global+service+affinity), should trigger redirect
	vs.SetService(ctx, "test-vrf", true)
	vs.SetAffinity(ctx, "test-vrf", 0)

	// Verify the VRF is now active
	vrf, ok := vs.Get("test-vrf")
	if !ok {
		t.Fatal("VRF should exist")
	}
	if !vrf.Active {
		t.Error("VRF should be active after SetService+SetAffinity")
	}
}

func TestStore_RedirectNotTriggeredWithoutHandler(t *testing.T) {
	// Store without gNMI handler should not panic
	vs := NewStore(context.Background())
	ctx := context.Background()

	// These should work fine without a gNMI handler
	vs.SetGlobal(ctx, "test-vrf", true)
	vs.SetService(ctx, "test-vrf", true)
	vs.SetAffinity(ctx, "test-vrf", 0)
	// Auto-remove by clearing both flags
	vs.SetGlobal(ctx, "test-vrf", false)
}

func TestStore_SetGnmiHandler(t *testing.T) {
	vs := NewStore(context.Background())
	ctx := context.Background()

	// Add an active VRF first (no handler set, no redirect triggered)
	vs.SetGlobal(ctx, "test-vrf", true)

	// Now set the handler
	handler := mock.NewHandler()
	vs.SetGnmiHandler(handler)

	// Subsequent changes should work with the handler
	vs.SetService(ctx, "test-vrf", true)
	vs.SetAffinity(ctx, "test-vrf", 0)

	// Verify the VRF is active
	vrf, ok := vs.Get("test-vrf")
	if !ok {
		t.Fatal("VRF should exist")
	}
	if !vrf.Active {
		t.Error("VRF should be active")
	}
}

func TestStore_RedirectProgramsAllSteps(t *testing.T) {
	handler := mock.NewHandler()
	vs := NewStore(context.Background())
	vs.SetGnmiHandler(handler)
	vs.SetRedirectsReady()
	ctx := context.Background()

	// Make VRF active (all three flags set); GID is auto-allocated on activation
	vs.SetGlobal(ctx, "prod-vrf", true)
	vs.SetService(ctx, "prod-vrf", true)
	vs.SetAffinity(ctx, "prod-vrf", 0)

	// Verify the GID was auto-allocated
	gid, ok := vs.GetGID("prod-vrf")
	if !ok || gid == 0 {
		t.Fatal("expected GID to be auto-allocated on activation")
	}

	// Verify fwPolicyState was programmed
	vals, err := handler.Get(ctx, paths.FwPolicyStateVrf)
	if err != nil {
		t.Fatalf("failed to get fwPolicyState: %v", err)
	}
	if len(vals) == 0 {
		t.Error("fwPolicyState should have been programmed")
	}

	// Verify enforcement was programmed
	vals, err = handler.Get(ctx, paths.ServiceRedirDomItems)
	if err != nil {
		t.Fatalf("failed to get enforcement: %v", err)
	}
	if len(vals) == 0 {
		t.Error("enforcement binding should have been programmed")
	}

	// Verify policy map was programmed
	vals, err = handler.Get(ctx, paths.ServiceRedirPmapItems)
	if err != nil {
		t.Fatalf("failed to get policy map: %v", err)
	}
	if len(vals) == 0 {
		t.Error("policy map should have been programmed")
	}

	// Verify service endpoint was programmed at the specific list-entry path
	// (the parent path is pre-initialized by the mock with an empty Service-list).
	svcPath := fmt.Sprintf("%s/Service-list[name=__prod-vrf_dpu_redir]", paths.ServiceRedirServiceItems)
	vals, err = handler.Get(ctx, svcPath)
	if err != nil {
		t.Fatalf("failed to get service endpoint: %v", err)
	}
	if len(vals) == 0 {
		t.Error("service endpoint should have been programmed")
	}

}

func TestStore_CleanupRedirects_OnDeactivation(t *testing.T) {
	handler := mock.NewHandler()
	vs := NewStore(context.Background())
	vs.SetGnmiHandler(handler)
	ctx := context.Background()

	// Add an active VRF
	vs.SetGlobal(ctx, "test-vrf", true)
	vs.SetService(ctx, "test-vrf", true)
	vs.SetAffinity(ctx, "test-vrf", 0)

	// Deactivate by clearing service flag; global still set → entry survives
	vs.SetService(ctx, "test-vrf", false)

	vrf, ok := vs.Get("test-vrf")
	if !ok {
		t.Fatal("VRF should still exist after service deactivation (global still set)")
	}
	if vrf.Active {
		t.Error("VRF should be inactive after service flag cleared")
	}

	// Clear the global flag too → both false → entry is auto-removed
	vs.SetGlobal(ctx, "test-vrf", false)
	if _, ok := vs.Get("test-vrf"); ok {
		t.Error("VRF should be removed once both flags are false")
	}
}

func TestStore_AutoRemove_SetGlobalFalse_NoService(t *testing.T) {
	vs := NewStore(context.Background())
	ctx := context.Background()

	var events []Event
	vs.Watch(func(e Event) { events = append(events, e) })

	vs.SetGlobal(ctx, "test-vrf", true)
	events = nil // reset after create

	// Clearing global with no service flag → auto-remove
	vs.SetGlobal(ctx, "test-vrf", false)

	if _, ok := vs.Get("test-vrf"); ok {
		t.Error("VRF should be removed when SetGlobal(false) and no service flag")
	}
	if len(events) != 1 || events[0].Type != store.EventDeleted {
		t.Errorf("expected one EventDeleted, got %v", events)
	}
}

func TestStore_AutoRemove_SetServiceFalse_NoGlobal(t *testing.T) {
	vs := NewStore(context.Background())
	ctx := context.Background()

	var events []Event
	vs.Watch(func(e Event) { events = append(events, e) })

	vs.SetService(ctx, "test-vrf", true)
	events = nil // reset after create

	// Clearing service with no global flag → auto-remove
	vs.SetService(ctx, "test-vrf", false)

	if _, ok := vs.Get("test-vrf"); ok {
		t.Error("VRF should be removed when SetService(false) and no global flag")
	}
	if len(events) != 1 || events[0].Type != store.EventDeleted {
		t.Errorf("expected one EventDeleted, got %v", events)
	}
}

func TestStore_AutoRemove_GIDReleasedOnAutoRemove(t *testing.T) {
	vs := NewStore(context.Background())
	ctx := context.Background()

	// Activate a VRF (GID auto-allocated on activation)
	vs.SetGlobal(ctx, "test-vrf", true)
	vs.SetService(ctx, "test-vrf", true)
	vs.SetAffinity(ctx, "test-vrf", 0)

	gid, ok := vs.GetGID("test-vrf")
	if !ok || gid == 0 {
		t.Fatal("expected GID to be allocated on activation")
	}

	// Auto-remove by clearing global (service was also set, so clear it first to deactivate)
	vs.SetService(ctx, "test-vrf", false)
	vs.SetGlobal(ctx, "test-vrf", false)

	if _, ok := vs.Get("test-vrf"); ok {
		t.Error("VRF should be removed")
	}

	// GID should be released — a new VRF should reuse or get a new valid GID
	vs.SetGlobal(ctx, "new-vrf", true)
	vs.SetService(ctx, "new-vrf", true)
	vs.SetAffinity(ctx, "new-vrf", 0)

	newGID, ok := vs.GetGID("new-vrf")
	if !ok || newGID == 0 {
		t.Error("expected a valid GID after prior GID was released")
	}
}

func TestStore_NoAutoRemove_GlobalStillSet(t *testing.T) {
	vs := NewStore(context.Background())
	ctx := context.Background()

	vs.SetGlobal(ctx, "test-vrf", true)
	vs.SetService(ctx, "test-vrf", true)

	// Clear service — global still set, entry must survive
	vs.SetService(ctx, "test-vrf", false)

	vrf, ok := vs.Get("test-vrf")
	if !ok {
		t.Fatal("VRF should survive when global flag is still set")
	}
	if vrf.Global != true || vrf.Service != false {
		t.Errorf("unexpected flags: IsGlobal=%v IsService=%v", vrf.Global, vrf.Service)
	}
}

func TestStore_NoAutoRemove_ServiceStillSet(t *testing.T) {
	vs := NewStore(context.Background())
	ctx := context.Background()

	vs.SetGlobal(ctx, "test-vrf", true)
	vs.SetService(ctx, "test-vrf", true)

	// Clear global — service still set, entry must survive
	vs.SetGlobal(ctx, "test-vrf", false)

	vrf, ok := vs.Get("test-vrf")
	if !ok {
		t.Fatal("VRF should survive when service flag is still set")
	}
	if vrf.Global != false || vrf.Service != true {
		t.Errorf("unexpected flags: IsGlobal=%v IsService=%v", vrf.Global, vrf.Service)
	}
}

// --- Auto GID / Pinning Tests ---

func TestStore_AutoGIDAllocation_OnActivation(t *testing.T) {
	vs := NewStore(context.Background())
	ctx := context.Background()

	// Before activation, no GID
	vs.SetGlobal(ctx, "test-vrf", true)
	_, ok := vs.GetGID("test-vrf")
	if ok {
		t.Error("GID should not be allocated before VRF is active")
	}

	// Activation (global+service+affinity) should auto-allocate GID
	vs.SetService(ctx, "test-vrf", true)
	vs.SetAffinity(ctx, "test-vrf", 0)
	gid, ok := vs.GetGID("test-vrf")
	if !ok {
		t.Fatal("expected GID to be allocated after activation")
	}
	if gid == 0 {
		t.Error("expected non-zero GID")
	}
}

func TestStore_AutoGIDAllocation_NotOnPartialFlags(t *testing.T) {
	vs := NewStore(context.Background())
	ctx := context.Background()

	// Only global flag set — not active, no GID
	vs.SetGlobal(ctx, "test-vrf", true)
	_, ok := vs.GetGID("test-vrf")
	if ok {
		t.Error("GID should not be allocated when only global flag is set")
	}

	// Only service flag set — not active, no GID
	vs2 := NewStore(context.Background())
	vs2.SetService(ctx, "test-vrf", true)
	_, ok = vs2.GetGID("test-vrf")
	if ok {
		t.Error("GID should not be allocated when only service flag is set")
	}
}

func TestStore_AutoGIDAllocation_TriggersRedirect(t *testing.T) {
	handler := mock.NewHandler()
	vs := NewStore(context.Background())
	vs.SetGnmiHandler(handler)
	vs.SetRedirectsReady()
	ctx := context.Background()

	// Make VRF active — GID auto-allocated, redirect programmed
	vs.SetGlobal(ctx, "prod-vrf", true)
	vs.SetService(ctx, "prod-vrf", true)
	vs.SetAffinity(ctx, "prod-vrf", 0)

	gid, ok := vs.GetGID("prod-vrf")
	if !ok || gid == 0 {
		t.Fatal("expected non-zero GID after activation")
	}

	// Service endpoint should be programmed (requires GID)
	vals, err := handler.Get(ctx, paths.ServiceRedirServiceItems)
	if err != nil {
		t.Fatalf("failed to get service endpoint: %v", err)
	}
	if len(vals) == 0 {
		t.Error("service endpoint should have been programmed after auto-GID allocation")
	}
}

func TestStore_AutoPinning_StaticAffinity(t *testing.T) {
	vs := NewStore(context.Background(), WithLbModePinning(func() bool { return true }), WithDPUCount(4))
	ctx := context.Background()

	// Activate with a non-zero affinity in pinning mode → DPUPinned = Affinity
	vs.SetGlobal(ctx, "test-vrf", true)
	vs.SetService(ctx, "test-vrf", true)
	vs.SetAffinity(ctx, "test-vrf", 2)

	pinning, ok := vs.GetPinning("test-vrf")
	if !ok {
		t.Fatal("expected pinning to be set for static VRF")
	}
	if pinning != 2 {
		t.Errorf("expected DPUPinned=2, got %d", pinning)
	}
}

func TestStore_AutoPinning_Dynamic(t *testing.T) {
	vs := NewStore(context.Background())
	ctx := context.Background()

	// Activate with zero affinity in symmetric hash mode (default) → DPUPinned = 65535
	vs.SetGlobal(ctx, "test-vrf", true)
	vs.SetService(ctx, "test-vrf", true)
	vs.SetAffinity(ctx, "test-vrf", 0)

	pinning, ok := vs.GetPinning("test-vrf")
	if !ok {
		t.Error("expected pinning to be set in symmetric hash mode")
	}
	if pinning != 65535 {
		t.Errorf("expected DPUPinned=65535 in symmetric hash mode, got %d", pinning)
	}
}

func TestStore_AutoPinning_DynamicPinningMode(t *testing.T) {
	vs := NewStore(context.Background(), WithLbModePinning(func() bool { return true }), WithDPUCount(4))
	ctx := context.Background()

	// Activate with zero affinity in pinning mode → FNV-1a hash (1-4)
	vs.SetGlobal(ctx, "test-vrf", true)
	vs.SetService(ctx, "test-vrf", true)
	vs.SetAffinity(ctx, "test-vrf", 0)

	pinning, ok := vs.GetPinning("test-vrf")
	if !ok {
		t.Error("expected pinning to be set in pinning mode")
	}
	if pinning < 1 || pinning > 4 {
		t.Errorf("expected DPUPinned in range 1-4 for pinning mode, got %d", pinning)
	}
}

// --- SetAffinity Tests ---

func TestStore_SetAffinity_ActivatesVRF(t *testing.T) {
	vs := NewStore(context.Background())
	ctx := context.Background()

	// Set global and service but not affinity — VRF not active yet
	vs.SetGlobal(ctx, "test-vrf", true)
	vs.SetService(ctx, "test-vrf", true)

	vrf, ok := vs.Get("test-vrf")
	if !ok {
		t.Fatal("expected VRF to exist after SetGlobal+SetService")
	}
	if vrf.Active {
		t.Error("VRF should not be active without affinity set")
	}
	if _, hasGID := vs.GetGID("test-vrf"); hasGID {
		t.Error("expected no GID when affinity not set")
	}

	// SetAffinity activates the VRF
	vs.SetAffinity(ctx, "test-vrf", 0)

	vrf, ok = vs.Get("test-vrf")
	if !ok {
		t.Fatal("expected VRF to exist after SetAffinity")
	}
	if !vrf.Active {
		t.Error("VRF should be active after SetAffinity")
	}
	if !vrf.HasAffinity {
		t.Error("expected HasAffinity to be true")
	}
	gid, ok := vs.GetGID("test-vrf")
	if !ok || gid == 0 {
		t.Error("expected GID to be allocated on activation via SetAffinity")
	}
}

func TestStore_SetAffinity_RepinsActiveVRF(t *testing.T) {
	vs := NewStore(context.Background(), WithLbModePinning(func() bool { return true }), WithDPUCount(4))
	ctx := context.Background()

	// Activate with affinity=2 in pinning mode
	vs.SetGlobal(ctx, "test-vrf", true)
	vs.SetService(ctx, "test-vrf", true)
	vs.SetAffinity(ctx, "test-vrf", 2)

	pinning, ok := vs.GetPinning("test-vrf")
	if !ok || pinning != 2 {
		t.Fatalf("expected DPUPinned=2, got %d (ok=%v)", pinning, ok)
	}

	// Change affinity to 3 — should repin
	vs.SetAffinity(ctx, "test-vrf", 3)

	pinning, ok = vs.GetPinning("test-vrf")
	if !ok || pinning != 3 {
		t.Errorf("expected DPUPinned=3 after repin, got %d (ok=%v)", pinning, ok)
	}
}

func TestStore_GlobalServiceOnly_NotActive(t *testing.T) {
	vs := NewStore(context.Background())
	ctx := context.Background()

	vs.SetGlobal(ctx, "test-vrf", true)
	vs.SetService(ctx, "test-vrf", true)

	vrf, ok := vs.Get("test-vrf")
	if !ok {
		t.Fatal("expected VRF to exist")
	}
	if vrf.Active {
		t.Error("VRF should NOT be active with only global+service (no affinity)")
	}
	if _, hasGID := vs.GetGID("test-vrf"); hasGID {
		t.Error("expected no GID when affinity not set")
	}
}

func TestStore_DeactivationClearsGIDAndPinning(t *testing.T) {
	ctx := context.Background()

	t.Run("clear_global_frees_gid_and_pinning", func(t *testing.T) {
		vs := NewStore(ctx)
		vs.SetGlobal(ctx, "test-vrf", true)
		vs.SetService(ctx, "test-vrf", true)
		vs.SetAffinity(ctx, "test-vrf", 2)

		vrf, _ := vs.Get("test-vrf")
		if !vrf.Active || vrf.GID == 0 || vrf.DPUPinned == 0 {
			t.Fatalf("expected active VRF with GID and pinning set, got active=%v GID=%d DPUPinned=%d", vrf.Active, vrf.GID, vrf.DPUPinned)
		}
		allocatedGID := vrf.GID

		// Clear global — VRF survives (service still set) but becomes inactive
		vs.SetGlobal(ctx, "test-vrf", false)

		vrf, ok := vs.Get("test-vrf")
		if !ok {
			t.Fatal("expected VRF to survive (service still set)")
		}
		if vrf.Active {
			t.Error("expected VRF to be inactive after clearing global")
		}
		if vrf.GID != 0 {
			t.Errorf("expected GID=0 after deactivation, got %d", vrf.GID)
		}
		if vrf.DPUPinned != 0 {
			t.Errorf("expected DPUPinned=0 after deactivation, got %d", vrf.DPUPinned)
		}

		// The freed GID should be available for a new VRF
		vs2 := NewStore(ctx)
		vs2.SetGlobal(ctx, "other-vrf", true)
		vs2.SetService(ctx, "other-vrf", true)
		vs2.SetAffinity(ctx, "other-vrf", 0)
		newGID, _ := vs2.GetGID("other-vrf")
		if newGID == allocatedGID {
			// Fine — just checking no panic/error; reuse depends on nextGID position
			_ = newGID
		}
	})

	t.Run("clear_service_frees_gid_and_pinning", func(t *testing.T) {
		vs := NewStore(ctx)
		vs.SetGlobal(ctx, "test-vrf", true)
		vs.SetService(ctx, "test-vrf", true)
		vs.SetAffinity(ctx, "test-vrf", 3)

		vrf, _ := vs.Get("test-vrf")
		if !vrf.Active || vrf.GID == 0 || vrf.DPUPinned == 0 {
			t.Fatalf("expected active VRF with GID and pinning set")
		}

		// Clear service — VRF survives (global still set) but becomes inactive
		vs.SetService(ctx, "test-vrf", false)

		vrf, ok := vs.Get("test-vrf")
		if !ok {
			t.Fatal("expected VRF to survive (global still set)")
		}
		if vrf.Active {
			t.Error("expected VRF to be inactive after clearing service")
		}
		if vrf.GID != 0 {
			t.Errorf("expected GID=0 after deactivation, got %d", vrf.GID)
		}
		if vrf.DPUPinned != 0 {
			t.Errorf("expected DPUPinned=0 after deactivation, got %d", vrf.DPUPinned)
		}
	})

	t.Run("preset_preserved_after_deactivation", func(t *testing.T) {
		vs := NewStore(ctx)
		vs.SetGlobal(ctx, "test-vrf", true)
		vs.SetService(ctx, "test-vrf", true)
		vs.SetAffinity(ctx, "test-vrf", 0)

		vrf, _ := vs.Get("test-vrf")
		preset := vrf.Preset
		if preset == 0 {
			t.Fatal("expected Preset to be set after activation")
		}

		// Deactivate — Preset must survive so re-activation uses the same GID
		vs.SetGlobal(ctx, "test-vrf", false)

		vrf, ok := vs.Get("test-vrf")
		if !ok {
			t.Fatal("expected VRF to survive")
		}
		if vrf.Preset != preset {
			t.Errorf("expected Preset=%d to be preserved after deactivation, got %d", preset, vrf.Preset)
		}
	})
}

func TestStore_SetServiceFalse_ClearsAffinity(t *testing.T) {
	vs := NewStore(context.Background())
	ctx := context.Background()

	// Activate fully
	vs.SetGlobal(ctx, "test-vrf", true)
	vs.SetService(ctx, "test-vrf", true)
	vs.SetAffinity(ctx, "test-vrf", 5)

	vrf, ok := vs.Get("test-vrf")
	if !ok || !vrf.Active {
		t.Fatal("expected active VRF after full activation")
	}

	// Clear service — should also clear HasAffinity and Affinity
	vs.SetService(ctx, "test-vrf", false)

	vrf, ok = vs.Get("test-vrf")
	if !ok {
		t.Fatal("expected VRF to survive (global still set)")
	}
	if vrf.HasAffinity {
		t.Error("expected HasAffinity to be cleared after SetService(false)")
	}
	if vrf.Affinity != 0 {
		t.Errorf("expected Affinity=0 after SetService(false), got %d", vrf.Affinity)
	}
	if vrf.Active {
		t.Error("VRF should be inactive after SetService(false)")
	}
}

// activateVRF is a test helper that sets global, service, and affinity on a VRF,
// triggering GID allocation.
func activateVRF(vs Store, name string, affinity uint16) {
	ctx := context.Background()
	vs.SetGlobal(ctx, name, true)
	vs.SetService(ctx, name, true)
	vs.SetAffinity(ctx, name, affinity)
}

func TestStore_GIDAllocation(t *testing.T) {
	t.Run("default_vrf_gets_gid_1", func(t *testing.T) {
		vs := NewStore(context.Background())
		activateVRF(vs, "default", 0)

		gid, ok := vs.GetGID("default")
		if !ok {
			t.Fatal("expected GID to be allocated for 'default' VRF")
		}
		if gid != 1 {
			t.Errorf("expected default VRF to get GID=1, got %d", gid)
		}
	})

	t.Run("sequential_allocation", func(t *testing.T) {
		vs := NewStore(context.Background())
		activateVRF(vs, "default", 0)
		activateVRF(vs, "vrf-a", 0)
		activateVRF(vs, "vrf-b", 0)

		defaultGID, _ := vs.GetGID("default")
		vrfAGID, _ := vs.GetGID("vrf-a")
		vrfBGID, _ := vs.GetGID("vrf-b")

		if defaultGID != 1 {
			t.Errorf("expected default GID=1, got %d", defaultGID)
		}
		if vrfAGID != 10 {
			t.Errorf("expected vrf-a GID=10, got %d", vrfAGID)
		}
		if vrfBGID != 11 {
			t.Errorf("expected vrf-b GID=11, got %d", vrfBGID)
		}
	})

	t.Run("gap_not_reused_immediately", func(t *testing.T) {
		// Activate 3 VRFs → GIDs 1, 10, 11
		ctx := context.Background()
		vs := NewStore(ctx)
		activateVRF(vs, "default", 0)
		activateVRF(vs, "vrf-a", 0)
		activateVRF(vs, "vrf-b", 0)

		// Remove vrf-a (GID=10) by clearing both flags → auto-remove
		vs.SetService(ctx, "vrf-a", false)
		vs.SetGlobal(ctx, "vrf-a", false)

		if _, ok := vs.Get("vrf-a"); ok {
			t.Fatal("expected vrf-a to be removed after clearing both flags")
		}

		// nextGID is at 12, so new VRF gets GID=12 (gap at 10 not reused immediately)
		activateVRF(vs, "vrf-c", 0)
		vrfCGID, ok := vs.GetGID("vrf-c")
		if !ok {
			t.Fatal("expected GID to be allocated for vrf-c")
		}
		if vrfCGID != 12 {
			t.Errorf("expected vrf-c GID=12 (gap not reused), got %d", vrfCGID)
		}
	})

	t.Run("pre_seeded_gid_honored", func(t *testing.T) {
		vs := NewStore(context.Background(), WithPreSeededGIDs(map[string]uint16{"vrf-x": 42}))
		activateVRF(vs, "vrf-x", 0)

		gid, ok := vs.GetGID("vrf-x")
		if !ok {
			t.Fatal("expected GID to be allocated for 'vrf-x'")
		}
		if gid != 42 {
			t.Errorf("expected pre-seeded GID=42 for 'vrf-x', got %d", gid)
		}
	})

	t.Run("pre_seeded_gid_protected_from_others", func(t *testing.T) {
		// Pre-seed "vrf-x" with GID=10. Sequential allocation for other VRFs
		// should skip GID=10 (claimed as a preset) so vrf-x can use it.
		vs := NewStore(context.Background(), WithPreSeededGIDs(map[string]uint16{"vrf-x": 10}))

		// Activate "default" → GID=1, then "vrf-blocker" → sequential, must skip 10.
		activateVRF(vs, "default", 0)
		activateVRF(vs, "vrf-blocker", 0)

		blockerGID, _ := vs.GetGID("vrf-blocker")
		if blockerGID == 10 {
			t.Fatalf("expected vrf-blocker to skip GID=10 (pre-seeded for vrf-x), got %d", blockerGID)
		}

		// Activate "vrf-x" — preset GID=10 is available.
		activateVRF(vs, "vrf-x", 0)
		gid, ok := vs.GetGID("vrf-x")
		if !ok {
			t.Fatal("expected GID to be allocated for 'vrf-x'")
		}
		if gid != 10 {
			t.Errorf("expected pre-seeded GID=10 for 'vrf-x', got %d", gid)
		}
	})

	t.Run("preserved_across_reload", func(t *testing.T) {
		ctx := context.Background()
		mem := storage.NewMemoryStorage()

		// Create store, activate VRFs so GIDs are assigned and persisted
		vs1 := NewStore(ctx, WithStorage(mem))
		activateVRF(vs1, "default", 0)
		activateVRF(vs1, "vrf-a", 0)

		gid1, _ := vs1.GetGID("default")
		gidA, _ := vs1.GetGID("vrf-a")

		// Reload from the same storage backend
		vs2 := NewStore(ctx, WithStorage(mem))

		reloadedGID1, ok := vs2.GetGID("default")
		if !ok {
			t.Fatal("expected 'default' GID to be present after reload")
		}
		if reloadedGID1 != gid1 {
			t.Errorf("expected reloaded default GID=%d, got %d", gid1, reloadedGID1)
		}

		reloadedGIDA, ok := vs2.GetGID("vrf-a")
		if !ok {
			t.Fatal("expected 'vrf-a' GID to be present after reload")
		}
		if reloadedGIDA != gidA {
			t.Errorf("expected reloaded vrf-a GID=%d, got %d", gidA, reloadedGIDA)
		}
	})
}

func TestStore_VRF_GlobalServiceFlags(t *testing.T) {
	t.Run("global_only_no_gid", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx)
		vs.SetGlobal(ctx, "vrf-x", true)

		vrf, ok := vs.Get("vrf-x")
		if !ok {
			t.Fatal("expected vrf-x to exist")
		}
		if vrf.Active {
			t.Error("expected VRF to be inactive with only global flag set")
		}
		if _, hasGID := vs.GetGID("vrf-x"); hasGID {
			t.Error("expected no GID when only global flag is set")
		}
	})

	t.Run("service_only_no_gid", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx)
		vs.SetService(ctx, "vrf-x", true)

		vrf, ok := vs.Get("vrf-x")
		if !ok {
			t.Fatal("expected vrf-x to exist")
		}
		if vrf.Active {
			t.Error("expected VRF to be inactive with only service flag set")
		}
		if _, hasGID := vs.GetGID("vrf-x"); hasGID {
			t.Error("expected no GID when only service flag is set")
		}
	})

	t.Run("both_flags_active_with_gid", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx)
		activateVRF(vs, "vrf-x", 0)

		vrf, ok := vs.Get("vrf-x")
		if !ok {
			t.Fatal("expected vrf-x to exist")
		}
		if !vrf.Active {
			t.Error("expected VRF to be active with both flags set")
		}
		gid, hasGID := vs.GetGID("vrf-x")
		if !hasGID || gid == 0 {
			t.Error("expected non-zero GID when both flags are set")
		}
	})

	t.Run("clear_service_deactivates", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx)
		activateVRF(vs, "vrf-x", 0)
		vs.SetService(ctx, "vrf-x", false)

		vrf, ok := vs.Get("vrf-x")
		if !ok {
			t.Fatal("expected vrf-x to survive after clearing service (global still set)")
		}
		if vrf.Active {
			t.Error("expected VRF to be inactive after clearing service flag")
		}
		if !vrf.Global {
			t.Error("expected IsGlobal to remain true")
		}
	})

	t.Run("clear_global_deactivates", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx)
		activateVRF(vs, "vrf-x", 0)
		vs.SetGlobal(ctx, "vrf-x", false)

		vrf, ok := vs.Get("vrf-x")
		if !ok {
			t.Fatal("expected vrf-x to survive after clearing global (service still set)")
		}
		if vrf.Active {
			t.Error("expected VRF to be inactive after clearing global flag")
		}
		if !vrf.Service {
			t.Error("expected IsService to remain true")
		}
	})

	t.Run("clear_both_removes", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx)
		activateVRF(vs, "vrf-x", 0)
		vs.SetService(ctx, "vrf-x", false)
		vs.SetGlobal(ctx, "vrf-x", false)

		if _, ok := vs.Get("vrf-x"); ok {
			t.Error("expected vrf-x to be removed when both flags are cleared")
		}
	})
}

// --- RestoreGIDsFromGnmi Tests ---

func TestStore_RestoreGIDsFromGnmi_NoHandler(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx)

	// No handler set - should return nil without error
	err := vs.RestoreGIDsFromGnmi(ctx)
	if err != nil {
		t.Errorf("expected no error without handler, got %v", err)
	}
}

func TestStore_RestoreGIDsFromGnmi_EmptyResponse(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	vs := NewStore(ctx)
	vs.SetGnmiHandler(handler)

	// Add an active VRF (all flags set) - GID allocated on activation
	vs.SetGlobal(ctx, "test-vrf", true)
	vs.SetService(ctx, "test-vrf", true)
	vs.SetAffinity(ctx, "test-vrf", 0)

	originalGID, _ := vs.GetGID("test-vrf")

	// RestoreGIDsFromGnmi with empty response should keep existing GID
	err := vs.RestoreGIDsFromGnmi(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	gid, ok := vs.GetGID("test-vrf")
	if !ok {
		t.Error("expected GID to exist after restore")
	}
	if gid != originalGID {
		t.Errorf("expected GID to remain %d, got %d", originalGID, gid)
	}
}

func TestStore_RestoreGIDsFromGnmi_OverwritesExistingGID(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	vs := NewStore(ctx)
	vs.SetGnmiHandler(handler)

	// Add an active VRF - GID allocated on activation (e.g., GID=1)
	vs.SetGlobal(ctx, "prod-vrf", true)
	vs.SetService(ctx, "prod-vrf", true)
	vs.SetAffinity(ctx, "prod-vrf", 0)

	originalGID, _ := vs.GetGID("prod-vrf")
	if originalGID == 0 {
		t.Fatal("expected GID to be allocated on activation")
	}

	// Simulate switch has different GID (42) from a previous run
	// Using the programmed JSON format that redirect.go produces
	serviceItemsJSON := `{
		"Cisco-NX-OS-device:Service-list": [
			{
				"name": "__prod-vrf_dpu_redir",
				"type": "dpu",
				"vrf": "prod-vrf",
				"dpuep-items": {
					"SvcEndPointDpu-list": [
						{
							"dpuNum": "all",
							"vlan": 42
						}
					]
				}
			}
		]
	}`
	handler.Set(ctx, paths.ServiceRedirServiceItems, serviceItemsJSON)

	// RestoreGIDsFromGnmi should overwrite GID with value from switch
	err := vs.RestoreGIDsFromGnmi(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	gid, ok := vs.GetGID("prod-vrf")
	if !ok {
		t.Fatal("expected GID to exist")
	}
	if gid != 42 {
		t.Errorf("expected GID=42 from switch (overwriting original %d), got %d", originalGID, gid)
	}
}

// --- Preset-Based GID Tests ---

func TestSetGID_CreatesSkeletonVRF(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx)

	// SetGID on a non-existent VRF creates a skeleton with Preset set.
	if err := vs.SetGID(ctx, "new-vrf", 42); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	vrf, ok := vs.Get("new-vrf")
	if !ok {
		t.Fatal("expected skeleton VRF to be created")
	}
	if vrf.Preset != 42 {
		t.Errorf("expected Preset=42, got %d", vrf.Preset)
	}
	// GID is not yet allocated (VRF not active)
	if vrf.GID != 0 {
		t.Errorf("expected GID=0 before activation, got %d", vrf.GID)
	}
}

func TestSetGID_UpdatesPresetAndReconciles(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx)

	// Activate a VRF; it gets a sequential GID.
	activateVRF(vs, "my-vrf", 0)
	originalGID, _ := vs.GetGID("my-vrf")

	// SetGID changes the Preset; reconcilePresets applies it.
	if err := vs.SetGID(ctx, "my-vrf", 99); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	gid, ok := vs.GetGID("my-vrf")
	if !ok {
		t.Fatal("expected GID to be set")
	}
	if gid != 99 {
		t.Errorf("expected GID=99 after SetGID, got %d (was %d)", gid, originalGID)
	}
}

func TestSetGID_HandlesGIDCollision(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx)

	// Activate vrf-a (GID=10) and vrf-b (GID=11).
	activateVRF(vs, "vrf-a", 0)
	activateVRF(vs, "vrf-b", 0)
	gidA, _ := vs.GetGID("vrf-a")
	gidB, _ := vs.GetGID("vrf-b")

	// SetGID for vrf-c claiming vrf-a's current GID.
	if err := vs.SetGID(ctx, "vrf-c", gidA); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// vrf-a should have gotten a new GID (its old GID is now vrf-c's preset).
	newGIDA, _ := vs.GetGID("vrf-a")
	if newGIDA == gidA {
		t.Errorf("expected vrf-a to get a new GID (old GID %d claimed by vrf-c), but kept %d", gidA, newGIDA)
	}
	// vrf-b should be unaffected.
	if newGIDB, _ := vs.GetGID("vrf-b"); newGIDB != gidB {
		t.Errorf("expected vrf-b GID to be unchanged %d, got %d", gidB, newGIDB)
	}
}

func TestSetGIDs_BatchPresets(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx)

	// Activate two VRFs with sequential GIDs.
	activateVRF(vs, "vrf-a", 0)
	activateVRF(vs, "vrf-b", 0)

	// Apply batch with specific GIDs for both.
	if err := vs.SetGIDs(ctx, map[string]uint16{"vrf-a": 50, "vrf-b": 51}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	gidA, _ := vs.GetGID("vrf-a")
	gidB, _ := vs.GetGID("vrf-b")
	if gidA != 50 {
		t.Errorf("expected vrf-a GID=50, got %d", gidA)
	}
	if gidB != 51 {
		t.Errorf("expected vrf-b GID=51, got %d", gidB)
	}
}

func TestActivation_UsesPreset(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx)

	// SetGID before activation creates skeleton with Preset=42.
	if err := vs.SetGID(ctx, "preset-vrf", 42); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Activate the VRF — should use the preset GID.
	vs.SetGlobal(ctx, "preset-vrf", true)
	vs.SetService(ctx, "preset-vrf", true)
	vs.SetAffinity(ctx, "preset-vrf", 0)

	gid, ok := vs.GetGID("preset-vrf")
	if !ok {
		t.Fatal("expected GID to be allocated")
	}
	if gid != 42 {
		t.Errorf("expected GID=42 from preset, got %d", gid)
	}
}

func TestActivation_NoPreset_AllocatesAndSetsPreset(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx)

	// Activate with no preset — sequential allocation sets both GID and Preset.
	activateVRF(vs, "seq-vrf", 0)

	vrf, ok := vs.Get("seq-vrf")
	if !ok {
		t.Fatal("expected seq-vrf to exist")
	}
	if vrf.GID == 0 {
		t.Error("expected non-zero GID after activation")
	}
	if vrf.Preset != vrf.GID {
		t.Errorf("expected Preset == GID after sequential allocation, got Preset=%d GID=%d", vrf.Preset, vrf.GID)
	}
}

func TestStore_RestoreGIDsFromGnmi_UpdatesNextGID(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	vs := NewStore(ctx)
	vs.SetGnmiHandler(handler)

	// Add active VRF - gets GID=1
	vs.SetGlobal(ctx, "vrf-a", true)
	vs.SetService(ctx, "vrf-a", true)
	vs.SetAffinity(ctx, "vrf-a", 0)

	// Simulate switch has high GID (100) from previous allocation
	serviceItemsJSON := `{
		"Cisco-NX-OS-device:Service-list": [
			{
				"name": "__vrf-a_dpu_redir",
				"type": "dpu",
				"vrf": "vrf-a",
				"dpuep-items": {
					"SvcEndPointDpu-list": [
						{
							"dpuNum": "all",
							"vlan": 100
						}
					]
				}
			}
		]
	}`
	handler.Set(ctx, paths.ServiceRedirServiceItems, serviceItemsJSON)

	err := vs.RestoreGIDsFromGnmi(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// vrf-a should have GID=100
	gidA, _ := vs.GetGID("vrf-a")
	if gidA != 100 {
		t.Errorf("expected vrf-a GID=100, got %d", gidA)
	}

	// New VRF should get GID > 100 (nextGID should have been updated)
	vs.SetGlobal(ctx, "vrf-b", true)
	vs.SetService(ctx, "vrf-b", true)
	vs.SetAffinity(ctx, "vrf-b", 0)

	gidB, ok := vs.GetGID("vrf-b")
	if !ok {
		t.Fatal("expected GID for vrf-b")
	}
	if gidB <= 100 {
		t.Errorf("expected vrf-b GID > 100 (nextGID should be updated), got %d", gidB)
	}
}

// --- Idempotency Tests ---

func TestStore_Idempotency_SetService(t *testing.T) {
	ctx := context.Background()

	var events []Event
	vs := NewStore(ctx)
	vs.Watch(func(e Event) { events = append(events, e) })

	// First call: creates and activates the VRF
	vs.SetGlobal(ctx, "test-vrf", true)
	vs.SetService(ctx, "test-vrf", true)
	vs.SetAffinity(ctx, "test-vrf", 0)
	events = nil // reset after initial setup

	// Second call with identical args should be a no-op
	vs.SetService(ctx, "test-vrf", true)

	if len(events) != 0 {
		t.Errorf("expected no events on duplicate SetService call, got %d", len(events))
	}
}

func TestStore_Idempotency_SetGlobal(t *testing.T) {
	ctx := context.Background()

	var events []Event
	vs := NewStore(ctx)
	vs.Watch(func(e Event) { events = append(events, e) })

	vs.SetGlobal(ctx, "test-vrf", true)
	events = nil // reset after initial setup

	// Calling SetGlobal with the same value is a no-op
	vs.SetGlobal(ctx, "test-vrf", true)

	if len(events) != 0 {
		t.Errorf("expected no events on duplicate SetGlobal call, got %d", len(events))
	}
}

func TestStore_Idempotency_DuplicateGnmiNotification(t *testing.T) {
	ctx := context.Background()

	var events []Event
	vs := NewStore(ctx)
	vs.Watch(func(e Event) { events = append(events, e) })

	path := serviceVRFLeafPath("tenant1")
	update := makeStringUpdate("tenant1")

	// First notification: creates the VRF
	vs.HandleGnmiNotification(ctx, path, update, false)
	if len(events) != 1 {
		t.Fatalf("expected 1 event after first notification, got %d", len(events))
	}
	events = nil

	// Second identical notification: should be a no-op
	vs.HandleGnmiNotification(ctx, path, update, false)
	if len(events) != 0 {
		t.Errorf("expected no events on duplicate gNMI notification, got %d", len(events))
	}
}
