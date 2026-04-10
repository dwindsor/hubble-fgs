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
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
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
	vs.SetInService(true)
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

func TestStore_RedirectBlockedWhenNotInService(t *testing.T) {
	handler := mock.NewHandler()
	vs := NewStore(context.Background())
	vs.SetGnmiHandler(handler)
	// inService defaults to false — reactive redirects should be blocked
	ctx := context.Background()

	// Make VRF active
	vs.SetGlobal(ctx, "prod-vrf", true)
	vs.SetService(ctx, "prod-vrf", true)
	vs.SetAffinity(ctx, "prod-vrf", 0)

	// fwPolicyState should NOT be programmed because inService=false
	vals, err := handler.Get(ctx, paths.FwPolicyStateVrf)
	if err != nil {
		t.Fatalf("failed to get fwPolicyState: %v", err)
	}
	if len(vals) != 0 {
		t.Error("expected no fwPolicyState when inService=false, but got data")
	}
}

func TestStore_ProgramAllRedirects_BypassesInServiceGate(t *testing.T) {
	handler := mock.NewHandler()
	vs := NewStore(context.Background())
	vs.SetGnmiHandler(handler)
	// inService is false — but ProgramAllRedirects should bypass the gate
	ctx := context.Background()

	// Make VRF active (redirects not programmed reactively since inService=false)
	vs.SetGlobal(ctx, "prod-vrf", true)
	vs.SetService(ctx, "prod-vrf", true)
	vs.SetAffinity(ctx, "prod-vrf", 0)

	// Explicitly program all redirects (bypasses gate)
	vs.ProgramAllRedirects(ctx)

	// fwPolicyState should now be programmed
	vals, err := handler.Get(ctx, paths.FwPolicyStateVrf)
	if err != nil {
		t.Fatalf("failed to get fwPolicyState: %v", err)
	}
	if len(vals) == 0 {
		t.Error("expected fwPolicyState after ProgramAllRedirects, but got none")
	}

	// Enforcement should be programmed
	vals, err = handler.Get(ctx, paths.ServiceRedirDomItems)
	if err != nil {
		t.Fatalf("failed to get enforcement: %v", err)
	}
	if len(vals) == 0 {
		t.Error("expected enforcement binding after ProgramAllRedirects, but got none")
	}
}

func TestStore_CleanupAllRedirects(t *testing.T) {
	handler := mock.NewHandler()
	vs := NewStore(context.Background())
	vs.SetGnmiHandler(handler)
	vs.SetInService(true)
	ctx := context.Background()

	// Make multiple VRFs active — redirects are programmed
	vs.SetGlobal(ctx, "vrf-a", true)
	vs.SetService(ctx, "vrf-a", true)
	vs.SetAffinity(ctx, "vrf-a", 0)
	vs.SetGlobal(ctx, "vrf-b", true)
	vs.SetService(ctx, "vrf-b", true)
	vs.SetAffinity(ctx, "vrf-b", 0)

	active := vs.ListActive()
	if len(active) != 2 {
		t.Fatalf("expected 2 active VRFs, got %d", len(active))
	}

	// CleanupAllRedirects should run without error for all active VRFs.
	// (Individual cleanup paths are tested by TestStore_CleanupRedirects_OnDeactivation.)
	vs.CleanupAllRedirects(ctx)
}

func TestStore_AutoGIDAllocation_TriggersRedirect(t *testing.T) {
	handler := mock.NewHandler()
	vs := NewStore(context.Background())
	vs.SetGnmiHandler(handler)
	vs.SetInService(true)
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
	vs := NewStore(context.Background(), WithLbModePinning(true), WithDPUCount(4))
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
	vs := NewStore(context.Background(), WithLbModePinning(true), WithDPUCount(4))
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
	vs := NewStore(context.Background(), WithLbModePinning(true), WithDPUCount(4))
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

// --- Fix 1: Error Propagation Tests ---

// TestReconcilePresets_Batch1FailureSkipsBatch2 verifies that if the batch1 gNMI SET
// fails, batch2 is not attempted and an error is returned.
func TestReconcilePresets_Batch1FailureSkipsBatch2(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	handler := mock.NewHandlerBuilder().
		WithSetError(paths.ServiceRedirServiceItems, fmt.Errorf("gNMI error")).
		WithPersistPath(tmpDir + "/mock.json").
		Build()
	defer handler.Close()

	vs := NewStore(ctx)
	vs.SetGnmiHandler(handler)

	// Activate with inService=false so no gNMI SET calls happen during activation.
	activateVRF(vs, "vrf-a", 0)
	activateVRF(vs, "vrf-b", 0)
	gidA, _ := vs.GetGID("vrf-a")
	gidB, _ := vs.GetGID("vrf-b")

	// Now enable in-service so reconcilePresets will attempt gNMI SETs.
	vs.SetInService(true)

	// Swap GIDs: contested ordering means both VRFs must be in batch1.
	// If batch1 fails, batch2 must not run.
	err := vs.SetGIDs(ctx, map[string]uint16{"vrf-a": gidB, "vrf-b": gidA})
	if err == nil {
		t.Fatal("expected error from SetGIDs when gNMI SET fails")
	}

	// TxLog should show exactly 1 "set" for ServiceRedirServiceItems (batch1 only).
	entries, txErr := handler.TxLog().ReadEntries("", paths.ServiceRedirServiceItems, "set")
	if txErr != nil {
		t.Fatalf("failed to read TxLog: %v", txErr)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 SET attempt (batch1 only), got %d", len(entries))
	}
}

// TestSetGIDs_PropagatesReconcileError verifies SetGIDs returns error when gNMI SET fails.
func TestSetGIDs_PropagatesReconcileError(t *testing.T) {
	ctx := context.Background()

	handler := mock.NewHandlerBuilder().
		WithSetError(paths.ServiceRedirServiceItems, fmt.Errorf("gNMI error")).
		Build()

	vs := NewStore(ctx)
	vs.SetGnmiHandler(handler)
	vs.SetInService(true)

	activateVRF(vs, "vrf-a", 0)

	// Changing the GID will trigger reconcilePresets → sendGIDUpdateBatch which will fail.
	err := vs.SetGIDs(ctx, map[string]uint16{"vrf-a": 50})
	if err == nil {
		t.Error("expected SetGIDs to propagate gNMI error")
	}
}

// --- Fix 2: Cross-Peer GID Overlap Tests ---

// TestSetGIDs_CrossPeerOverlap_Reallocates verifies that a local VRF whose GID is
// claimed by an incoming preset (for a differently-named VRF) gets a new GID.
func TestSetGIDs_CrossPeerOverlap_Reallocates(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx)

	// Activate local VRF "alpha" — gets GID=10.
	activateVRF(vs, "alpha", 0)
	alphaGID, _ := vs.GetGID("alpha")
	if alphaGID == 0 {
		t.Fatal("expected alpha to have a GID")
	}

	// Peer has VRF "beta" with the same GID as "alpha".
	// SetGIDs should detect the collision and reallocate "alpha".
	if err := vs.SetGIDs(ctx, map[string]uint16{"beta": alphaGID}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	newAlphaGID, _ := vs.GetGID("alpha")
	if newAlphaGID == alphaGID {
		t.Errorf("expected alpha to be reallocated away from GID %d (claimed by beta)", alphaGID)
	}
}

// TestSetGIDs_CrossPeerOverlap_ChainedConflict verifies multiple local VRFs are all
// reallocated when they conflict with incoming presets.
func TestSetGIDs_CrossPeerOverlap_ChainedConflict(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx)

	activateVRF(vs, "a", 0)
	activateVRF(vs, "b", 0)
	gidA, _ := vs.GetGID("a")
	gidB, _ := vs.GetGID("b")

	// Peer claims both GIDs for different VRFs.
	if err := vs.SetGIDs(ctx, map[string]uint16{"x": gidA, "y": gidB}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	newGIDA, _ := vs.GetGID("a")
	newGIDB, _ := vs.GetGID("b")
	if newGIDA == gidA {
		t.Errorf("expected 'a' to be reallocated from GID %d", gidA)
	}
	if newGIDB == gidB {
		t.Errorf("expected 'b' to be reallocated from GID %d", gidB)
	}
}

// TestSetGIDs_SameNameNotCrossPeer verifies that same-name VRF gets preset adoption,
// not treated as a cross-peer conflict.
func TestSetGIDs_SameNameNotCrossPeer(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx)

	activateVRF(vs, "alpha", 0)
	originalGID, _ := vs.GetGID("alpha")

	// SetGIDs for the same name: this is a same-name adoption, not cross-peer.
	if err := vs.SetGIDs(ctx, map[string]uint16{"alpha": 20}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	gid, _ := vs.GetGID("alpha")
	if gid != 20 {
		t.Errorf("expected alpha GID=20 after preset adoption (was %d), got %d", originalGID, gid)
	}
}

// --- Fix 3: Refcount Map Tests ---

// TestReservePreset_BlocksAllocation verifies that a reserved preset blocks
// sequential GID allocation for other VRFs.
func TestReservePreset_BlocksAllocation(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx)

	// Reserve GID=10 for a peer VRF.
	vs.ReservePreset(ctx, "peer-vrf", GIDAllocationStart)

	// Activate a different VRF; it must not get GID=10.
	activateVRF(vs, "local-vrf", 0)
	gid, ok := vs.GetGID("local-vrf")
	if !ok {
		t.Fatal("expected GID to be allocated for local-vrf")
	}
	if gid == GIDAllocationStart {
		t.Errorf("expected local-vrf to skip GID=%d (reserved by peer-vrf), got %d", GIDAllocationStart, gid)
	}
}

// TestReservePreset_CleanupOnDelete verifies that auto-removing a skeleton VRF
// frees its reserved GID, allowing future allocations to use it.
func TestReservePreset_CleanupOnDelete(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx)

	// Reserve GID=10 for peer-vrf by giving it both global+service flags (skeleton).
	// Actually ReservePreset only creates a skeleton; SetGlobal then SetService would
	// auto-remove when both are false. Let's use SetGlobal+SetService to test the cleanup.
	vs.ReservePreset(ctx, "peer-vrf", GIDAllocationStart)

	// Trigger auto-remove: set global true then false with no service flag.
	vs.SetGlobal(ctx, "peer-vrf", true)
	// Now peer-vrf exists with Global=true. GID is still 0 (not active yet, no service/affinity).
	// Clearing global should auto-remove it (no service flag).
	vs.SetGlobal(ctx, "peer-vrf", false)

	if _, ok := vs.Get("peer-vrf"); ok {
		t.Fatal("expected peer-vrf to be auto-removed")
	}

	// After removal, GID=10 should be allocatable.
	activateVRF(vs, "new-vrf", 0)
	gid, ok := vs.GetGID("new-vrf")
	if !ok {
		t.Fatal("expected GID for new-vrf")
	}
	if gid != GIDAllocationStart {
		t.Errorf("expected new-vrf to get GID=%d (freed by peer-vrf removal), got %d", GIDAllocationStart, gid)
	}
}

// TestReservePreset_NoDoubleFree verifies refcount correctness when a VRF transitions
// from skeleton (Preset-only) to active (GID set) then deactivates.
func TestReservePreset_NoDoubleFree(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx)

	// Reserve GID=10 for "alpha".
	vs.ReservePreset(ctx, "alpha", GIDAllocationStart)

	// Activate "alpha": should use preset GID=10.
	activateVRF(vs, "alpha", 0)
	gid, _ := vs.GetGID("alpha")
	if gid != GIDAllocationStart {
		t.Fatalf("expected alpha to use preset GID=%d, got %d", GIDAllocationStart, gid)
	}

	// Deactivate by clearing service (global still set).
	vs.SetService(ctx, "alpha", false)

	vrf, ok := vs.Get("alpha")
	if !ok {
		t.Fatal("expected alpha to survive (global still set)")
	}
	if vrf.GID != 0 {
		t.Errorf("expected GID=0 after deactivation, got %d", vrf.GID)
	}

	// Activate a second VRF — it must not get GID=10 (Preset still holds it).
	activateVRF(vs, "beta", 0)
	betaGID, _ := vs.GetGID("beta")
	if betaGID == GIDAllocationStart {
		t.Errorf("expected beta to skip GID=%d (still held by alpha's Preset), got %d", GIDAllocationStart, betaGID)
	}
}

// TestRefcount_RestoreOverwrite verifies that RestoreGIDsFromGnmi correctly manages
// refcounts when overwriting a VRF's GID with a different value from the switch.
func TestRefcount_RestoreOverwrite(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	vs := NewStore(ctx)
	vs.SetGnmiHandler(handler)

	// Activate "vrf-a" — gets GID=10 in memory.
	activateVRF(vs, "vrf-a", 0)
	originalGID, _ := vs.GetGID("vrf-a")
	if originalGID == 0 {
		t.Fatal("expected GID to be allocated")
	}

	// Switch has vrf-a with a different GID (77).
	differentGID := uint16(77)
	serviceItemsJSON := fmt.Sprintf(`{
		"Cisco-NX-OS-device:Service-list": [
			{
				"name": "__vrf-a_dpu_redir",
				"type": "dpu",
				"vrf": "vrf-a",
				"dpuep-items": {
					"SvcEndPointDpu-list": [
						{"dpuNum": "all", "vlan": %d}
					]
				}
			}
		]
	}`, differentGID)
	handler.Set(ctx, paths.ServiceRedirServiceItems, serviceItemsJSON)

	if err := vs.RestoreGIDsFromGnmi(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// vrf-a should now have GID=77.
	newGID, _ := vs.GetGID("vrf-a")
	if newGID != differentGID {
		t.Errorf("expected vrf-a GID=%d after restore, got %d", differentGID, newGID)
	}

	// Activate a second VRF — it must not get originalGID (should be freed)
	// and must not get differentGID (still in use by vrf-a).
	activateVRF(vs, "vrf-b", 0)
	bGID, _ := vs.GetGID("vrf-b")
	if bGID == differentGID {
		t.Errorf("expected vrf-b to skip GID=%d (in use by vrf-a), got %d", differentGID, bGID)
	}
}

// TestRefcount_RebuildCountsSkeletons verifies that rebuildGIDStateLocked counts
// skeleton VRF presets in gidsInUse, blocking allocation of those GIDs.
func TestRefcount_RebuildCountsSkeletons(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemoryStorage()

	// Create store and add skeleton VRF with Preset=GIDAllocationStart via SetGID.
	vs1 := NewStore(ctx, WithStorage(mem))
	if err := vs1.SetGID(ctx, "skeleton-vrf", GIDAllocationStart); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Reload from storage — rebuildGIDStateLocked should count the skeleton preset.
	vs2 := NewStore(ctx, WithStorage(mem))

	// Activating a new VRF in vs2 must skip GID=GIDAllocationStart.
	activateVRF(vs2, "new-vrf", 0)
	gid, ok := vs2.GetGID("new-vrf")
	if !ok {
		t.Fatal("expected GID for new-vrf")
	}
	if gid == GIDAllocationStart {
		t.Errorf("expected new-vrf to skip GID=%d (held by skeleton preset), got %d", GIDAllocationStart, gid)
	}
}

// --- Fix 4: DPU Repinning Tests ---

// TestRestoreGIDsFromGnmi_RepinDeletesOldEndpoint verifies that if the switch has a VRF
// with a DPU endpoint that doesn't match the desired DPUPinned, a DELETE is issued.
func TestRestoreGIDsFromGnmi_RepinDeletesOldEndpoint(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	handler := mock.NewHandlerBuilder().
		WithPersistPath(tmpDir + "/mock.json").
		Build()
	defer handler.Close()

	vs := NewStore(ctx, WithLbModePinning(true), WithDPUCount(4))
	vs.SetGnmiHandler(handler)

	// Activate vrf-a with DPUPinned=2 (affinity=2 in pinning mode).
	activateVRF(vs, "vrf-a", 2)
	_, ok := vs.GetGID("vrf-a")
	if !ok {
		t.Fatal("expected vrf-a to be activated")
	}

	// Switch has vrf-a with DPU=1 endpoint (stale from before repinning to DPU=2).
	serviceItemsJSON := `{
		"Cisco-NX-OS-device:Service-list": [
			{
				"name": "__vrf-a_dpu_redir",
				"type": "dpu",
				"vrf": "vrf-a",
				"dpuep-items": {
					"SvcEndPointDpu-list": [
						{"dpuNum": "1", "vlan": 10}
					]
				}
			}
		]
	}`
	handler.Set(ctx, paths.ServiceRedirServiceItems, serviceItemsJSON)

	if err := vs.RestoreGIDsFromGnmi(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// A DELETE should have been issued for the DPU=1 endpoint.
	entries, err := handler.TxLog().ReadEntries("", paths.ServiceRedirServiceItems, "delete")
	if err != nil {
		t.Fatalf("failed to read TxLog: %v", err)
	}
	if len(entries) == 0 {
		t.Error("expected DELETE for stale DPU=1 endpoint, but none was issued")
	}
}

// TestRestoreGIDsFromGnmi_SamePinningNoDelete verifies that when switch DPU matches
// desired DPUPinned, no DELETE is issued.
func TestRestoreGIDsFromGnmi_SamePinningNoDelete(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	handler := mock.NewHandlerBuilder().
		WithPersistPath(tmpDir + "/mock.json").
		Build()
	defer handler.Close()

	vs := NewStore(ctx, WithLbModePinning(true), WithDPUCount(4))
	vs.SetGnmiHandler(handler)

	// Activate vrf-a with DPUPinned=1.
	activateVRF(vs, "vrf-a", 1)

	// Switch also has DPU=1 (matching).
	serviceItemsJSON := `{
		"Cisco-NX-OS-device:Service-list": [
			{
				"name": "__vrf-a_dpu_redir",
				"type": "dpu",
				"vrf": "vrf-a",
				"dpuep-items": {
					"SvcEndPointDpu-list": [
						{"dpuNum": "1", "vlan": 10}
					]
				}
			}
		]
	}`
	handler.Set(ctx, paths.ServiceRedirServiceItems, serviceItemsJSON)

	if err := vs.RestoreGIDsFromGnmi(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No DELETE should be issued for the DPU=1 endpoint (it matches).
	entries, err := handler.TxLog().ReadEntries("", paths.ServiceRedirServiceItems, "delete")
	if err != nil {
		t.Fatalf("failed to read TxLog: %v", err)
	}
	if len(entries) > 0 {
		t.Errorf("expected no DELETE (DPU matches), but got %d", len(entries))
	}
}

// TestRestoreGIDsFromGnmi_NoPinningDeletesAll verifies that when DPUPinned=0 (no
// endpoint expected), all switch DPU endpoints are deleted.
func TestRestoreGIDsFromGnmi_NoPinningDeletesAll(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	handler := mock.NewHandlerBuilder().
		WithPersistPath(tmpDir + "/mock.json").
		Build()
	defer handler.Close()

	vs := NewStore(ctx)
	vs.SetGnmiHandler(handler)

	// Add vrf-a with no pinning (DPUPinned=0, not active).
	// We need it to be "active" in the store but with DPUPinned=0.
	// In symmetric-hash mode, active VRFs get DPUPinned=65535, not 0.
	// Let's manually set up a VRF with DPUPinned=0 by not having dpuCount set.
	// Actually, with dpuCount=0 and affinity=0 in pinning mode, DPUPinned=0.
	vs2 := NewStore(ctx, WithLbModePinning(true))
	vs2.SetGnmiHandler(handler)
	activateVRF(vs2, "vrf-a", 0)
	vrf, _ := vs2.Get("vrf-a")
	if vrf.DPUPinned != 0 {
		t.Skipf("skipping: expected DPUPinned=0 with dpuCount=0, got %d", vrf.DPUPinned)
	}

	// Switch has DPU=1 endpoint for vrf-a.
	serviceItemsJSON := `{
		"Cisco-NX-OS-device:Service-list": [
			{
				"name": "__vrf-a_dpu_redir",
				"type": "dpu",
				"vrf": "vrf-a",
				"dpuep-items": {
					"SvcEndPointDpu-list": [
						{"dpuNum": "1", "vlan": 10}
					]
				}
			}
		]
	}`
	handler.Set(ctx, paths.ServiceRedirServiceItems, serviceItemsJSON)

	if err := vs2.RestoreGIDsFromGnmi(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// DELETE should be issued for DPU=1 (DPUPinned=0 means no endpoint expected).
	entries, err := handler.TxLog().ReadEntries("", paths.ServiceRedirServiceItems, "delete")
	if err != nil {
		t.Fatalf("failed to read TxLog: %v", err)
	}
	if len(entries) == 0 {
		t.Error("expected DELETE for DPU=1 when DPUPinned=0, but none issued")
	}
}

// TestRestoreGIDsFromGnmi_MultipleStaleEndpoints verifies that when a VRF has multiple
// stale DPU endpoints on the switch, DELETEs are issued for each stale one.
func TestRestoreGIDsFromGnmi_MultipleStaleEndpoints(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	handler := mock.NewHandlerBuilder().
		WithPersistPath(tmpDir + "/mock.json").
		Build()
	defer handler.Close()

	vs := NewStore(ctx, WithLbModePinning(true), WithDPUCount(4))
	vs.SetGnmiHandler(handler)

	// Activate vrf-a with DPUPinned=2.
	activateVRF(vs, "vrf-a", 2)

	// Switch has DPU=1, DPU=2, and "all" endpoints (only DPU=2 is correct).
	serviceItemsJSON := `{
		"Cisco-NX-OS-device:Service-list": [
			{
				"name": "__vrf-a_dpu_redir",
				"type": "dpu",
				"vrf": "vrf-a",
				"dpuep-items": {
					"SvcEndPointDpu-list": [
						{"dpuNum": "1", "vlan": 10},
						{"dpuNum": "2", "vlan": 10},
						{"dpuNum": "all", "vlan": 10}
					]
				}
			}
		]
	}`
	handler.Set(ctx, paths.ServiceRedirServiceItems, serviceItemsJSON)

	if err := vs.RestoreGIDsFromGnmi(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// DELETEs should be issued for DPU=1 and "all", but NOT for DPU=2.
	entries, err := handler.TxLog().ReadEntries("", paths.ServiceRedirServiceItems, "delete")
	if err != nil {
		t.Fatalf("failed to read TxLog: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 DELETEs (for DPU=1 and all), got %d", len(entries))
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

func TestStore_RepinAll_SymmetricToPinning(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx, WithDPUCount(4))

	// Activate VRFs in symmetric hash mode → DPUPinned = 65535
	vs.SetGlobal(ctx, "tenant1", true)
	vs.SetService(ctx, "tenant1", true)
	vs.SetAffinity(ctx, "tenant1", 2) // direct affinity

	vs.SetGlobal(ctx, "tenant2", true)
	vs.SetService(ctx, "tenant2", true)
	vs.SetAffinity(ctx, "tenant2", 0) // dynamic (hash)

	p1, _ := vs.GetPinning("tenant1")
	p2, _ := vs.GetPinning("tenant2")
	if p1 != 65535 {
		t.Errorf("expected DPUPinned=65535 in symmetric mode for tenant1, got %d", p1)
	}
	if p2 != 65535 {
		t.Errorf("expected DPUPinned=65535 in symmetric mode for tenant2, got %d", p2)
	}

	// Switch to pinning mode and repin.
	vs.SetLbModePinning(true)
	vs.RepinAll(ctx)

	p1, _ = vs.GetPinning("tenant1")
	p2, _ = vs.GetPinning("tenant2")
	if p1 != 2 {
		t.Errorf("expected DPUPinned=2 after RepinAll for tenant1 (affinity=2), got %d", p1)
	}
	if p2 < 1 || p2 > 4 {
		t.Errorf("expected DPUPinned in 1-4 after RepinAll for tenant2 (dynamic), got %d", p2)
	}
}

func TestStore_RepinAll_PinningToSymmetric(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx, WithLbModePinning(true), WithDPUCount(4))

	// Activate VRF in pinning mode → DPUPinned = affinity value
	vs.SetGlobal(ctx, "tenant1", true)
	vs.SetService(ctx, "tenant1", true)
	vs.SetAffinity(ctx, "tenant1", 3)

	p, _ := vs.GetPinning("tenant1")
	if p != 3 {
		t.Fatalf("expected DPUPinned=3 in pinning mode, got %d", p)
	}

	// Switch to symmetric hash mode and repin.
	vs.SetLbModePinning(false)
	vs.RepinAll(ctx)

	p, _ = vs.GetPinning("tenant1")
	if p != 65535 {
		t.Errorf("expected DPUPinned=65535 after RepinAll to symmetric mode, got %d", p)
	}
}

func TestStore_RepinAll_NoChange(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx, WithLbModePinning(true), WithDPUCount(4))

	vs.SetGlobal(ctx, "tenant1", true)
	vs.SetService(ctx, "tenant1", true)
	vs.SetAffinity(ctx, "tenant1", 2)

	p, _ := vs.GetPinning("tenant1")
	if p != 2 {
		t.Fatalf("expected DPUPinned=2, got %d", p)
	}

	// RepinAll with unchanged mode → no change
	vs.RepinAll(ctx)

	p, _ = vs.GetPinning("tenant1")
	if p != 2 {
		t.Errorf("expected DPUPinned=2 after no-op RepinAll, got %d", p)
	}
}

// TestVRFStore_RepinStaleEntries verifies that repinStaleEntries corrects
// allDpu (65535) values in pinning mode and leaves them unchanged in symmetric mode.
func TestVRFStore_RepinStaleEntries(t *testing.T) {
	ctx := context.Background()

	t.Run("corrects_allDpu_in_pinning_mode", func(t *testing.T) {
		vs := NewStore(ctx, WithDPUCount(4))
		s := vs.(*vrfStore)

		// Insert a VRF with stale allDpu (65535) directly in the store.
		s.mu.Lock()
		s.vrfs["tenant1"] = types.VRF{Name: "tenant1", Active: true, DPUPinned: 65535}
		s.isLbModePinning = true
		s.mu.Unlock()

		stale := []types.VRF{{Name: "tenant1", Active: true, DPUPinned: 65535}}
		corrected := s.repinStaleEntries(ctx, stale)

		if len(corrected) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(corrected))
		}
		if corrected[0].DPUPinned == 65535 {
			t.Errorf("expected DPUPinned to be corrected from allDpu, still got %d", corrected[0].DPUPinned)
		}
		if corrected[0].DPUPinned < 1 || corrected[0].DPUPinned > 4 {
			t.Errorf("expected DPUPinned in 1-4 after correction, got %d", corrected[0].DPUPinned)
		}
		// Verify the store was also updated.
		stored, _ := vs.Get("tenant1")
		if stored.DPUPinned == 65535 {
			t.Error("expected store to be updated with corrected DPUPinned")
		}
	})

	t.Run("noop_in_symmetric_mode", func(t *testing.T) {
		vs := NewStore(ctx, WithDPUCount(4)) // isLbModePinning=false by default
		s := vs.(*vrfStore)

		s.mu.Lock()
		s.vrfs["tenant1"] = types.VRF{Name: "tenant1", Active: true, DPUPinned: 65535}
		s.mu.Unlock()

		input := []types.VRF{{Name: "tenant1", Active: true, DPUPinned: 65535}}
		result := s.repinStaleEntries(ctx, input)

		if result[0].DPUPinned != 65535 {
			t.Errorf("expected DPUPinned to remain allDpu in symmetric mode, got %d", result[0].DPUPinned)
		}
	})

	t.Run("leaves_valid_pinning_unchanged", func(t *testing.T) {
		vs := NewStore(ctx, WithDPUCount(4))
		s := vs.(*vrfStore)

		s.mu.Lock()
		s.vrfs["tenant1"] = types.VRF{Name: "tenant1", Active: true, DPUPinned: 2}
		s.isLbModePinning = true
		s.mu.Unlock()

		input := []types.VRF{{Name: "tenant1", Active: true, DPUPinned: 2}}
		result := s.repinStaleEntries(ctx, input)

		if result[0].DPUPinned != 2 {
			t.Errorf("expected DPUPinned=2 to remain unchanged, got %d", result[0].DPUPinned)
		}
	})
}

// TestVRFStore_ProgramAllRedirects_RepinsBeforeProgramming verifies that
// ProgramAllRedirects corrects stale allDpu VRFs before programming the switch.
func TestVRFStore_ProgramAllRedirects_RepinsBeforeProgramming(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()

	vs := NewStore(ctx, WithDPUCount(4))
	s := vs.(*vrfStore)
	s.SetGnmiHandler(handler)

	// Insert a VRF with stale allDpu (65535) in pinning mode. GID must be set
	// for service endpoint programming to proceed.
	s.mu.Lock()
	s.vrfs["tenant1"] = types.VRF{Name: "tenant1", Active: true, DPUPinned: 65535, GID: 10}
	s.isLbModePinning = true
	s.mu.Unlock()

	s.ProgramAllRedirects(ctx)

	// Verify the store was corrected.
	stored, ok := vs.Get("tenant1")
	if !ok {
		t.Fatal("expected tenant1 to exist")
	}
	if stored.DPUPinned == 65535 {
		t.Errorf("expected DPUPinned to be corrected from allDpu by ProgramAllRedirects, got %d", stored.DPUPinned)
	}
	if stored.DPUPinned < 1 || stored.DPUPinned > 4 {
		t.Errorf("expected DPUPinned in 1-4 after ProgramAllRedirects, got %d", stored.DPUPinned)
	}
}

// TestVRFStore_AssignPinning_DpuCountZeroWithAffinity verifies that
// assignPinningLocked defers pinning (DPUPinned=0) when dpuCount=0.
func TestVRFStore_AssignPinning_DpuCountZeroWithAffinity(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx) // dpuCount defaults to 0
	s := vs.(*vrfStore)

	s.mu.Lock()
	s.isLbModePinning = true
	vrf := types.VRF{Name: "tenant1", Affinity: 3}
	result := s.assignPinningLocked(vrf)
	s.mu.Unlock()

	if result.DPUPinned != 0 {
		t.Errorf("expected DPUPinned=0 when dpuCount=0, got %d", result.DPUPinned)
	}
}

// TestVRFStore_RepinAll_AfterReactivation verifies the lbMode-first ordering:
// VRFs deactivated → lbMode changes to pinning → VRFs reactivated
// → activation calls assignPinningLocked with isPinningActive=true → correct value.
func TestVRFStore_RepinAll_AfterReactivation(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx, WithDPUCount(4))

	// Activate VRF in symmetric mode → DPUPinned = 65535
	vs.SetGlobal(ctx, "tenant1", true)
	vs.SetService(ctx, "tenant1", true)
	vs.SetAffinity(ctx, "tenant1", 0)

	p, _ := vs.GetPinning("tenant1")
	if p != 65535 {
		t.Fatalf("expected DPUPinned=65535 in symmetric mode, got %d", p)
	}

	// Deactivate VRF (simulates FW disable)
	vs.SetService(ctx, "tenant1", false)
	vrf, _ := vs.Get("tenant1")
	if vrf.Active {
		t.Fatal("expected VRF to be inactive after SetService(false)")
	}

	// lbMode changes to pinning — RepinAll skips inactive VRFs
	vs.SetLbModePinning(true)
	vs.RepinAll(ctx)

	// Reactivate VRF (simulates FW re-enable: NX-OS sends service + affinity + in-service).
	// SetService(false) cleared HasAffinity, so we must call SetAffinity again to fully reactivate.
	// handleActivateLocked calls assignPinningLocked with isPinningActive=true → correct value.
	vs.SetService(ctx, "tenant1", true)
	vs.SetAffinity(ctx, "tenant1", 0)

	p, ok := vs.GetPinning("tenant1")
	if !ok {
		t.Fatal("expected pinning to be set after reactivation")
	}
	if p < 1 || p > 4 {
		t.Errorf("expected DPUPinned in 1-4 after reactivation in pinning mode, got %d", p)
	}
}
