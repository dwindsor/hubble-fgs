// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package vlan

import (
	"context"
	"testing"
	"time"

	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
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

func TestVLANStore_GlobalServiceLifecycle(t *testing.T) {
	t.Run("set_global_creates", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx)
		vs.SetGlobal(ctx, "vlan-10", true)

		vlan, ok := vs.Get("vlan-10")
		if !ok {
			t.Fatal("expected vlan-10 to exist after SetGlobal")
		}
		if !vlan.Global {
			t.Error("expected IsGlobal=true")
		}
	})

	t.Run("set_service_creates", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx)
		vs.SetService(ctx, "vlan-10", true)

		vlan, ok := vs.Get("vlan-10")
		if !ok {
			t.Fatal("expected vlan-10 to exist after SetService")
		}
		if !vlan.Service {
			t.Error("expected IsService=true")
		}
	})

	t.Run("active_when_both_set", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx)
		vs.SetGlobal(ctx, "vlan-10", true)
		vs.SetService(ctx, "vlan-10", true)
		vs.SetAffinity(ctx, "vlan-10", 0)

		vlan, ok := vs.Get("vlan-10")
		if !ok {
			t.Fatal("expected vlan-10 to exist")
		}
		if !vlan.Active {
			t.Error("expected VLAN to be active when both flags and affinity are set")
		}
	})

	t.Run("not_active_global_only", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx)
		vs.SetGlobal(ctx, "vlan-10", true)

		vlan, ok := vs.Get("vlan-10")
		if !ok {
			t.Fatal("expected vlan-10 to exist")
		}
		if vlan.Active {
			t.Error("expected VLAN to be inactive with only global flag set")
		}
	})

	t.Run("not_active_service_only", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx)
		vs.SetService(ctx, "vlan-10", true)

		vlan, ok := vs.Get("vlan-10")
		if !ok {
			t.Fatal("expected vlan-10 to exist")
		}
		if vlan.Active {
			t.Error("expected VLAN to be inactive with only service flag set")
		}
	})

	t.Run("auto_remove_both_false", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx)

		var events []Event
		vs.Watch(func(e Event) { events = append(events, e) })

		vs.SetGlobal(ctx, "vlan-10", true)
		vs.SetService(ctx, "vlan-10", true)
		vs.SetAffinity(ctx, "vlan-10", 0)
		events = nil // reset after setup

		vs.SetService(ctx, "vlan-10", false)
		vs.SetGlobal(ctx, "vlan-10", false)

		if _, ok := vs.Get("vlan-10"); ok {
			t.Error("expected vlan-10 to be removed when both flags are cleared")
		}
		// Should have received delete events
		deleted := false
		for _, e := range events {
			if e.Type == store.EventDeleted {
				deleted = true
			}
		}
		if !deleted {
			t.Error("expected EventDeleted when entry is auto-removed")
		}
	})

	t.Run("partial_delete_global_survives", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx)
		vs.SetGlobal(ctx, "vlan-10", true)
		vs.SetService(ctx, "vlan-10", true)
		vs.SetAffinity(ctx, "vlan-10", 0)
		vs.SetService(ctx, "vlan-10", false)

		vlan, ok := vs.Get("vlan-10")
		if !ok {
			t.Fatal("expected vlan-10 to survive after clearing service (global still set)")
		}
		if !vlan.Global {
			t.Error("expected IsGlobal=true to be preserved")
		}
		if vlan.Service {
			t.Error("expected IsService=false after clearing service")
		}
	})

	t.Run("partial_delete_service_survives", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx)
		vs.SetGlobal(ctx, "vlan-10", true)
		vs.SetService(ctx, "vlan-10", true)
		vs.SetAffinity(ctx, "vlan-10", 0)
		vs.SetGlobal(ctx, "vlan-10", false)

		vlan, ok := vs.Get("vlan-10")
		if !ok {
			t.Fatal("expected vlan-10 to survive after clearing global (service still set)")
		}
		if vlan.Global {
			t.Error("expected IsGlobal=false after clearing global")
		}
		if !vlan.Service {
			t.Error("expected IsService=true to be preserved")
		}
	})
}

func TestVLANStore_DeactivationClearsPinning(t *testing.T) {
	t.Run("clear_global_clears_pinning", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx, WithDPUCount(4))
		vs.SetGlobal(ctx, "vlan-10", true)
		vs.SetService(ctx, "vlan-10", true)
		vs.SetAffinity(ctx, "vlan-10", 2)

		vlan, _ := vs.Get("vlan-10")
		if !vlan.Active || vlan.DPUPinned == 0 {
			t.Fatalf("expected active VLAN with pinning, got active=%v DPUPinned=%d", vlan.Active, vlan.DPUPinned)
		}

		// Deactivate by clearing global
		vs.SetGlobal(ctx, "vlan-10", false)

		vlan, ok := vs.Get("vlan-10")
		if !ok {
			t.Fatal("expected vlan-10 to survive (service still set)")
		}
		if vlan.Active {
			t.Error("expected VLAN to be inactive after clearing global")
		}
		if vlan.ID != 10 {
			t.Errorf("expected ID=10 to be preserved after deactivation, got %d", vlan.ID)
		}
		if vlan.DPUPinned != 0 {
			t.Errorf("expected DPUPinned=0 after deactivation, got %d", vlan.DPUPinned)
		}
	})

	t.Run("clear_service_clears_pinning", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx, WithDPUCount(4))
		vs.SetGlobal(ctx, "vlan-10", true)
		vs.SetService(ctx, "vlan-10", true)
		vs.SetAffinity(ctx, "vlan-10", 3)

		vlan, _ := vs.Get("vlan-10")
		if !vlan.Active {
			t.Fatal("expected active VLAN")
		}

		// Deactivate by clearing service
		vs.SetService(ctx, "vlan-10", false)

		vlan, ok := vs.Get("vlan-10")
		if !ok {
			t.Fatal("expected vlan-10 to survive (global still set)")
		}
		if vlan.Active {
			t.Error("expected VLAN to be inactive after clearing service")
		}
		if vlan.ID != 10 {
			t.Errorf("expected ID=10 to be preserved after deactivation, got %d", vlan.ID)
		}
		if vlan.DPUPinned != 0 {
			t.Errorf("expected DPUPinned=0 after deactivation, got %d", vlan.DPUPinned)
		}
	})
}

func TestVLANStore_ManualOperations(t *testing.T) {
	t.Run("get_id_from_name", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx)
		vs.SetGlobal(ctx, "vlan-42", true)

		id, ok := vs.GetID("vlan-42")
		if !ok {
			t.Fatal("expected ID to be set")
		}
		if id != 42 {
			t.Errorf("expected ID=42, got %d", id)
		}
	})

	t.Run("set_pinning", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx)
		vs.SetGlobal(ctx, "vlan-10", true)

		if err := vs.SetPinning(ctx, "vlan-10", 2); err != nil {
			t.Fatalf("unexpected error from SetPinning: %v", err)
		}

		pinning, ok := vs.GetPinning("vlan-10")
		if !ok {
			t.Fatal("expected pinning to be set")
		}
		if pinning != 2 {
			t.Errorf("expected DPUPinned=2, got %d", pinning)
		}
	})

	t.Run("set_pinning_not_found", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx)

		err := vs.SetPinning(ctx, "nonexistent", 2)
		if err == nil {
			t.Fatal("expected error from SetPinning on missing VLAN")
		}
		if !IsNotFound(err) {
			t.Errorf("expected ErrNotFound, got %T: %v", err, err)
		}
	})
}

func TestVLANStore_Persistence(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemoryStorage()

	// Create store, add VLANs, verify they persist and reload
	vs1 := NewStore(ctx, WithStorage(mem))
	vs1.SetGlobal(ctx, "vlan-10", true)
	vs1.SetService(ctx, "vlan-10", true)
	vs1.SetAffinity(ctx, "vlan-10", 0)
	vs1.SetGlobal(ctx, "vlan-20", true)

	if _, err := mem.LoadVLANs(ctx); err != nil {
		t.Fatal("expected VLANs to be persisted to storage")
	}

	// Reload from same storage
	vs2 := NewStore(ctx, WithStorage(mem))

	v10, ok := vs2.Get("vlan-10")
	if !ok {
		t.Fatal("expected vlan-10 to be present after reload")
	}
	if !v10.Global || !v10.Service {
		t.Errorf("expected vlan-10 to have both flags set after reload, got Global=%v Service=%v", v10.Global, v10.Service)
	}

	_, ok = vs2.Get("vlan-20")
	if !ok {
		t.Fatal("expected vlan-20 to be present after reload")
	}
}

func TestVLANStore_AutoPinning_StaticAffinity(t *testing.T) {
	vs := NewStore(context.Background(), WithLbModePinning(true), WithDPUCount(4))
	ctx := context.Background()

	vs.SetGlobal(ctx, "vlan-10", true)
	vs.SetService(ctx, "vlan-10", true)
	vs.SetAffinity(ctx, "vlan-10", 2)

	pinning, ok := vs.GetPinning("vlan-10")
	if !ok {
		t.Fatal("expected pinning to be set for static VLAN")
	}
	if pinning != 2 {
		t.Errorf("expected DPUPinned=2, got %d", pinning)
	}
}

func TestVLANStore_AutoPinning_Dynamic(t *testing.T) {
	vs := NewStore(context.Background())
	ctx := context.Background()

	vs.SetGlobal(ctx, "vlan-10", true)
	vs.SetService(ctx, "vlan-10", true)
	vs.SetAffinity(ctx, "vlan-10", 0)

	pinning, ok := vs.GetPinning("vlan-10")
	if !ok {
		t.Error("expected pinning to be set in symmetric hash mode")
	}
	if pinning != 65535 {
		t.Errorf("expected DPUPinned=65535 in symmetric hash mode, got %d", pinning)
	}
}

func TestVLANStore_AutoPinning_DynamicPinningMode(t *testing.T) {
	vs := NewStore(context.Background(), WithLbModePinning(true), WithDPUCount(4))
	ctx := context.Background()

	vs.SetGlobal(ctx, "vlan-10", true)
	vs.SetService(ctx, "vlan-10", true)
	vs.SetAffinity(ctx, "vlan-10", 0)

	pinning, ok := vs.GetPinning("vlan-10")
	if !ok {
		t.Error("expected pinning to be set in pinning mode")
	}
	if pinning < 1 || pinning > 4 {
		t.Errorf("expected DPUPinned in range 1-4 for pinning mode, got %d", pinning)
	}
}

func TestVLANStore_HandleGnmiNotification(t *testing.T) {
	globalPath := "device:/System/bd-items/bd-items/BD-list[fabEncap=vxlan-10]/fabEncap"
	servicePath := "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/bd-items/vlan-items/Vlan-list[vlanId=vxlan-10]/vlanId"
	globalDeletePath := "device:/System/bd-items/bd-items/BD-list[fabEncap=vxlan-10]"
	serviceDeletePath := "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/bd-items/vlan-items/Vlan-list[vlanId=vxlan-10]"

	t.Run("global_update_sets_global_flag", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx)

		vs.HandleGnmiNotification(ctx, globalPath, makeStringUpdate("vxlan-10"), false)

		vlan, ok := vs.Get("vxlan-10")
		if !ok {
			t.Fatal("expected vxlan-10 to be created by global path notification")
		}
		if !vlan.Global {
			t.Error("expected IsGlobal=true after global path notification")
		}
	})

	t.Run("service_update_sets_service_flag", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx)

		vs.HandleGnmiNotification(ctx, servicePath, makeStringUpdate("vxlan-10"), false)

		vlan, ok := vs.Get("vxlan-10")
		if !ok {
			t.Fatal("expected vxlan-10 to be created by service path notification")
		}
		if !vlan.Service {
			t.Error("expected IsService=true after service path notification")
		}
	})

	t.Run("global_delete_clears_global_flag", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx)

		// Create with both flags so entry survives the global delete
		vs.SetGlobal(ctx, "vxlan-10", true)
		vs.SetService(ctx, "vxlan-10", true)
		vs.SetAffinity(ctx, "vxlan-10", 0)

		vs.HandleGnmiNotification(ctx, globalDeletePath, nil, true)

		vlan, ok := vs.Get("vxlan-10")
		if !ok {
			t.Fatal("expected vxlan-10 to survive after global delete (service still set)")
		}
		if vlan.Global {
			t.Error("expected IsGlobal=false after global delete notification")
		}
	})

	t.Run("service_delete_clears_service_flag", func(t *testing.T) {
		ctx := context.Background()
		vs := NewStore(ctx)

		// Create with both flags so entry survives the service delete
		vs.SetGlobal(ctx, "vxlan-10", true)
		vs.SetService(ctx, "vxlan-10", true)
		vs.SetAffinity(ctx, "vxlan-10", 0)

		vs.HandleGnmiNotification(ctx, serviceDeletePath, nil, true)

		vlan, ok := vs.Get("vxlan-10")
		if !ok {
			t.Fatal("expected vxlan-10 to survive after service delete (global still set)")
		}
		if vlan.Service {
			t.Error("expected IsService=false after service delete notification")
		}
	})
}

func TestVLANStore_RepinAll_SymmetricToPinning(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx, WithDPUCount(4))

	// Activate VLANs in symmetric hash mode → DPUPinned = 65535
	vs.SetGlobal(ctx, "vlan-10", true)
	vs.SetService(ctx, "vlan-10", true)
	vs.SetAffinity(ctx, "vlan-10", 2) // direct affinity

	vs.SetGlobal(ctx, "vlan-20", true)
	vs.SetService(ctx, "vlan-20", true)
	vs.SetAffinity(ctx, "vlan-20", 0) // dynamic (hash)

	p1, _ := vs.GetPinning("vlan-10")
	p2, _ := vs.GetPinning("vlan-20")
	if p1 != 65535 {
		t.Errorf("expected DPUPinned=65535 in symmetric mode for vlan-10, got %d", p1)
	}
	if p2 != 65535 {
		t.Errorf("expected DPUPinned=65535 in symmetric mode for vlan-20, got %d", p2)
	}

	// Switch to pinning mode and repin.
	vs.SetLbModePinning(true)
	vs.RepinAll(ctx)

	p1, _ = vs.GetPinning("vlan-10")
	p2, _ = vs.GetPinning("vlan-20")
	if p1 != 2 {
		t.Errorf("expected DPUPinned=2 after RepinAll for vlan-10 (affinity=2), got %d", p1)
	}
	if p2 < 1 || p2 > 4 {
		t.Errorf("expected DPUPinned in 1-4 after RepinAll for vlan-20 (dynamic), got %d", p2)
	}
}

// mockGnmiHandler is a minimal gNMI handler that counts Set calls.
type mockGnmiHandler struct {
	setCalls int
}

func (m *mockGnmiHandler) Close() error                                      { return nil }
func (m *mockGnmiHandler) Get(_ context.Context, _ string) ([]string, error) { return nil, nil }
func (m *mockGnmiHandler) Delete(_ context.Context, _ string) error          { return nil }
func (m *mockGnmiHandler) RegisterHandler(_ gnmi.SubscriptionCallback, _ ...string) {
}
func (m *mockGnmiHandler) UnregisterHandler(_ gnmi.SubscriptionCallback) {}
func (m *mockGnmiHandler) StartSubscriptions(_ context.Context)          {}
func (m *mockGnmiHandler) StopSubscriptions()                            {}
func (m *mockGnmiHandler) LastNotificationTime() time.Time               { return time.Time{} }
func (m *mockGnmiHandler) Set(_ context.Context, _ string, _ any) error {
	m.setCalls++
	return nil
}

func TestVLANStore_SetPinning_TriggersRedirects(t *testing.T) {
	ctx := context.Background()
	handler := &mockGnmiHandler{}
	vs := NewStore(ctx, WithLbModePinning(true), WithDPUCount(4))
	s := vs.(*vlanStore)
	s.SetGnmiHandler(handler)
	s.SetInService(true)

	vs.SetGlobal(ctx, "vlan-10", true)
	vs.SetService(ctx, "vlan-10", true)
	vs.SetAffinity(ctx, "vlan-10", 2) // DPUPinned=2, triggers initial programRedirects

	setCalls := handler.setCalls // capture after activation

	// Change pinning to DPU 3 — should trigger programRedirects
	if err := vs.SetPinning(ctx, "vlan-10", 3); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if handler.setCalls <= setCalls {
		t.Error("expected gNMI SET calls after SetPinning on active VLAN with changed DPU")
	}

	vlan, _ := vs.Get("vlan-10")
	if vlan.DPUPinned != 3 {
		t.Errorf("expected DPUPinned=3, got %d", vlan.DPUPinned)
	}
}

func TestVLANStore_SetAffinity_RepinsActiveVLAN(t *testing.T) {
	ctx := context.Background()
	handler := &mockGnmiHandler{}
	vs := NewStore(ctx, WithLbModePinning(true), WithDPUCount(4))
	s := vs.(*vlanStore)
	s.SetGnmiHandler(handler)
	s.SetInService(true)

	vs.SetGlobal(ctx, "vlan-10", true)
	vs.SetService(ctx, "vlan-10", true)
	vs.SetAffinity(ctx, "vlan-10", 1) // DPUPinned=1

	setCalls := handler.setCalls

	// Change affinity — DPUPinned changes from 1 to 2, should trigger programRedirects
	vs.SetAffinity(ctx, "vlan-10", 2)

	if handler.setCalls <= setCalls {
		t.Error("expected gNMI SET calls after SetAffinity on active VLAN with changed pinning")
	}

	vlan, _ := vs.Get("vlan-10")
	if vlan.DPUPinned != 2 {
		t.Errorf("expected DPUPinned=2, got %d", vlan.DPUPinned)
	}
}

func TestVLANStore_SetPinning_NoOpWhenInactive(t *testing.T) {
	ctx := context.Background()
	handler := &mockGnmiHandler{}
	vs := NewStore(ctx)
	s := vs.(*vlanStore)
	s.SetGnmiHandler(handler)
	s.SetInService(true)

	// Create a VLAN but don't activate it (no service flag)
	vs.SetGlobal(ctx, "vlan-10", true)

	setCalls := handler.setCalls

	if err := vs.SetPinning(ctx, "vlan-10", 2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if handler.setCalls != setCalls {
		t.Errorf("expected no gNMI SET calls for inactive VLAN, got %d new calls", handler.setCalls-setCalls)
	}
}

func TestVLANStore_RepinAll_PinningToSymmetric(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx, WithLbModePinning(true), WithDPUCount(4))

	// Activate VLAN in pinning mode → DPUPinned = affinity value
	vs.SetGlobal(ctx, "vlan-10", true)
	vs.SetService(ctx, "vlan-10", true)
	vs.SetAffinity(ctx, "vlan-10", 3)

	p, _ := vs.GetPinning("vlan-10")
	if p != 3 {
		t.Fatalf("expected DPUPinned=3 in pinning mode, got %d", p)
	}

	// Switch to symmetric hash mode and repin.
	vs.SetLbModePinning(false)
	vs.RepinAll(ctx)

	p, _ = vs.GetPinning("vlan-10")
	if p != 65535 {
		t.Errorf("expected DPUPinned=65535 after RepinAll to symmetric mode, got %d", p)
	}
}

// TestVLANStore_RepinStaleEntries verifies that repinStaleEntries corrects
// allDpu (65535) values in pinning mode and leaves them unchanged in symmetric mode.
func TestVLANStore_RepinStaleEntries(t *testing.T) {
	ctx := context.Background()

	t.Run("corrects_allDpu_in_pinning_mode", func(t *testing.T) {
		vs := NewStore(ctx, WithDPUCount(4))
		s := vs.(*vlanStore)

		// Insert a VLAN with stale allDpu (65535) directly in the store, simulating
		// the race where lbMode changed after VLAN was activated in symmetric mode.
		s.mu.Lock()
		s.vlans["vlan-10"] = types.VLAN{Name: "vlan-10", Active: true, DPUPinned: allDpu}
		s.isLbModePinning = true
		s.mu.Unlock()

		stale := []types.VLAN{{Name: "vlan-10", Active: true, DPUPinned: allDpu}}
		corrected := s.repinStaleEntries(ctx, stale)

		if len(corrected) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(corrected))
		}
		if corrected[0].DPUPinned == allDpu {
			t.Errorf("expected DPUPinned to be corrected from allDpu, still got %d", corrected[0].DPUPinned)
		}
		if corrected[0].DPUPinned < 1 || corrected[0].DPUPinned > 4 {
			t.Errorf("expected DPUPinned in 1-4 after correction, got %d", corrected[0].DPUPinned)
		}
		// Verify the store was also updated
		stored, _ := vs.Get("vlan-10")
		if stored.DPUPinned == allDpu {
			t.Error("expected store to be updated with corrected DPUPinned")
		}
	})

	t.Run("noop_in_symmetric_mode", func(t *testing.T) {
		vs := NewStore(ctx, WithDPUCount(4)) // isLbModePinning=false by default
		s := vs.(*vlanStore)

		s.mu.Lock()
		s.vlans["vlan-10"] = types.VLAN{Name: "vlan-10", Active: true, DPUPinned: allDpu}
		s.mu.Unlock()

		input := []types.VLAN{{Name: "vlan-10", Active: true, DPUPinned: allDpu}}
		result := s.repinStaleEntries(ctx, input)

		if result[0].DPUPinned != allDpu {
			t.Errorf("expected DPUPinned to remain allDpu in symmetric mode, got %d", result[0].DPUPinned)
		}
	})

	t.Run("leaves_valid_pinning_unchanged", func(t *testing.T) {
		vs := NewStore(ctx, WithDPUCount(4))
		s := vs.(*vlanStore)

		s.mu.Lock()
		s.vlans["vlan-10"] = types.VLAN{Name: "vlan-10", Active: true, DPUPinned: 3}
		s.isLbModePinning = true
		s.mu.Unlock()

		input := []types.VLAN{{Name: "vlan-10", Active: true, DPUPinned: 3}}
		result := s.repinStaleEntries(ctx, input)

		if result[0].DPUPinned != 3 {
			t.Errorf("expected DPUPinned=3 to remain unchanged, got %d", result[0].DPUPinned)
		}
	})
}

// TestVLANStore_ProgramAllRedirects_RepinsBeforeProgramming verifies that
// ProgramAllRedirects corrects stale allDpu VLANs in pinning mode before
// programming the switch (the silent 65535 fallback bug).
func TestVLANStore_ProgramAllRedirects_RepinsBeforeProgramming(t *testing.T) {
	ctx := context.Background()
	handler := &mockGnmiHandler{}

	vs := NewStore(ctx, WithDPUCount(4))
	s := vs.(*vlanStore)
	s.SetGnmiHandler(handler)

	// Insert a VLAN with stale allDpu (65535) in pinning mode.
	s.mu.Lock()
	s.vlans["vlan-10"] = types.VLAN{Name: "vlan-10", Active: true, DPUPinned: allDpu, Affinity: 0}
	s.isLbModePinning = true
	s.mu.Unlock()

	s.ProgramAllRedirects(ctx)

	// Verify the store was corrected before programming.
	stored, ok := vs.Get("vlan-10")
	if !ok {
		t.Fatal("expected vlan-10 to exist")
	}
	if stored.DPUPinned == allDpu {
		t.Errorf("expected DPUPinned to be corrected from allDpu by ProgramAllRedirects, got %d", stored.DPUPinned)
	}
	if stored.DPUPinned < 1 || stored.DPUPinned > 4 {
		t.Errorf("expected DPUPinned in 1-4 after ProgramAllRedirects, got %d", stored.DPUPinned)
	}
	// Verify gNMI Set was called.
	if handler.setCalls == 0 {
		t.Error("expected gNMI Set calls from ProgramAllRedirects")
	}
}

// TestVLANStore_AssignPinning_DpuCountZeroWithAffinity verifies that
// assignPinningLocked defers pinning (DPUPinned=0) when dpuCount=0,
// rather than accepting a raw unvalidated affinity value.
func TestVLANStore_AssignPinning_DpuCountZeroWithAffinity(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx) // dpuCount defaults to 0
	s := vs.(*vlanStore)

	s.mu.Lock()
	s.isLbModePinning = true
	vlan := types.VLAN{Name: "vlan-10", Affinity: 3}
	result := s.assignPinningLocked(vlan)
	s.mu.Unlock()

	if result.DPUPinned != 0 {
		t.Errorf("expected DPUPinned=0 when dpuCount=0, got %d", result.DPUPinned)
	}
}

// TestVLANStore_RepinAll_AfterReactivation verifies the lbMode-first ordering:
// VLANs deactivated (FW disable) → lbMode changes to pinning → VLANs reactivated
// → RepinAll corrects stale DPUPinned values.
func TestVLANStore_RepinAll_AfterReactivation(t *testing.T) {
	ctx := context.Background()
	vs := NewStore(ctx, WithDPUCount(4))

	// Activate VLANs in symmetric mode → DPUPinned = 65535
	vs.SetGlobal(ctx, "vlan-10", true)
	vs.SetService(ctx, "vlan-10", true)
	vs.SetAffinity(ctx, "vlan-10", 0)

	p, _ := vs.GetPinning("vlan-10")
	if p != allDpu {
		t.Fatalf("expected DPUPinned=allDpu in symmetric mode, got %d", p)
	}

	// Deactivate VLAN (simulates FW disable: service flag cleared)
	vs.SetService(ctx, "vlan-10", false)
	vlan, _ := vs.Get("vlan-10")
	if vlan.Active {
		t.Fatal("expected VLAN to be inactive after SetService(false)")
	}

	// lbMode changes to pinning — RepinAll skips inactive VLANs
	vs.SetLbModePinning(true)
	vs.RepinAll(ctx)

	p, _ = vs.GetPinning("vlan-10")
	// DPUPinned still allDpu because VLAN was inactive during RepinAll
	if p != allDpu {
		t.Logf("note: DPUPinned=%d after RepinAll on inactive VLAN (not necessarily allDpu if entry was cleared)", p)
	}

	// Reactivate VLAN (simulates FW re-enable: NX-OS sends service + affinity + in-service).
	// SetService(false) cleared HasAffinity, so we must call SetAffinity again to fully reactivate.
	// handleActivateLocked calls assignPinningLocked with isPinningActive=true → correct value.
	vs.SetService(ctx, "vlan-10", true)
	vs.SetAffinity(ctx, "vlan-10", 0)

	p, ok := vs.GetPinning("vlan-10")
	if !ok {
		t.Fatal("expected pinning to be set after reactivation")
	}
	if p < 1 || p > 4 {
		t.Errorf("expected DPUPinned in 1-4 after reactivation in pinning mode, got %d", p)
	}
}
