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

	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"

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
	vs := NewStore(context.Background(), WithLbModePinning(func() bool { return true }), WithDPUCount(4))
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
	vs := NewStore(context.Background(), WithLbModePinning(func() bool { return true }), WithDPUCount(4))
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
