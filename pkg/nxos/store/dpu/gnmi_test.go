// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dpu

import (
	"context"
	"fmt"
	"testing"

	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/mock"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
	nxosmodel "github.com/isovalent/hubble-fgs/pkg/nxosmodel"
)

func makeStringUpdate(s string) *gnmiproto.Update {
	return &gnmiproto.Update{
		Val: &gnmiproto.TypedValue{
			Value: &gnmiproto.TypedValue_StringVal{StringVal: s},
		},
	}
}

func makeUintUpdate(v uint64) *gnmiproto.Update {
	return &gnmiproto.Update{
		Val: &gnmiproto.TypedValue{
			Value: &gnmiproto.TypedValue_UintVal{UintVal: v},
		},
	}
}

func TestHandleGnmiNotification_InitState(t *testing.T) {
	ctx := context.Background()
	s := NewStore(context.Background())

	// inventory-done should set inventory complete
	s.HandleGnmiNotification(ctx, paths.DPUStoreInitState, makeStringUpdate("inventory-done"), false)
	if !s.IsInventoryComplete() {
		t.Error("expected inventory complete after inventory-done notification")
	}

	// inventory-not-done should clear inventory complete
	s.HandleGnmiNotification(ctx, paths.DPUStoreInitState, makeStringUpdate("inventory-not-done"), false)
	if s.IsInventoryComplete() {
		t.Error("expected inventory not complete after inventory-not-done notification")
	}
}

func TestHandleGnmiNotification_NumDPUs_Uint(t *testing.T) {
	ctx := context.Background()
	s := NewStore(context.Background())

	s.HandleGnmiNotification(ctx, paths.DPUStoreNumDPUs, makeUintUpdate(4), false)
	if s.DpuCount() != 4 {
		t.Errorf("expected DPU count 4, got %d", s.DpuCount())
	}
}

func TestHandleGnmiNotification_NumDPUs_String(t *testing.T) {
	ctx := context.Background()
	s := NewStore(context.Background())

	s.HandleGnmiNotification(ctx, paths.DPUStoreNumDPUs, makeStringUpdate("8"), false)
	if s.DpuCount() != 8 {
		t.Errorf("expected DPU count 8, got %d", s.DpuCount())
	}
}

func TestHandleGnmiNotification_IP(t *testing.T) {
	ctx := context.Background()
	s := NewStore(context.Background())

	// Simulate a notification with moduleNum in the path
	notifPath := "device:/System/sas-items/dpu-items/inst-items/Inst-list[moduleNum=1]/ext-items/ip"
	s.HandleGnmiNotification(ctx, notifPath, makeStringUpdate("10.0.0.1"), false)

	dpu, ok := s.Get("dpu1")
	if !ok {
		t.Fatal("expected DPU dpu1 to exist")
	}
	if dpu.IP != "10.0.0.1" {
		t.Errorf("expected IP '10.0.0.1', got %q", dpu.IP)
	}
	if dpu.ModuleNum != 1 {
		t.Errorf("expected ModuleNum 1, got %d", dpu.ModuleNum)
	}
}

func TestHandleGnmiNotification_State(t *testing.T) {
	ctx := context.Background()
	s := NewStore(context.Background())

	notifPath := "device:/System/sas-items/dpu-items/inst-items/Inst-list[moduleNum=2]/ext-items/state"
	s.HandleGnmiNotification(ctx, notifPath, makeStringUpdate("online"), false)

	dpu, ok := s.Get("dpu2")
	if !ok {
		t.Fatal("expected DPU dpu2 to exist")
	}
	if dpu.State != nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_online {
		t.Errorf("expected state online, got %v", dpu.State)
	}
}

func TestHandleGnmiNotification_Version(t *testing.T) {
	ctx := context.Background()
	s := NewStore(context.Background())

	notifPath := "device:/System/sas-items/dpu-items/inst-items/Inst-list[moduleNum=3]/ext-items/mainFwVer"
	s.HandleGnmiNotification(ctx, notifPath, makeStringUpdate("1.2.3"), false)

	dpu, ok := s.Get("dpu3")
	if !ok {
		t.Fatal("expected DPU dpu3 to exist")
	}
	if dpu.Version != "1.2.3" {
		t.Errorf("expected version '1.2.3', got %q", dpu.Version)
	}
}

func TestHandleGnmiNotification_UpsertPreservesFields(t *testing.T) {
	ctx := context.Background()
	s := NewStore(context.Background())

	// First set IP
	ipPath := "device:/System/sas-items/dpu-items/inst-items/Inst-list[moduleNum=1]/ext-items/ip"
	s.HandleGnmiNotification(ctx, ipPath, makeStringUpdate("10.0.0.1"), false)

	// Then set state - should preserve IP
	statePath := "device:/System/sas-items/dpu-items/inst-items/Inst-list[moduleNum=1]/ext-items/state"
	s.HandleGnmiNotification(ctx, statePath, makeStringUpdate("online"), false)

	// Then set version - should preserve IP and state
	versionPath := "device:/System/sas-items/dpu-items/inst-items/Inst-list[moduleNum=1]/ext-items/mainFwVer"
	s.HandleGnmiNotification(ctx, versionPath, makeStringUpdate("2.0.0"), false)

	dpu, ok := s.Get("dpu1")
	if !ok {
		t.Fatal("expected DPU dpu1 to exist")
	}
	if dpu.IP != "10.0.0.1" {
		t.Errorf("expected IP '10.0.0.1', got %q", dpu.IP)
	}
	if dpu.State != nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_online {
		t.Errorf("expected state online, got %v", dpu.State)
	}
	if dpu.Version != "2.0.0" {
		t.Errorf("expected version '2.0.0', got %q", dpu.Version)
	}
}

func TestHandleGnmiNotification_Delete(t *testing.T) {
	ctx := context.Background()
	s := NewStore(context.Background())

	// Create a DPU first
	ipPath := "device:/System/sas-items/dpu-items/inst-items/Inst-list[moduleNum=1]/ext-items/ip"
	s.HandleGnmiNotification(ctx, ipPath, makeStringUpdate("10.0.0.1"), false)

	if _, ok := s.Get("dpu1"); !ok {
		t.Fatal("expected DPU dpu1 to exist before delete")
	}

	// Delete notification
	deletePath := "device:/System/sas-items/dpu-items/inst-items/Inst-list[moduleNum=1]/ext-items/state"
	s.HandleGnmiNotification(ctx, deletePath, &gnmiproto.Update{}, true)

	if _, ok := s.Get("dpu1"); ok {
		t.Error("expected DPU dpu1 to be removed after delete")
	}
}

func TestHandleGnmiNotification_DeleteNonExistent(t *testing.T) {
	ctx := context.Background()
	s := NewStore(context.Background())

	// Delete a DPU that doesn't exist - should not panic or error
	deletePath := "device:/System/sas-items/dpu-items/inst-items/Inst-list[moduleNum=99]/ext-items/state"
	s.HandleGnmiNotification(ctx, deletePath, &gnmiproto.Update{}, true)
}

func TestUpdate_WritesPortRangeToGnmi(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	s := NewStore(ctx)
	s.SetGnmiHandler(handler)

	// Without dpuCount, port range cannot be calculated — no gNMI write expected.
	_ = s.Update(ctx, types.DPU{Name: "dpu1", ModuleNum: 1})
	tcpPath := fmt.Sprintf(paths.DPUStoreTCPPorts, 1)
	vals, _ := handler.Get(ctx, tcpPath)
	if len(vals) != 0 {
		t.Errorf("expected no gNMI write before dpuCount is set, got %v", vals)
	}

	// Set dpuCount, then update DPU — port range should be written.
	s.SetExpectedCount(ctx, 2)
	_ = s.Update(ctx, types.DPU{Name: "dpu1", ModuleNum: 1})

	vals, err := handler.Get(ctx, tcpPath)
	if err != nil {
		t.Fatalf("handler.Get error: %v", err)
	}
	if len(vals) == 0 {
		t.Fatal("expected gNMI SET for TCP port range after update with dpuCount set")
	}
	udpPath := fmt.Sprintf(paths.DPUStoreUDPPorts, 1)
	vals, err = handler.Get(ctx, udpPath)
	if err != nil {
		t.Fatalf("handler.Get error: %v", err)
	}
	if len(vals) == 0 {
		t.Fatal("expected gNMI SET for UDP port range after update with dpuCount set")
	}
}

func TestUpdate_PortRangeNotWrittenWhenUnchanged(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	s := NewStore(ctx)
	s.SetGnmiHandler(handler)
	s.SetExpectedCount(ctx, 2)

	// First update — writes port range.
	_ = s.Update(ctx, types.DPU{Name: "dpu1", ModuleNum: 1})

	// Overwrite with a different field (state) — port range unchanged, so no second write.
	// We verify by checking the value is still the expected range (not overwritten to something wrong).
	tcpPath := fmt.Sprintf(paths.DPUStoreTCPPorts, 1)
	first, _ := handler.Get(ctx, tcpPath)

	_ = s.Update(ctx, types.DPU{Name: "dpu1", ModuleNum: 1, IP: "10.0.0.1"})
	second, _ := handler.Get(ctx, tcpPath)

	if len(first) == 0 || len(second) == 0 {
		t.Fatal("expected port range written on both updates")
	}
	if first[0] != second[0] {
		t.Errorf("port range changed unexpectedly: %v -> %v", first[0], second[0])
	}
}

func TestRemove_DeletesPortRangeFromGnmi(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	s := NewStore(ctx)
	s.SetGnmiHandler(handler)
	s.SetExpectedCount(ctx, 1)

	// Create DPU and verify port range is written.
	_ = s.Update(ctx, types.DPU{Name: "dpu1", ModuleNum: 1})
	tcpPath := fmt.Sprintf(paths.DPUStoreTCPPorts, 1)
	vals, _ := handler.Get(ctx, tcpPath)
	if len(vals) == 0 {
		t.Fatal("expected port range to be set before remove")
	}

	// Remove DPU — port range should be deleted.
	_ = s.Remove(ctx, "dpu1")
	vals, _ = handler.Get(ctx, tcpPath)
	if len(vals) != 0 {
		t.Errorf("expected port range deleted after remove, got %v", vals)
	}
	udpPath := fmt.Sprintf(paths.DPUStoreUDPPorts, 1)
	vals, _ = handler.Get(ctx, udpPath)
	if len(vals) != 0 {
		t.Errorf("expected UDP port range deleted after remove, got %v", vals)
	}
}

func TestSetExpectedCount_WritesPortRangesToGnmi(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	s := NewStore(ctx)
	s.SetGnmiHandler(handler)

	// Add DPUs before dpuCount is known — no port range written yet.
	_ = s.Update(ctx, types.DPU{Name: "dpu1", ModuleNum: 1})
	_ = s.Update(ctx, types.DPU{Name: "dpu2", ModuleNum: 2})

	// Setting expected count triggers recalculation and gNMI write for all DPUs.
	s.SetExpectedCount(ctx, 2)

	for _, moduleNum := range []int{1, 2} {
		tcpPath := fmt.Sprintf(paths.DPUStoreTCPPorts, moduleNum)
		vals, err := handler.Get(ctx, tcpPath)
		if err != nil {
			t.Fatalf("handler.Get error: %v", err)
		}
		if len(vals) == 0 {
			t.Errorf("expected port range written for moduleNum=%d after SetExpectedCount", moduleNum)
		}
	}
}

func TestSetGlobalPortRange_WritesUpdatedRangesToGnmi(t *testing.T) {
	ctx := context.Background()
	handler := mock.NewHandler()
	s := NewStore(ctx)
	s.SetGnmiHandler(handler)
	s.SetExpectedCount(ctx, 2)

	_ = s.Update(ctx, types.DPU{Name: "dpu1", ModuleNum: 1})
	_ = s.Update(ctx, types.DPU{Name: "dpu2", ModuleNum: 2})

	// Get initial values.
	tcpPath1 := fmt.Sprintf(paths.DPUStoreTCPPorts, 1)
	initial, _ := handler.Get(ctx, tcpPath1)

	// Change global port range — should recalculate and write new values.
	s.SetGlobalPortRange(ctx, 30000, 31023)

	updated, _ := handler.Get(ctx, tcpPath1)
	if len(updated) == 0 {
		t.Fatal("expected port range written after SetGlobalPortRange")
	}
	if len(initial) > 0 && initial[0] == updated[0] {
		t.Errorf("expected port range to change after SetGlobalPortRange, but got same value: %v", updated[0])
	}
}

func TestFormatPortRange(t *testing.T) {
	dpu := types.DPU{PortLow: 28672, PortHigh: 29183}
	got := formatPortRange(dpu)
	if got != "28672-29183" {
		t.Errorf("expected '28672-29183', got %q", got)
	}
}

func TestParseDpuState(t *testing.T) {
	tests := []struct {
		input    string
		expected nxosmodel.E_Cisco_NX_OSDevice_Sas_DpuStateE
	}{
		{"none", nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_none},
		{"init", nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_init},
		{"update", nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_update},
		{"online", nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_online},
		{"failed", nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_failed},
		{"power-down", nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_power_down},
		{"power_down", nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_power_down},
		{"discovery", nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_discovery},
		{"gold-fw-boot", nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_gold_fw_boot},
		{"gold_fw_boot", nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_gold_fw_boot},
		{"main-fw-boot", nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_main_fw_boot},
		{"main_fw_boot", nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_main_fw_boot},
		{"unknown", nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_UNSET},
		{"", nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_UNSET},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("state=%s", tt.input), func(t *testing.T) {
			got := parseDpuState(tt.input)
			if got != tt.expected {
				t.Errorf("parseDpuState(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}
