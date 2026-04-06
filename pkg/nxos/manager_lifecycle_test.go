// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package nxos

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/mock"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/device"
)

func TestHandleServiceLifecycleNotification_IgnoresUpdates(t *testing.T) {
	t.Setenv("NX_AGENT_IGNORE_MODULES", "1")
	ctx := context.Background()
	m := NewManager(ctx, WithMockGnmiHandler(nil)).(*manager)

	// Should not panic or take action on non-delete notifications
	m.handleServiceLifecycleNotification(ctx, paths.SvcInstancePath, false)
	m.handleServiceLifecycleNotification(ctx, paths.SvcFwPolicyPath, false)
}

func TestHandleServiceLifecycleNotification_IgnoresChildDeletes(t *testing.T) {
	// Child paths of SvcInstancePath should NOT trigger lifecycle handling.
	// PathMatches uses exact matching (after stripping selectors), so these should not match.
	childPaths := []string{
		// operState under fwpolicy-items (handled by device store)
		"System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/operState",
		// connToken (handled by device store)
		"System/sas-items/volatiledata-items/agent-items/SasAgentData-list[svcName=hypershield]/connToken",
		// HA admin state (handled by HA store)
		"System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/adminState",
		// VRF service path (handled by VRF store)
		"System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/ipvrf-items/dom-items/Dom-list[name=default]",
	}

	for _, childPath := range childPaths {
		// PathMatches should NOT match these against SvcInstancePath or SvcFwPolicyPath
		if paths.PathMatches(childPath, paths.SvcInstancePath) {
			t.Errorf("PathMatches should not match child path %q against SvcInstancePath", childPath)
		}
		if paths.PathMatches(childPath, paths.SvcFwPolicyPath) {
			t.Errorf("PathMatches should not match child path %q against SvcFwPolicyPath", childPath)
		}
	}
}

func TestHandleServiceLifecycleNotification_SvcInstancePathMatches(t *testing.T) {
	// Verify that a delete notification for SvcInstance-list[name=hypershield]
	// matches the SvcInstancePath constant via PathMatches.
	notificationPath := "System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]"
	if !paths.PathMatches(notificationPath, paths.SvcInstancePath) {
		t.Error("SvcInstance delete notification should match SvcInstancePath")
	}
}

func TestHandleServiceLifecycleNotification_SvcFwPolicyPathMatches(t *testing.T) {
	// Verify that a delete notification for fwpolicy-items matches SvcFwPolicyPath.
	notificationPath := "System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items"
	if !paths.PathMatches(notificationPath, paths.SvcFwPolicyPath) {
		t.Error("SvcFwPolicy delete notification should match SvcFwPolicyPath")
	}
}

func TestHandleSvcInstanceDelete_IgnoresNonHypershield(t *testing.T) {
	t.Setenv("NX_AGENT_IGNORE_MODULES", "1")
	ctx := context.Background()
	m := NewManager(ctx, WithMockGnmiHandler(nil)).(*manager)

	// Should not panic or restart for a different service instance name.
	// The path check uses strings.Contains(path, "name=hypershield").
	m.handleSvcInstanceDelete(ctx, "System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=other-service]")
}

func TestHandleSvcFwPolicyPathDoesNotMatchOperState(t *testing.T) {
	// The operState path is a child of fwpolicy-items. PathMatches must NOT
	// match it against SvcFwPolicyPath, otherwise the device store's InService
	// delete handler and the manager's fwpolicy delete handler would both fire.
	operStatePath := "System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/operState"
	if paths.PathMatches(operStatePath, paths.SvcFwPolicyPath) {
		t.Error("operState child path should NOT match SvcFwPolicyPath via PathMatches")
	}
}

// TestSetupInServiceHooks_OutOfService_LocalSvcStateBeforeRedirects verifies
// that SetLocalSvcStateToFailure is written to gNMI before the bulk service
// redirect delete when transitioning to out-of-service.
func TestSetupInServiceHooks_OutOfService_LocalSvcStateBeforeRedirects(t *testing.T) {
	t.Setenv("NX_AGENT_IGNORE_MODULES", "1")
	ctx := context.Background()

	dir := t.TempDir()
	handler := mock.NewHandlerBuilder().
		WithPersistPath(filepath.Join(dir, "state.json")).
		Build()

	m := NewManager(ctx, WithMockGnmiHandler(handler)).(*manager)
	m.haStore.SetGnmiHandler(handler)
	m.deviceStore.SetGnmiHandler(handler)
	m.vrfStore.SetGnmiHandler(handler)
	m.vlanStore.SetGnmiHandler(handler)

	m.setupInServiceHooks()

	// Transition: in-service -> out-of-service
	m.deviceStore.SetInService(ctx, device.InServiceStateInService)
	m.deviceStore.SetInService(ctx, "out-of-service")

	txLog := handler.TxLog()

	// Read all set entries — localSvcState must appear before the bulk delete.
	allEntries, err := txLog.ReadEntries("", "", "")
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}

	svcStateIdx := -1
	bulkDeleteIdx := -1
	for i, e := range allEntries {
		if strings.Contains(e.Path, "localSvcState") && e.Action == "set" {
			if svcStateIdx < 0 {
				svcStateIdx = i
			}
		}
		if strings.Contains(e.Path, "serviceredir-items") && e.Action == "delete" {
			if bulkDeleteIdx < 0 {
				bulkDeleteIdx = i
			}
		}
	}

	if svcStateIdx < 0 {
		t.Error("expected SET for localSvcState, none found in TxLog")
	}
	if bulkDeleteIdx < 0 {
		t.Error("expected DELETE for serviceredir-items, none found in TxLog")
	}
	if svcStateIdx >= 0 && bulkDeleteIdx >= 0 && svcStateIdx >= bulkDeleteIdx {
		t.Errorf("localSvcState SET (idx %d) must come before serviceredir-items DELETE (idx %d)",
			svcStateIdx, bulkDeleteIdx)
	}
}

// TestSetupInServiceHooks_OutOfService_BulkDeleteAndSystemState verifies that
// the post-hook uses a single bulk DELETE for serviceredir-items and also
// deletes system state.
func TestSetupInServiceHooks_OutOfService_BulkDeleteAndSystemState(t *testing.T) {
	t.Setenv("NX_AGENT_IGNORE_MODULES", "1")
	ctx := context.Background()

	dir := t.TempDir()
	handler := mock.NewHandlerBuilder().
		WithPersistPath(filepath.Join(dir, "state.json")).
		Build()

	m := NewManager(ctx, WithMockGnmiHandler(handler)).(*manager)
	m.haStore.SetGnmiHandler(handler)
	m.deviceStore.SetGnmiHandler(handler)
	m.vrfStore.SetGnmiHandler(handler)
	m.vlanStore.SetGnmiHandler(handler)

	m.setupInServiceHooks()

	// Transition: in-service -> out-of-service
	m.deviceStore.SetInService(ctx, device.InServiceStateInService)
	m.deviceStore.SetInService(ctx, "out-of-service")

	txLog := handler.TxLog()

	// Verify bulk delete of serviceredir-items was issued.
	bulkDeletes, err := txLog.ReadEntries("", "/System/serviceredir-items", "delete")
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	if len(bulkDeletes) == 0 {
		t.Error("expected DELETE for /System/serviceredir-items, none found")
	}

	// Verify system state was deleted.
	sysStateDeletes, err := txLog.ReadEntries("", paths.DeviceStoreSystemState, "delete")
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	if len(sysStateDeletes) == 0 {
		t.Error("expected DELETE for DeviceStoreSystemState, none found")
	}
}

// TestSetupInServiceHooks_OutOfService_TriggersGracefulRestart verifies that
// the post-hook delegates cleanup to Close() via GracefulRestart, which
// performs the full cleanup sequence (localSvcState, fwPolicyState,
// serviceredir-items, system state) in one code path.
func TestSetupInServiceHooks_OutOfService_TriggersGracefulRestart(t *testing.T) {
	t.Setenv("NX_AGENT_IGNORE_MODULES", "1")
	ctx := context.Background()

	dir := t.TempDir()
	handler := mock.NewHandlerBuilder().
		WithPersistPath(filepath.Join(dir, "state.json")).
		Build()

	m := NewManager(ctx, WithMockGnmiHandler(handler)).(*manager)
	m.haStore.SetGnmiHandler(handler)
	m.deviceStore.SetGnmiHandler(handler)
	m.vrfStore.SetGnmiHandler(handler)
	m.vlanStore.SetGnmiHandler(handler)

	m.setupInServiceHooks()

	// Transition: in-service -> out-of-service
	m.deviceStore.SetInService(ctx, device.InServiceStateInService)
	m.deviceStore.SetInService(ctx, "out-of-service")

	// After GracefulRestart, the manager should be closed.
	if !m.closed.Load() {
		t.Error("expected manager to be closed after out-of-service transition")
	}

	txLog := handler.TxLog()

	// Verify the VLAN fwPolicyState was cleaned up (global redirect state).
	// The VLAN store does an unconditional bulk delete of FwPolicyStateVlan,
	// so this always appears even without active VLANs.
	vlanFwDeletes, err := txLog.ReadEntries("", paths.FwPolicyStateVlan, "delete")
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	if len(vlanFwDeletes) == 0 {
		t.Error("expected DELETE for VLAN fwPolicyState, none found")
	}
}
