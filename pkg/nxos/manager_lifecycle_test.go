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
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
)

func TestHandleServiceLifecycleNotification_IgnoresUpdates(t *testing.T) {
	ctx := context.Background()
	m := NewManager(ctx, WithMockGnmiHandler(nil), WithSkipDPU(true)).(*manager)

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
	ctx := context.Background()
	m := NewManager(ctx, WithMockGnmiHandler(nil), WithSkipDPU(true)).(*manager)

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
