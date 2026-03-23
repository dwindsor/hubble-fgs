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

	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

// Reader provides read-only access to VLAN data.
type Reader interface {
	Get(name string) (types.VLAN, bool)
	List() []types.VLAN
	ListActive() []types.VLAN
	GetID(name string) (uint16, bool)
	GetPinning(name string) (uint16, bool)
}

// Watcher allows subscribing to VLAN changes.
type Watcher interface {
	Watch(callback func(event Event)) (unsubscribe func())
}

// Store provides full access to VLAN data.
type Store interface {
	Reader
	Watcher

	SetGlobal(ctx context.Context, name string, isGlobal bool) error
	SetService(ctx context.Context, name string, isService bool) error
	SetAffinity(ctx context.Context, name string, affinity uint16) error
	SetPinning(ctx context.Context, name string, dpuPinned uint16) error

	// GetAll returns all VLANs (for external persistence needs).
	GetAll() map[string]types.VLAN

	// HandleGnmiNotification processes a gNMI notification for VLAN state.
	// It is called by the notification dispatcher when a VLAN-related update is received.
	HandleGnmiNotification(ctx context.Context, path string, update *gnmiproto.Update, isDelete bool)

	// SetGnmiHandler sets the gNMI handler for state synchronization.
	// When set, service redirects are automatically programmed when VLANs change.
	SetGnmiHandler(handler gnmi.GnmiHandler)

	// ProgramBDServiceEndpoints creates per-DPU service endpoints for BD
	// redirect. Called once during setup after DPU inventory completes.
	ProgramBDServiceEndpoints(ctx context.Context, dpuCount uint16) error

	// ProgramBDPolicyMaps creates per-DPU policy maps for BD redirect.
	// Called once during setup after DPU inventory completes.
	ProgramBDPolicyMaps(ctx context.Context, dpuCount uint16) error

	// SetDPUCount updates the number of DPUs for hash-based dynamic pinning.
	// Called after DPU inventory completes.
	SetDPUCount(count uint16)

	// SetRedirectsReady marks the store as ready to program redirects.
	// Called after shared redirect infrastructure and reconciliation are complete.
	SetRedirectsReady()

	// ReconcileRedirects reprograms redirects for all active VLANs.
	// Called during startup after shared infrastructure is in place.
	ReconcileRedirects(ctx context.Context)

	// CleanupAllFwPolicyState deletes fwPolicyState for all active VLANs.
	// Called during Close() to clean up stale state on the switch.
	CleanupAllFwPolicyState(ctx context.Context)
}
