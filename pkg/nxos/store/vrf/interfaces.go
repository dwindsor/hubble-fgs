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

	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

// Reader provides read-only access to VRF data.
type Reader interface {
	Get(name string) (types.VRF, bool)
	List() []types.VRF
	ListActive() []types.VRF
	GetGID(name string) (uint16, bool)
	GetPinning(name string) (uint16, bool)
	// NextGID returns the next sequential GID that would be allocated (for diagnostics).
	NextGID() uint16
}

// Watcher allows subscribing to VRF changes.
type Watcher interface {
	Watch(callback func(event Event)) (unsubscribe func())
}

// Store provides full access to VRF data.
type Store interface {
	Reader
	Watcher

	SetGlobal(ctx context.Context, name string, isGlobal bool) error
	SetService(ctx context.Context, name string, isService bool) error
	SetAffinity(ctx context.Context, name string, affinity uint16) error

	// HandleGnmiNotification processes a gNMI notification for VRF state.
	// It is called by the notification dispatcher when a VRF-related update is received.
	HandleGnmiNotification(ctx context.Context, path string, update *gnmiproto.Update, isDelete bool)

	// SetGnmiHandler sets the gNMI handler for state synchronization.
	// When set, service redirects are automatically programmed when VRFs change.
	SetGnmiHandler(handler gnmi.GnmiHandler)

	// RestoreGIDsFromGnmi reads existing service redirect configuration from gNMI
	// and populates GIDs for VRFs that should have them. This should be called
	// after SetGnmiHandler to restore GID state from the switch.
	RestoreGIDsFromGnmi(ctx context.Context) error

	// SetGID sets the desired GID (Preset) for a VRF and reconciles all active VRFs
	// whose current GID conflicts with the new preset. If the VRF does not exist yet
	// it is created as a skeleton so the preset is honored on first activation.
	SetGID(ctx context.Context, name string, gid uint16) error

	// SetGIDs atomically sets desired GIDs (Presets) for multiple VRFs and resolves
	// collisions with other VRFs whose current GID is claimed by one of the new presets.
	// Used during HA reconciliation so the non-leader adopts the leader's GIDs.
	SetGIDs(ctx context.Context, changes map[string]uint16) error

	// SetDPUCount updates the number of DPUs for hash-based dynamic pinning.
	// Called after DPU inventory completes.
	SetDPUCount(count uint16)

	// SetInService controls the in-service gate for reactive redirect programming.
	// When false, programRedirects no-ops for newly activated VRFs/VLANs.
	SetInService(inService bool)

	// ProgramAllRedirects programs redirects for all active VRFs.
	// Used during in-service transition and startup reconciliation.
	ProgramAllRedirects(ctx context.Context) int

	// CleanupAllRedirects removes redirects for all active VRFs.
	// Used during out-of-service transition.
	CleanupAllRedirects(ctx context.Context)

	// ReconcileRedirects reprograms redirects for all active VRFs.
	// Called during startup after shared infrastructure is in place.
	ReconcileRedirects(ctx context.Context)

	// CleanupAllFwPolicyState deletes fwPolicyState for all active VRFs.
	// Called during Close() to clean up stale state on the switch.
	CleanupAllFwPolicyState(ctx context.Context)

	// SetPeerGIDs stores the peer's GID allocations for HA-aware allocation.
	// Non-leader nodes prefer peer GIDs when allocating for new VRFs.
	SetPeerGIDs(peerGIDs map[string]uint16)

	// ClearPeerGIDs removes peer GID information (e.g., on peer disconnect).
	ClearPeerGIDs()
}
