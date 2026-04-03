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

	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

// Reader provides read-only access to DPU data.
type Reader interface {
	Get(name string) (types.DPU, bool)
	List() []types.DPU
	Count() int
	DpuCount() int
	IsInventoryComplete() bool
	AreAllOnline() bool
	// IsReady returns true when inventory is complete AND all expected DPUs are discovered.
	IsReady() bool
	// HealthyCount returns the count of healthy DPUs.
	HealthyCount() int
	// IsHealthy returns whether the DPU fleet is considered healthy.
	IsHealthy() bool
	// IsInSync returns whether the DPU fleet is in sync.
	IsInSync() bool
	// InSyncCount returns the count of DPUs that are in sync.
	InSyncCount() int
	// GetGlobalPortRange returns the configured fleet-wide port range (low, high).
	GetGlobalPortRange() (uint16, uint16)
	// IsSkipDPU returns true if the store is operating in DPUless mode.
	IsSkipDPU() bool
}

// Watcher allows subscribing to DPU changes.
type Watcher interface {
	Watch(callback func(event Event)) (unsubscribe func())
}

// Store provides full access to DPU data.
type Store interface {
	Reader
	Watcher

	Update(ctx context.Context, dpu types.DPU) error
	Remove(ctx context.Context, name string) error
	SetExpectedCount(ctx context.Context, count int)
	SetInventoryComplete(complete bool)
	SetInSync(inSync bool)
	SetHealth(healthy bool, count int)
	// SetInSyncCount tracks the count of DPUs that are in sync.
	SetInSyncCount(count int)
	// SetGlobalPortRange sets the fleet-wide port range and recalculates all per-DPU ranges.
	SetGlobalPortRange(ctx context.Context, low, high uint16)

	// SetDpuPortRange writes TCP/UDP control plane port ranges for a DPU (gnmi.md SET #6).
	SetDpuPortRange(ctx context.Context, moduleNum int, tcpRange, udpRange string) error

	// DeleteDpuPortRange deletes control plane port ranges for a DPU (gnmi.md DELETE #7).
	DeleteDpuPortRange(ctx context.Context, moduleNum int) error

	// WaitForInventory blocks until inventory is complete AND all expected DPUs are discovered,
	// or until the context is cancelled.
	WaitForInventory(ctx context.Context) error

	// HandleGnmiNotification processes a gNMI notification for DPU state.
	// It is called by the notification dispatcher when a DPU-related update is received.
	HandleGnmiNotification(ctx context.Context, path string, update *gnmiproto.Update, isDelete bool)

	// SetGnmiHandler sets the gNMI handler for state synchronization.
	SetGnmiHandler(handler gnmi.GnmiHandler)
}
