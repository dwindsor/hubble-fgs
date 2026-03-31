// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package storage

import (
	"context"

	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

// Storage defines the interface for persisting domain store data.
// Implementations can use filesystem, memory, or other backends.
// All domain stores use this single interface for persistence.
type Storage interface {
	// VRF operations
	LoadVRFs(ctx context.Context) (map[string]types.VRF, error)
	SaveVRFs(ctx context.Context, vrfs map[string]types.VRF) error

	// VLAN operations
	LoadVLANs(ctx context.Context) (map[string]types.VLAN, error)
	SaveVLANs(ctx context.Context, vlans map[string]types.VLAN) error

	// Device operations
	LoadDevice(ctx context.Context) (*DeviceState, error)
	SaveDevice(ctx context.Context, state *DeviceState) error

	// HA operations
	LoadHA(ctx context.Context) (*HAState, error)
	SaveHA(ctx context.Context, state *HAState) error

	// DPU operations
	LoadDPUs(ctx context.Context) (map[string]types.DPU, error)
	SaveDPUs(ctx context.Context, dpus map[string]types.DPU) error

	// EnsureReady prepares the storage backend (e.g., creates directories).
	EnsureReady(ctx context.Context) error

	// Clear removes all persisted data.
	Clear(ctx context.Context) error

	// FlushAll synchronously persists all data. Used during shutdown to ensure
	// all pending writes complete before the process exits.
	FlushAll(ctx context.Context) error
}

// DeviceState represents the persisted device state.
// Only configuration values that must survive a restart are stored here.
// Runtime values (connection/admission status, serial number, model, software
// version, headless mode, in-service state) are intentionally excluded —
// they are either re-derived from gNMI on startup or overridden by config
// files and therefore have no value being persisted.
// Token is managed separately by AgentTokenProvider (/iox_data/k8sauth_token)
// and must NOT be duplicated here to avoid a second plaintext copy on disk.
type DeviceState struct {
	ProxyServer   string `json:"proxy_server,omitempty"`
	ProxyPort     uint32 `json:"proxy_port,omitempty"`
	ServiceIP     string `json:"service_ip,omitempty"`
	SkipReg       bool   `json:"skip_reg,omitempty"`
	SkipRegReason string `json:"skip_reg_reason,omitempty"`
	LbMode        string `json:"lb_mode,omitempty"`
}

// HAState represents the persisted HA state.
// Only configuration values and peer IPs are stored here; all runtime state
// (local criteria, adjacency status, peer criteria, member info, DPU statuses)
// is rebuilt from scratch via gNMI and the HA adjacency protocol on startup.
// Persisting stale runtime state would be actively harmful.
type HAState struct {
	Enabled     string   `json:"admin_state,omitempty"`
	SwitchState string   `json:"oper_state,omitempty"`
	HaIP        string   `json:"local_ip,omitempty"`
	HaPort      uint16   `json:"ha_port,omitempty"`
	PeerIPs     []string `json:"peer_ips,omitempty"`
}

// ErrNotFound is returned when persisted data does not exist.
// This is not an error condition for initial startup.
type ErrNotFound struct {
	Key string
}

func (e *ErrNotFound) Error() string {
	return "storage: key not found: " + e.Key
}

// IsNotFound returns true if the error indicates data was not found.
func IsNotFound(err error) bool {
	_, ok := err.(*ErrNotFound)
	return ok
}
