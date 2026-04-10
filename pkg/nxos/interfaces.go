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
	"os"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/device"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/dpu"
	hastore "github.com/isovalent/hubble-fgs/pkg/nxos/store/ha"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/vlan"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/vrf"
)

// Manager is the main entry point for NXOS operations.
// It provides a clean, testable interface for managing NXOS state.
type Manager interface {
	// Lifecycle
	Setup(ctx context.Context) error
	Close(ctx context.Context) error

	// Phase management
	Phase() Phase

	// Domain store accessors (callers access stores directly)
	DeviceStore() device.Store
	HAStore() hastore.Store
	VRFStore() vrf.Store
	VLANStore() vlan.Store
	DPUStore() dpu.Store

	// Domain stores (read-only access for external code)
	DeviceWatcher() device.Watcher

	// Configuration
	IsInService(ctx context.Context) bool
	IsLbModePinning(ctx context.Context) bool

	// Controller management
	GetToken() string
	SetToken(ctx context.Context, token string) (bool, error)
	GetControllerConnectionStatus() string
	GetSerialNum(ctx context.Context) string
	// Registration status
	SetRegFail(ctx context.Context, reason string)
	SetRegOk(ctx context.Context, reason string)
	SetConnFail(ctx context.Context, reason string)
	SetConnOk(ctx context.Context, reason string)
	ResetReg(ctx context.Context)
	ResetConn(ctx context.Context)
	// HA management
	IsPeerOk(ctx context.Context, peer string) bool
	NotifyPolicyCheck(ctx context.Context, check bool)

	// Upgrade management
	GetExitCodeForSignal(sig os.Signal, inUpgrade bool) int

	// GracefulRestart triggers a graceful agent restart. If cleanup is true,
	// Close() is called first to clean up switch state before restarting.
	GracefulRestart(ctx context.Context, cleanup bool)

	// CLI commands
	ShowStatus(ctx context.Context) string
	ShowHa(ctx context.Context) string
	ShowAdj(ctx context.Context) string
	ShowMbr(ctx context.Context) string
	DelTokens(ctx context.Context) string
	// Status
	Status() Status

	// DPU status updates
	DpuInSync(ctx context.Context, inSync bool)
	DpuHealth(ctx context.Context, healthy bool, count int)

	// GnmiHandler returns the underlying gNMI handler (may be nil).
	// Callers may type-assert to *mock.Handler to access mock-specific methods.
	GnmiHandler() gnmi.GnmiHandler
}
