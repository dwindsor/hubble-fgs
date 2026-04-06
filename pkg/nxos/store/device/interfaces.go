// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package device

import (
	"context"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"
)

// Reader provides read-only access to device data.
type Reader interface {
	Token() string
	ProxyServer() string
	ProxyPort() uint32
	ProxyAddress() string
	ConnectionStatus() string
	AdmissionStatus() string
	SerialNumber() string
	Model() string
	SoftwareVersion() string
	ServiceIP() string
	ControllerEndpoint() string
	ControllerPort() uint32
	ControllerVersion() string
	CPAVersion() string
	SystemState() int
	RejectReason() string
	SkipReg() bool
	SkipRegReason() string
	IsHeadlessMode() bool
	IsInService() bool
	InServiceState() string
	// IsSkipReg returns (skipReg bool, reload bool, reason string).
	// The reload flag uses read-once semantics and is cleared on each call.
	// Use IsHeadlessMode() separately for headless mode status.
	IsSkipReg() (bool, bool, string)
	LbMode() string
	// HSAPortLow returns the low end of the configured HSA port range.
	HSAPortLow() uint16
}

// Watcher allows subscribing to device changes.
type Watcher interface {
	Watch(callback func(event Event)) (unsubscribe func())
}

// Store provides full access to device data.
type Store interface {
	Reader
	Watcher

	SetToken(ctx context.Context, token string) (bool, error)
	SetProxyServer(ctx context.Context, server string)
	SetProxyPort(ctx context.Context, port uint32)
	SetConnectionStatus(ctx context.Context, status string, reason string)
	SetAdmissionStatus(ctx context.Context, status string, reason string)
	SetSerialNumber(ctx context.Context, serial string)
	SetModel(ctx context.Context, model string)
	SetSoftwareVersion(ctx context.Context, version string)
	SetServiceIP(ctx context.Context, ip string)
	SetHeadlessMode(ctx context.Context, headless bool)
	SetInService(ctx context.Context, inService string)
	SetSkipReg(ctx context.Context, skip bool, reason string)
	SetLbMode(ctx context.Context, mode string)
	ResetRegistration(ctx context.Context)
	ResetConnection(ctx context.Context)

	SetControllerEndpoint(ctx context.Context, endpoint string)
	SetControllerPort(ctx context.Context, port uint32)
	SetControllerVersion(ctx context.Context, version string)
	SetSystemState(ctx context.Context, systemState int)
	// UpdateSystemState atomically writes the non-ConnPending bits of systemState,
	// preserving the ConnPending bit which is owned by SetConnectionStatus.
	UpdateSystemState(ctx context.Context, bits int)
	DeleteSystemState(ctx context.Context) error

	// ReservePort returns the port for the given service type within the HSA range.
	ReservePort(serviceType ServicePortType) (uint16, error)

	// SetGnmiHandler sets the gNMI handler for state synchronization.
	// This is called after the gNMI handler is initialized.
	SetGnmiHandler(handler gnmi.GnmiHandler)

	// HandleGnmiNotification processes a gNMI notification for device state.
	// It is called by the notification dispatcher when a device-related update is received.
	HandleGnmiNotification(ctx context.Context, path string, update *gnmiproto.Update, isDelete bool)

	// SetPreInServiceHook registers a hook that runs BEFORE the in-service state changes.
	// Used to program redirects before the device transitions to in-service.
	SetPreInServiceHook(hook func(ctx context.Context, newState string))

	// SetPostInServiceHook registers a hook that runs AFTER the in-service state changes.
	// Used to remove redirects after the device transitions to out-of-service.
	SetPostInServiceHook(hook func(ctx context.Context, oldState string))
}
