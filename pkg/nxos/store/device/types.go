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

import nxosmodel "github.com/isovalent/hubble-fgs/pkg/nxosmodel"

// CommonState string values - derived directly from E_Cisco_NX_OSDevice_Sas_CommonStateE YANG enum.
// Using .String() ensures exact compliance with NX-OS expected values.
var (
	CommonStateUnknown = nxosmodel.Cisco_NX_OSDevice_Sas_CommonStateE_unknown.String()
	CommonStateSuccess = nxosmodel.Cisco_NX_OSDevice_Sas_CommonStateE_success.String()
	CommonStateFailure = nxosmodel.Cisco_NX_OSDevice_Sas_CommonStateE_failure.String()
)

// EventType represents the type of device event.
type EventType string

const (
	EventConnectionChanged EventType = "connection_changed"
	EventAdmissionChanged  EventType = "admission_changed"
	EventTokenChanged      EventType = "token_changed"
	EventInServiceChanged  EventType = "in_service_changed"
	EventLbModeChanged     EventType = "lb_mode_changed"
)

// Event represents a device store event.
type Event struct {
	Type   EventType
	Status string
	Reason string
}
