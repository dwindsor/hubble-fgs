// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package ha

import nxosmodel "github.com/isovalent/hubble-fgs/pkg/nxosmodel"

// PeerIpCfgState string values - derived directly from E_Cisco_NX_OSDevice_Sas_PeerIpCfgStateE YANG enum.
// Using .String() ensures exact compliance with NX-OS expected values.
var (
	PeerIpCfgStateNotStarted = nxosmodel.Cisco_NX_OSDevice_Sas_PeerIpCfgStateE_not_started.String()
	PeerIpCfgStateSuccess    = nxosmodel.Cisco_NX_OSDevice_Sas_PeerIpCfgStateE_success.String()
	PeerIpCfgStateFailed     = nxosmodel.Cisco_NX_OSDevice_Sas_PeerIpCfgStateE_failed.String()
)

// AdminState string values - derived from E_Cisco_NX_OSDevice_Sas_SvcHaAdminStateE YANG enum.
var (
	AdminStateEnabled  = nxosmodel.Cisco_NX_OSDevice_Sas_SvcHaAdminStateE_enabled.String()
	AdminStateDisabled = nxosmodel.Cisco_NX_OSDevice_Sas_SvcHaAdminStateE_disabled.String()
)

// SwitchState string values - derived from E_Cisco_NX_OSDevice_SasNxHaOperStateE YANG enum.
var (
	SwitchStateHaReady          = nxosmodel.Cisco_NX_OSDevice_SasNxHaOperStateE_ha_ready.String()
	SwitchStateHaNotInitialized = nxosmodel.Cisco_NX_OSDevice_SasNxHaOperStateE_ha_not_initialized.String()
)

// EventType represents the type of HA event.
type EventType string

const (
	EventAdminStateChanged   EventType = "admin_state_changed"
	EventSwitchStateChanged  EventType = "switch_state_changed"
	EventPeerAdded           EventType = "peer_added"
	EventPeerRemoved         EventType = "peer_removed"
	EventMemberUpdated       EventType = "member_updated"
	EventCriterionSet        EventType = "criterion_set"
	EventCriterionChanged    EventType = "criterion_changed"
	EventLeaderChanged       EventType = "leader_changed"
	EventPeerCriteriaUpdated EventType = "peer_criteria_updated"
	EventPartnerChanged      EventType = "partner_changed"
	EventDerivedStateChanged EventType = "derived_state_changed"
	EventLocalStateChanged   EventType = "local_state_changed"
	EventHaIPChanged         EventType = "ha_ip_changed"
)

// Event represents an HA store event.
type Event struct {
	Type      EventType
	PeerIP    string
	Criterion string
	Value     bool
}
