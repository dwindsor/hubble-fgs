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

// EventType represents the type of HA event.
type EventType string

const (
	EventAdminStateChanged   EventType = "admin_state_changed"
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
)

// Event represents an HA store event.
type Event struct {
	Type      EventType
	PeerIP    string
	Criterion string
	Value     bool
}
