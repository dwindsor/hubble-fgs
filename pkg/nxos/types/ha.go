// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package types

// Local HA States
const (
	HAStateNoHa       = "no-ha"
	HAStateNotReady   = "ha-not-ready"
	HAStateReady      = "ha-ready"
	HAStateSwitchover = "ha-switchover"
	HAStateTakeover   = "ha-takeover"
)

// HA service states
const (
	SvcStateUnknown = "unknown"
	SvcStateFailure = "not-ready"
	SvcStateSuccess = "ready"
)

// MaxReasonLength is the maximum length of a reason string.
const MaxReasonLength = 80

// ReasonString is a string type that enforces a maximum length of 80 characters.
type ReasonString string

// NewReasonString creates a ReasonString, truncating to MaxReasonLength if necessary.
func NewReasonString(s string) ReasonString {
	if len(s) > MaxReasonLength {
		return ReasonString(s[:MaxReasonLength])
	}
	return ReasonString(s)
}

// String returns the string representation of the ReasonString.
func (r ReasonString) String() string {
	return string(r)
}

// HACriterion is a unified criteria type used by both local and peer info.
type HACriterion string

const (
	// Local criteria
	HACritDpuHealth HACriterion = "dpu_healthy"
	HACritDpuInSync HACriterion = "dpu_insync"
	HACritSvcRedir  HACriterion = "service_redir"

	// Peer membership criteria
	HACritPeerCompatible HACriterion = "peer_compatible"

	// Peer adjacency criteria
	HACritPeerIpConfig     HACriterion = "peer_ip_config"
	HACritPeerServiceRedir HACriterion = "peer_service_redir"
	HACritPeerPolicy       HACriterion = "peer_policy"
	HACritPeerVrfGid       HACriterion = "peer_vrf_gid"
	HACritPeerDPUKeepalive HACriterion = "peer_dpu_keepalive"
	HACritPeerDPUBulkSync  HACriterion = "peer_dpu_bulk_sync"

	// Debug criteria
	HACritDebug HACriterion = "debug_override"
)

// DPUHAStatus tracks per-DPU HA keepalive and bulk-sync state.
type DPUHAStatus struct {
	KeepaliveUp   bool
	BulkSyncLocal bool
	BulkSyncPeer  bool
}

// HACriteria is a map of criteria name to value, used by both HALocalState and HAPeerState.
type HACriteria map[HACriterion]bool

// AllOk returns true if all criteria in the map are true.
func (c HACriteria) AllOk() bool {
	for _, v := range c {
		if !v {
			return false
		}
	}
	return true
}

// Copy returns a deep copy of the criteria map.
func (c HACriteria) Copy() HACriteria {
	if c == nil {
		return nil
	}
	cp := make(HACriteria, len(c))
	for k, v := range c {
		cp[k] = v
	}
	return cp
}

// HALocalState groups all local HA state into a single sub-object.
type HALocalState struct {
	Leader           bool       // leader election result (lowest IP wins)
	Criteria         HACriteria // local criteria
	CriteriaMet      bool       // all criteria true
	CriteriaMetEpoch int64      // when CriteriaMet last changed
	PolicyCheck      bool       // whether policy revision is being used as criteria
	PolicyRev        string     // current policy revision
	AdjacencyReached bool       // has adjacency been reached between peers at least once

	// Anti-flapping hold-down state
	CriteriaRecoveryPending bool
	CriteriaRecoveryEpoch   int64
	CriteriaFlapCount       int

	// Derived states (computed by state machine)
	HaState        string
	HaStateReason  ReasonString // reason for current HaState
	HaStateEpoch   int64        // when HaState last changed
	SvcState       string
	SvcStateReason ReasonString // reason for current SvcState
	SvcStateEpoch  int64        // when SvcState last changed
}

// Copy returns a deep copy that is safe to use without holding locks.
func (l HALocalState) Copy() HALocalState {
	cp := l
	cp.Criteria = l.Criteria.Copy()
	return cp
}

// HAPeerState groups all per-peer HA state into a single sub-object.
type HAPeerState struct {
	IP string

	// Membership criteria
	MemberCriteria         HACriteria
	MemberCriteriaMet      bool
	MemberCriteriaMetEpoch int64
	MemberInfo             *HAPeerMember // full member info

	// Adjacency criteria
	AdjacencyCriteria         HACriteria
	AdjacencyCriteriaMet      bool
	AdjacencyCriteriaMetEpoch int64
	AdjacencyConnected        bool  // successful keepalive
	AdjacencyConnectedEpoch   int64 // last successful keepalive

	// Per-DPU HA status (for CLI visibility)
	DPUStatuses map[string]DPUHAStatus

	// Derived states (computed by state machine)
	SvcState       string
	SvcStateReason ReasonString // reason for current SvcState
	SvcStateEpoch  int64        // when SvcState last changed
}

// Copy returns a deep copy that is safe to use without holding locks.
func (p HAPeerState) Copy() HAPeerState {
	cp := p
	cp.MemberCriteria = p.MemberCriteria.Copy()
	cp.AdjacencyCriteria = p.AdjacencyCriteria.Copy()
	if p.MemberInfo != nil {
		memberCopy := *p.MemberInfo
		cp.MemberInfo = &memberCopy
	}
	if p.DPUStatuses != nil {
		cp.DPUStatuses = make(map[string]DPUHAStatus, len(p.DPUStatuses))
		for k, v := range p.DPUStatuses {
			cp.DPUStatuses[k] = v
		}
	}
	return cp
}

// HAPeerMember contains detailed information about an HA member.
type HAPeerMember struct {
	SerialNum   string
	Model       string
	SWVersion   string
	CPAVersion  string
	DPUs        []DPUVersion
	HaState     string
	Service     string
	LbMode      string
	PolicyRev   string
	PolicyCheck bool
}
