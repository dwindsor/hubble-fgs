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

import (
	"strings"
	"testing"
)

func TestNewReasonString_Short(t *testing.T) {
	r := NewReasonString("short reason")
	if r.String() != "short reason" {
		t.Errorf("expected 'short reason', got %q", r.String())
	}
}

func TestNewReasonString_ExactlyMaxLength(t *testing.T) {
	s := strings.Repeat("a", MaxReasonLength)
	r := NewReasonString(s)
	if len(r.String()) != MaxReasonLength {
		t.Errorf("expected length %d, got %d", MaxReasonLength, len(r.String()))
	}
	if r.String() != s {
		t.Error("expected string to be unchanged at exact max length")
	}
}

func TestNewReasonString_TruncatesOverMax(t *testing.T) {
	s := strings.Repeat("b", MaxReasonLength+20)
	r := NewReasonString(s)
	if len(r.String()) != MaxReasonLength {
		t.Errorf("expected length %d, got %d", MaxReasonLength, len(r.String()))
	}
}

func TestNewReasonString_Empty(t *testing.T) {
	r := NewReasonString("")
	if r.String() != "" {
		t.Errorf("expected empty string, got %q", r.String())
	}
}

func TestMaxReasonLength_Is80(t *testing.T) {
	if MaxReasonLength != 80 {
		t.Errorf("expected MaxReasonLength to be 80, got %d", MaxReasonLength)
	}
}

func TestHACritPeerVrfGid_Constant(t *testing.T) {
	if HACritPeerVrfGid != "peer_vrf_gid" {
		t.Errorf("expected HACritPeerVrfGid=%q, got %q", "peer_vrf_gid", HACritPeerVrfGid)
	}
}

func TestHACritPeerVrfGid_InCriteriaMap(t *testing.T) {
	criteria := HACriteria{
		HACritPeerVrfGid: false,
	}
	if criteria.AllOk() {
		t.Error("expected AllOk to return false when HACritPeerVrfGid is false")
	}

	criteria[HACritPeerVrfGid] = true
	if !criteria.AllOk() {
		t.Error("expected AllOk to return true when HACritPeerVrfGid is true")
	}
}

func TestReasonString_String(t *testing.T) {
	r := ReasonString("test")
	if r.String() != "test" {
		t.Errorf("expected 'test', got %q", r.String())
	}
}

func TestHALocalState_ReasonFieldsCopied(t *testing.T) {
	local := HALocalState{
		HaState:        HAStateReady,
		HaStateReason:  NewReasonString("test ha reason"),
		SvcState:       SvcStateSuccess,
		SvcStateReason: NewReasonString("test svc reason"),
		Criteria:       HACriteria{HACritDpuHealth: true},
	}
	cp := local.Copy()
	if cp.HaStateReason != local.HaStateReason {
		t.Errorf("expected HaStateReason %q, got %q", local.HaStateReason, cp.HaStateReason)
	}
	if cp.SvcStateReason != local.SvcStateReason {
		t.Errorf("expected SvcStateReason %q, got %q", local.SvcStateReason, cp.SvcStateReason)
	}
}

func TestHAPeerState_ReasonFieldCopied(t *testing.T) {
	peer := HAPeerState{
		IP:                "10.0.0.1",
		SvcState:          SvcStateFailure,
		SvcStateReason:    NewReasonString("peer service failure"),
		MemberCriteria:    HACriteria{},
		AdjacencyCriteria: HACriteria{},
	}
	cp := peer.Copy()
	if cp.SvcStateReason != peer.SvcStateReason {
		t.Errorf("expected SvcStateReason %q, got %q", peer.SvcStateReason, cp.SvcStateReason)
	}
}
