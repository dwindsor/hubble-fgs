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
	"testing"
)

func TestPhaseOrder(t *testing.T) {
	phases := []Phase{PhaseDisabled, PhaseDpuPending, PhaseDpuReady, PhaseRedirDone}
	for i := 0; i < len(phases)-1; i++ {
		if phases[i].Order() >= phases[i+1].Order() {
			t.Errorf("Phase %s (order %d) should come before %s (order %d)",
				phases[i], phases[i].Order(), phases[i+1], phases[i+1].Order())
		}
	}
}

func TestPhaseSystemStateValues(t *testing.T) {
	tests := []struct {
		phase    Phase
		expected int
	}{
		{PhaseDisabled, 0x0},
		{PhaseDpuPending, 0x1},
		{PhaseDpuReady, 0x4},
		{PhaseRedirDone, 0xC},
	}
	for _, tt := range tests {
		if int(tt.phase) != tt.expected {
			t.Errorf("Phase %s: expected systemState 0x%X, got 0x%X", tt.phase, tt.expected, int(tt.phase))
		}
	}
}

func TestPhaseString(t *testing.T) {
	tests := []struct {
		phase    Phase
		expected string
	}{
		{PhaseDisabled, "disabled"},
		{PhaseDpuPending, "dpu-pending"},
		{PhaseDpuReady, "dpu-ready"},
		{PhaseRedirDone, "redir-done"},
	}
	for _, tt := range tests {
		if got := tt.phase.String(); got != tt.expected {
			t.Errorf("Phase.String(): got %q, want %q", got, tt.expected)
		}
	}
}

func TestPhaseIsAtLeast(t *testing.T) {
	tests := []struct {
		phase    Phase
		other    Phase
		expected bool
	}{
		{PhaseDpuReady, PhaseDisabled, true},
		{PhaseDpuReady, PhaseDpuPending, true},
		{PhaseDpuReady, PhaseDpuReady, true},
		{PhaseDpuReady, PhaseRedirDone, false},
		{PhaseDisabled, PhaseDpuPending, false},
		{PhaseRedirDone, PhaseDpuReady, true},
	}
	for _, tt := range tests {
		if got := tt.phase.IsAtLeast(tt.other); got != tt.expected {
			t.Errorf("%s.IsAtLeast(%s) = %v, want %v", tt.phase, tt.other, got, tt.expected)
		}
	}
}

func TestPhaseValidTransition(t *testing.T) {
	tests := []struct {
		from     Phase
		to       Phase
		expected bool
	}{
		// Same phase: always valid
		{PhaseDisabled, PhaseDisabled, true},
		{PhaseDpuPending, PhaseDpuPending, true},
		{PhaseDpuReady, PhaseDpuReady, true},
		{PhaseRedirDone, PhaseRedirDone, true},
		// Sequential forward: valid
		{PhaseDisabled, PhaseDpuPending, true},
		{PhaseDpuPending, PhaseDpuReady, true},
		{PhaseDpuReady, PhaseRedirDone, true},
		// Bidirectional health fluctuation: valid
		{PhaseDpuReady, PhaseDpuPending, true},
		// Skipping phases: invalid
		{PhaseDisabled, PhaseDpuReady, false},
		{PhaseDisabled, PhaseRedirDone, false},
		{PhaseDpuPending, PhaseRedirDone, false},
		// Backwards (except health fluctuation): invalid
		{PhaseRedirDone, PhaseDpuReady, false},
		{PhaseRedirDone, PhaseDpuPending, false},
		{PhaseRedirDone, PhaseDisabled, false},
		{PhaseDpuPending, PhaseDisabled, false},
	}
	for _, tt := range tests {
		if got := tt.from.ValidTransition(tt.to); got != tt.expected {
			t.Errorf("%s.ValidTransition(%s) = %v, want %v", tt.from, tt.to, got, tt.expected)
		}
	}
}
