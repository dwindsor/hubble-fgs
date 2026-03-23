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

// Phase represents the systemState progression reported to NXOS over gNMI.
// Phase values map directly to the SysSt* bitmask constants, so an int
// cast always yields the correct systemState to write to the device store.
type Phase int

const (
	// PhaseDisabled means FW is disabled (systemState = 0x0).
	PhaseDisabled Phase = SysStFwDisable
	// PhaseDpuPending means we are waiting for DPU inventory (systemState = 0x1).
	PhaseDpuPending Phase = SysStDpuPending
	// PhaseDpuReady means the DPU subsystem is ready (systemState = 0x4).
	PhaseDpuReady Phase = SysStDpuReady
	// PhaseRedirDone means DPU ready and service redirects are programmed (systemState = 0xC).
	PhaseRedirDone Phase = SysStDpuReady | SysStRedirDone
)

// Order returns the sequential order of the phase for comparison.
func (p Phase) Order() int {
	switch p {
	case PhaseDisabled:
		return 0
	case PhaseDpuPending:
		return 1
	case PhaseDpuReady:
		return 2
	case PhaseRedirDone:
		return 3
	default:
		return -1
	}
}

// String returns a human-readable name for the phase.
func (p Phase) String() string {
	switch p {
	case PhaseDisabled:
		return "disabled"
	case PhaseDpuPending:
		return "dpu-pending"
	case PhaseDpuReady:
		return "dpu-ready"
	case PhaseRedirDone:
		return "redir-done"
	default:
		return "unknown"
	}
}

// ValidTransition returns true if transitioning from p to target is allowed.
// Rules:
//   - Same phase is always valid (no-op).
//   - Forward sequential transitions are valid (no skipping).
//   - DpuReady ↔ DpuPending is valid to accommodate health fluctuation.
func (p Phase) ValidTransition(target Phase) bool {
	if p == target {
		return true
	}
	// Allow bidirectional health fluctuation between DpuPending and DpuReady.
	if (p == PhaseDpuPending && target == PhaseDpuReady) ||
		(p == PhaseDpuReady && target == PhaseDpuPending) {
		return true
	}
	// Forward sequential only (no skipping, no other backwards).
	return target.Order() == p.Order()+1
}

// IsAtLeast returns true if p is at least as advanced as other.
func (p Phase) IsAtLeast(other Phase) bool {
	return p.Order() >= other.Order()
}
