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

import "strings"

// Phase represents the composite systemState bitmask reported to NXOS over gNMI.
// It is an int so that Phase(deviceStore.SystemState()).String() works for display.
type Phase int

// String returns a human-readable representation of the bitmask state.
// Each set bit is listed as a component; multiple bits are joined with "|".
func (p Phase) String() string {
	state := int(p)
	if state == SysStFwDisable {
		return "disabled"
	}
	var parts []string
	if state&SysStDpuPending != 0 {
		parts = append(parts, "dpu-pending")
	}
	if state&SysStFwReady != 0 {
		parts = append(parts, "fw-ready")
	}
	if state&SysStRedirDone != 0 {
		parts = append(parts, "redir-done")
	}
	if state&SysStConnPending != 0 {
		parts = append(parts, "conn-pending")
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, "|")
}
