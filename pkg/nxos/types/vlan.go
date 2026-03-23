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

// VLAN represents a VLAN configuration.
type VLAN struct {
	Name        string // VLAN name/encap (e.g., "vlan-100")
	Global      bool   // Added via VLAN context (System/bd-items)
	Service     bool   // Added via fw policy (fwpolicy-items)
	HasAffinity bool   // Affinity has been explicitly set via SetAffinity
	Active      bool   // Computed: Global && Service && HasAffinity
	Affinity    uint16 // DPU affinity (0=dynamic, 1..N=direct DPU)
	DPUPinned   uint16 // Actual DPU assignment
	ID          uint16 // VLAN ID (parsed from name, e.g. vlan-100 → 100)
}

// DeepCopy returns a fully independent copy of the VLAN.
func (v *VLAN) DeepCopy() VLAN {
	return *v
}
