// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// Package types defines the core data types for the NXOS package.
package types

// VRF represents a Virtual Routing and Forwarding instance.
type VRF struct {
	Name        string
	Global      bool   // Added via VRF context (System/inst-items)
	Service     bool   // Added via fw policy (fwpolicy-items)
	HasAffinity bool   // Affinity has been explicitly set via SetAffinity
	Active      bool   // Computed: Global && Service && HasAffinity
	Affinity    uint16 // DPU affinity (0=dynamic, 1..N=direct DPU)
	DPUPinned   uint16 // Actual DPU assignment
	GID         uint16 // Global ID for service redirect
	Preset      uint16 // Desired GID (from HA reconciliation or --vrf-map); 0=use sequential allocation
}

// DeepCopy returns a fully independent copy of the VRF.
func (v *VRF) DeepCopy() VRF {
	return *v
}
