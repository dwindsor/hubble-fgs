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
	nxosmodel "github.com/isovalent/hubble-fgs/pkg/nxosmodel"
)

// DPU represents a Data Processing Unit.
type DPU struct {
	Name      string
	ModuleNum int
	IP        string
	PortHigh  int16
	PortLow   int16
	State     nxosmodel.E_Cisco_NX_OSDevice_Sas_DpuStateE
	Version   string
}

// IsOnline returns true if the DPU is in online state.
func (d DPU) IsOnline() bool {
	return d.State == nxosmodel.Cisco_NX_OSDevice_Sas_DpuStateE_online
}

// CalculatePortRange computes and sets this DPU's PortLow and PortHigh based on
// the global port range and total DPU count. The ModuleNum (1-indexed) determines
// which slice of the range this DPU owns.
func (d *DPU) CalculatePortRange(globalLow, globalHigh uint16, dpuCount int) bool {
	if dpuCount <= 0 || d.ModuleNum <= 0 {
		return false
	}
	totalPorts := int(globalHigh-globalLow) + 1
	perDPU := totalPorts / dpuCount
	if perDPU < 1 {
		return false
	}

	idx := d.ModuleNum - 1 // 0-indexed position
	d.PortLow = int16(int(globalLow) + idx*perDPU)
	if d.ModuleNum == dpuCount {
		// Last DPU gets any remainder ports.
		d.PortHigh = int16(globalHigh)
	} else {
		d.PortHigh = int16(int(globalLow) + (idx+1)*perDPU - 1)
	}
	return true
}

// DPUVersion contains version info for a DPU in HA member info.
type DPUVersion struct {
	Name    string
	Version string
}
