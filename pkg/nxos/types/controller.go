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

import nxosmodel "github.com/isovalent/hubble-fgs/pkg/nxosmodel"

// Device represents the device configuration and status.
type Device struct {
	Token            string
	ProxyServer      string
	ProxyPort        uint32
	Version          string
	RejectReason     string
	AdmissionStatus  nxosmodel.E_Cisco_NX_OSDevice_Sas_CommonStateE
	ConnectionStatus nxosmodel.E_Cisco_NX_OSDevice_Sas_CommonStateE
}

// Agent represents the agent state.
type Agent struct {
	InitState   nxosmodel.E_Cisco_NX_OSDevice_Sas_CommonStateE
	PolicyState nxosmodel.E_Cisco_NX_OSDevice_Sas_CommonStateE
	SystemState int
}

// SystemInfo contains system information.
type SystemInfo struct {
	Model        string
	SerialNumber string
	SWVersion    string
	CPAVersion   string
}
