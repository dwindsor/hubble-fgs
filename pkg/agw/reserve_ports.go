// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package agw

import "fmt"

// Port allocation constants for services within the port range
// Range: NX_HSA_PORT_START to NX_HSA_PORT_END
const (
	// Service port offsets from HSA port range start
	// Each service gets a fixed offset to ensure predictable port allocation

	// HAServerPortOffset is the offset for HA service port
	HAServerPortOffset uint16 = 0

	// Add service offsets here

)

// ServicePortType represents different service types that need port allocation
type ServicePortType int

const (
	// HAService represents the High Availability service
	HAService ServicePortType = iota
	// Add other services here as needed
)

// GetServicePortOffset returns the port offset for a given service type.
// Returns an error if the service type is unknown.
func GetServicePortOffset(serviceType ServicePortType) (uint16, error) {
	switch serviceType {
	case HAService:
		return HAServerPortOffset, nil
	default:
		return 0, fmt.Errorf("no port assigned for service type %d", serviceType)
	}
}
